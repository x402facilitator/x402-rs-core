//! HTTP endpoints implemented by the x402 **facilitator**.
//!
//! These are the server-side handlers for processing client-submitted x402 payments.
//! They include both protocol-critical endpoints (`/verify`, `/settle`) and discovery endpoints (`/supported`, etc).
//!
//! All payloads follow the types defined in the `x402-rs` crate, and are compatible
//! with the TypeScript and Go client SDKs.
//!
//! Each endpoint consumes or produces structured JSON payloads defined in `x402-rs`,
//! and is compatible with official x402 client SDKs.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router, response::IntoResponse};
use serde::Serialize;
use serde_json::json;
use tracing::instrument;

use crate::chain::FacilitatorLocalError;
use crate::facilitator::Facilitator;
use crate::from_env::{ENV_SETTLE_TRANSACTION_API_KEY, ENV_SETTLE_TRANSACTION_API_URL};
use crate::network::Network;
use crate::provider_cache::SolanaProviderCache;
use crate::types::{
    ErrorResponse, FacilitatorErrorReason, MixedAddress, SettleRequest, SettleResponse,
    VerifyRequest, VerifyResponse,
};
use std::env;

/// Request body for saving settle transaction to external API
#[derive(Debug, Serialize)]
struct SettleTransactionRequest {
    transaction: String,
    success: bool,
    network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_reason: Option<String>,
}

/// Helper function to save settle transaction to external API
/// This function logs errors but does not fail the main request
#[instrument(skip_all)]
async fn save_settle_transaction(response: &SettleResponse) {
    // Only save if transaction exists and is for Solana networks
    let network_str = match response.network {
        Network::Solana => "solana",
        Network::SolanaDevnet => "solana-devnet",
        _ => {
            tracing::debug!(
                network = ?response.network,
                "Skipping save_settle_transaction for non-Solana network"
            );
            return;
        }
    };

    let transaction = match &response.transaction {
        Some(tx) => tx.to_string(),
        None => {
            tracing::debug!("Skipping save_settle_transaction: no transaction hash");
            return;
        }
    };

    let payer = Some(response.payer.to_string());
    let error_reason = response.error_reason.as_ref().map(|r| format!("{:?}", r));

    let request_body = SettleTransactionRequest {
        transaction,
        success: response.success,
        network: network_str.to_string(),
        payer,
        error_reason,
    };

    // Get URL from environment variable, default to localhost if not set
    let url = env::var(ENV_SETTLE_TRANSACTION_API_URL)
        .unwrap_or_else(|_| "http://localhost:9999/client/transaction/settle".to_string());

    // Get API key from environment variable (optional)
    let api_key = env::var(ENV_SETTLE_TRANSACTION_API_KEY).ok();

    let client = reqwest::Client::new();
    let mut request = client.post(&url).json(&request_body);

    // Add API key to header if provided
    if let Some(key) = &api_key {
        request = request.header("x-api-key", key);
    }

    tracing::info!("Saving settle transaction to external API: {}", url);
    tracing::info!("Request body: {:?}", request_body);

    match request.send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                tracing::info!(
                    transaction = %request_body.transaction,
                    "Successfully saved settle transaction"
                );
            } else {
                tracing::warn!(
                    status = %resp.status(),
                    "Failed to save settle transaction: non-success status"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Failed to save settle transaction: request error"
            );
        }
    }
}

/// `GET /verify`: Returns a machine-readable description of the `/verify` endpoint.
///
/// This is served by the facilitator to help clients understand how to construct
/// a valid [`VerifyRequest`] for payment verification.
///
/// This is optional metadata and primarily useful for discoverability and debugging tools.
#[instrument(skip_all)]
pub async fn get_verify_info() -> impl IntoResponse {
    Json(json!({
        "endpoint": "/verify",
        "description": "POST to verify x402 payments",
        "body": {
            "paymentPayload": "PaymentPayload",
            "paymentRequirements": "PaymentRequirements",
        }
    }))
}

/// `GET /settle`: Returns a machine-readable description of the `/settle` endpoint.
///
/// This is served by the facilitator to describe the structure of a valid
/// [`SettleRequest`] used to initiate on-chain payment settlement.
#[instrument(skip_all)]
pub async fn get_settle_info() -> impl IntoResponse {
    Json(json!({
        "endpoint": "/settle",
        "description": "POST to settle x402 payments",
        "body": {
            "paymentPayload": "PaymentPayload",
            "paymentRequirements": "PaymentRequirements",
        }
    }))
}

pub fn routes<A>() -> Router<(A, SolanaProviderCache)>
where
    A: Facilitator + Clone + Send + Sync + 'static,
    A::Error: IntoResponse,
{
    Router::new()
        .route("/", get(get_root))
        .route("/verify", get(get_verify_info))
        .route("/verify", post(post_verify))
        .route("/settle", get(get_settle_info))
        .route("/settle", post(post_settle))
        .route("/{index}/verify", post(post_verify_with_index))
        .route("/{index}/settle", post(post_settle_with_index))
        .route("/health", get(get_health))
        .route("/supported", get(get_supported))
}

/// `GET /`: Returns a simple greeting message from the facilitator.
#[instrument(skip_all)]
pub async fn get_root() -> impl IntoResponse {
    let pkg_name = env!("CARGO_PKG_NAME");
    (StatusCode::OK, format!("Hello from {pkg_name}!"))
}

/// `POST /:index/verify`: Facilitator-side verification using a specific mnemonic index.
///
/// This endpoint uses a cached Solana provider created from the mnemonic using the provided index,
/// then verifies the payment payload.
#[instrument(skip_all)]
pub async fn post_verify_with_index(
    State((_, solana_cache)): State<(impl Facilitator, SolanaProviderCache)>,
    Path(index): Path<u32>,
    Json(body): Json<VerifyRequest>,
) -> impl IntoResponse {
    let network = body.network();

    // Only support Solana networks for mnemonic-based verification
    if !matches!(network, Network::Solana | Network::SolanaDevnet) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "Mnemonic-based verification only supports Solana networks, got {:?}",
                    network
                ),
            }),
        )
            .into_response();
    }

    // Get or create provider from cache
    let provider = match solana_cache.get_or_create(network, index) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to get or create Solana provider: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Verify the request
    match provider.verify(&body).await {
        Ok(valid_response) => (StatusCode::OK, Json(valid_response)).into_response(),
        Err(error) => {
            tracing::warn!(
                error = ?error,
                index = index,
                body = %serde_json::to_string(&body).unwrap_or_else(|_| "<can-not-serialize>".to_string()),
                "Verification failed"
            );
            error.into_response()
        }
    }
}

/// `POST /:index/settle`: Facilitator-side settlement using a specific mnemonic index.
///
/// This endpoint uses a cached Solana provider created from the mnemonic using the provided index,
/// then settles the payment on-chain.
#[instrument(skip_all)]
pub async fn post_settle_with_index(
    State((_, solana_cache)): State<(impl Facilitator, SolanaProviderCache)>,
    Path(index): Path<u32>,
    Json(body): Json<SettleRequest>,
) -> impl IntoResponse {
    let network = body.network();

    // Only support Solana networks for mnemonic-based settlement
    if !matches!(network, Network::Solana | Network::SolanaDevnet) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "Mnemonic-based settlement only supports Solana networks, got {:?}",
                    network
                ),
            }),
        )
            .into_response();
    }

    // Get or create provider from cache
    let provider = match solana_cache.get_or_create(network, index) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to get or create Solana provider: {}", e),
                }),
            )
                .into_response();
        }
    };

    // Settle the request
    match provider.settle(&body).await {
        Ok(valid_response) => {
            // Save transaction to external API in background
            let response_clone = valid_response.clone();
            tokio::spawn(async move {
                save_settle_transaction(&response_clone).await;
            });
            (StatusCode::OK, Json(valid_response)).into_response()
        }
        Err(error) => {
            tracing::warn!(
                error = ?error,
                index = index,
                body = %serde_json::to_string(&body).unwrap_or_else(|_| "<can-not-serialize>".to_string()),
                "Settlement failed"
            );
            error.into_response()
        }
    }
}

/// `GET /supported`: Lists the x402 payment schemes and networks supported by this facilitator.
///
/// Facilitators may expose this to help clients dynamically configure their payment requests
/// based on available network and scheme support.
#[instrument(skip_all)]
pub async fn get_supported<A>(
    State((facilitator, _)): State<(A, SolanaProviderCache)>,
) -> impl IntoResponse
where
    A: Facilitator,
    A::Error: IntoResponse,
{
    match facilitator.supported().await {
        Ok(supported) => (StatusCode::OK, Json(json!(supported))).into_response(),
        Err(error) => error.into_response(),
    }
}

#[instrument(skip_all)]
pub async fn get_health<A>(State(state): State<(A, SolanaProviderCache)>) -> impl IntoResponse
where
    A: Facilitator,
    A::Error: IntoResponse,
{
    get_supported(State(state)).await
}

/// `POST /verify`: Facilitator-side verification of a proposed x402 payment.
///
/// This endpoint checks whether a given payment payload satisfies the declared
/// [`PaymentRequirements`], including signature validity, scheme match, and fund sufficiency.
///
/// Responds with a [`VerifyResponse`] indicating whether the payment can be accepted.
#[instrument(skip_all)]
pub async fn post_verify<A>(
    State((facilitator, _)): State<(A, SolanaProviderCache)>,
    Json(body): Json<VerifyRequest>,
) -> impl IntoResponse
where
    A: Facilitator,
    A::Error: IntoResponse,
{
    match facilitator.verify(&body).await {
        Ok(valid_response) => (StatusCode::OK, Json(valid_response)).into_response(),
        Err(error) => {
            tracing::warn!(
                error = ?error,
                body = %serde_json::to_string(&body).unwrap_or_else(|_| "<can-not-serialize>".to_string()),
                "Verification failed"
            );
            error.into_response()
        }
    }
}

/// `POST /settle`: Facilitator-side execution of a valid x402 payment on-chain.
///
/// Given a valid [`SettleRequest`], this endpoint attempts to execute the payment
/// via ERC-3009 `transferWithAuthorization`, and returns a [`SettleResponse`] with transaction details.
///
/// This endpoint is typically called after a successful `/verify` step.
#[instrument(skip_all)]
pub async fn post_settle<A>(
    State((facilitator, _)): State<(A, SolanaProviderCache)>,
    Json(body): Json<SettleRequest>,
) -> impl IntoResponse
where
    A: Facilitator,
    A::Error: IntoResponse,
{
    match facilitator.settle(&body).await {
        Ok(valid_response) => {
            // Save transaction to external API in background
            let response_clone = valid_response.clone();
            tokio::spawn(async move {
                save_settle_transaction(&response_clone).await;
            });
            (StatusCode::OK, Json(valid_response)).into_response()
        }
        Err(error) => {
            tracing::warn!(
                error = ?error,
                body = %serde_json::to_string(&body).unwrap_or_else(|_| "<can-not-serialize>".to_string()),
                "Settlement failed"
            );
            error.into_response()
        }
    }
}

fn invalid_schema(payer: Option<MixedAddress>) -> VerifyResponse {
    VerifyResponse::invalid(payer, FacilitatorErrorReason::InvalidScheme)
}

impl IntoResponse for FacilitatorLocalError {
    fn into_response(self) -> Response {
        let error = self;

        let bad_request = (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid request".to_string(),
            }),
        )
            .into_response();

        match error {
            FacilitatorLocalError::SchemeMismatch(payer, ..) => {
                (StatusCode::OK, Json(invalid_schema(payer))).into_response()
            }
            FacilitatorLocalError::ReceiverMismatch(payer, ..)
            | FacilitatorLocalError::InvalidSignature(payer, ..)
            | FacilitatorLocalError::InvalidTiming(payer, ..)
            | FacilitatorLocalError::InsufficientValue(payer) => {
                (StatusCode::OK, Json(invalid_schema(Some(payer)))).into_response()
            }
            FacilitatorLocalError::NetworkMismatch(payer, ..)
            | FacilitatorLocalError::UnsupportedNetwork(payer) => (
                StatusCode::OK,
                Json(VerifyResponse::invalid(
                    payer,
                    FacilitatorErrorReason::InvalidNetwork,
                )),
            )
                .into_response(),
            FacilitatorLocalError::ContractCall(..)
            | FacilitatorLocalError::InvalidAddress(..)
            | FacilitatorLocalError::ClockError(_) => bad_request,
            FacilitatorLocalError::DecodingError(reason) => (
                StatusCode::OK,
                Json(VerifyResponse::invalid(
                    None,
                    FacilitatorErrorReason::FreeForm(reason),
                )),
            )
                .into_response(),
            FacilitatorLocalError::InsufficientFunds(payer) => (
                StatusCode::OK,
                Json(VerifyResponse::invalid(
                    Some(payer),
                    FacilitatorErrorReason::InsufficientFunds,
                )),
            )
                .into_response(),
        }
    }
}
