//! Ethereum provider cache and initialization logic.
//!
//! This module defines a cache of configured Ethereum JSON-RPC providers with signing capabilities.
//! Providers are constructed dynamically from environment variables, including private key credentials.
//!
//! This enables interaction with multiple Ethereum-compatible networks using Alloy's `ProviderBuilder`.
//!
//! Supported signer type: `private-key`.
//!
//! Environment variables used:
//! - `SIGNER_TYPE` — currently only `"private-key"` is supported,
//! - `EVM_PRIVATE_KEY` — comma-separated list of private keys used to sign transactions,
//! - `RPC_URL_BASE`, `RPC_URL_BASE_SEPOLIA` — RPC endpoints per network
//!
//! Example usage:
//! ```ignore
//! let provider_cache = ProviderCache::from_env().await?;
//! let provider = provider_cache.by_network(Network::Base)?;
//! ```

use std::borrow::Borrow;
use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;

use crate::chain::FromEnvByNetworkBuild;
use crate::chain::NetworkProvider;
use crate::chain::solana::SolanaProvider;
use crate::from_env;
use crate::network::Network;

/// A cache of pre-initialized [`EthereumProvider`] instances keyed by network.
///
/// This struct is responsible for lazily connecting to all configured RPC URLs
/// and wrapping them with appropriate signing and filler middleware.
///
/// Use [`ProviderCache::from_env`] to load credentials and connect using environment variables.
pub struct ProviderCache {
    providers: HashMap<Network, NetworkProvider>,
}

/// A generic cache of pre-initialized Ethereum provider instances [`ProviderMap::Value`] keyed by network.
///
/// This allows querying configured providers by network, and checking whether the network
/// supports EIP-1559 fee mechanics.
pub trait ProviderMap {
    type Value;

    /// Returns the Ethereum provider for the specified network, if configured.
    fn by_network<N: Borrow<Network>>(&self, network: N) -> Option<&Self::Value>;

    /// An iterator visiting all values in arbitrary order.
    fn values(&self) -> impl Iterator<Item = &Self::Value> + Send;
}

impl<'a> IntoIterator for &'a ProviderCache {
    type Item = (&'a Network, &'a NetworkProvider);
    type IntoIter = std::collections::hash_map::Iter<'a, Network, NetworkProvider>;

    fn into_iter(self) -> Self::IntoIter {
        self.providers.iter()
    }
}

impl ProviderCache {
    /// Constructs a new [`ProviderCache`] from environment variables.
    ///
    /// Expects the following to be set:
    /// - `SIGNER_TYPE` — currently only `"private-key"` is supported
    /// - `EVM_PRIVATE_KEY` — comma-separated list of private keys used to sign transactions
    /// - `RPC_URL_BASE`, `RPC_URL_BASE_SEPOLIA` — RPC endpoints per network
    ///
    /// Fails if required env vars are missing or if the provider cannot connect.
    pub async fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let mut providers = HashMap::new();
        for network in Network::variants() {
            let network_provider = NetworkProvider::from_env(*network).await?;
            if let Some(network_provider) = network_provider {
                providers.insert(*network, network_provider);
            }
        }
        Ok(Self { providers })
    }
}

impl ProviderMap for ProviderCache {
    type Value = NetworkProvider;

    fn by_network<N: Borrow<Network>>(&self, network: N) -> Option<&NetworkProvider> {
        self.providers.get(network.borrow())
    }

    fn values(&self) -> impl Iterator<Item = &Self::Value> {
        self.providers.values()
    }
}

/// A cache of Solana providers keyed by (network, index) for mnemonic-based derivation.
///
/// This cache lazily creates SolanaProvider instances from mnemonic phrases using BIP44 derivation.
/// Providers are cached to avoid recreating them on every request.
///
/// The cache is thread-safe and can be shared across multiple request handlers.
#[derive(Clone)]
pub struct SolanaProviderCache {
    providers: Arc<DashMap<(Network, u32), SolanaProvider>>,
}

impl SolanaProviderCache {
    /// Creates a new empty cache.
    pub fn new() -> Self {
        Self {
            providers: Arc::new(DashMap::new()),
        }
    }

    /// Gets or creates a Solana provider for the given network and mnemonic index.
    ///
    /// This method will:
    /// 1. Check if a provider already exists in the cache
    /// 2. If not, create a new provider from the mnemonic using the index
    /// 3. Cache and return the provider
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The mnemonic environment variable is not set
    /// - The mnemonic is invalid
    /// - The RPC URL for the network is not configured
    /// - The provider cannot be created
    pub fn get_or_create(
        &self,
        network: Network,
        index: u32,
    ) -> Result<Arc<SolanaProvider>, Box<dyn std::error::Error>> {
        let key = (network, index);

        println!("Getting or creating provider for key: {:?}", key);
        // Try to get from cache first (thread-safe check)
        if let Some(entry) = self.providers.get(&key) {
            return Ok(Arc::new(entry.clone()));
        }

        // Create new provider (outside of lock to avoid blocking)
        let keypair = from_env::SignerType::make_solana_wallet_from_mnemonic(index)?;

        let rpc_env_name = from_env::rpc_env_name_from_network(network);
        let rpc_url = std::env::var(rpc_env_name)
            .map_err(|_| format!("RPC URL not configured for network {:?}", network))?;

        let provider = SolanaProvider::try_new(keypair, rpc_url, network)
            .map_err(|e| format!("Failed to create Solana provider: {}", e))?;

        // Use entry API to atomically insert if not present
        // If another thread inserted in the meantime, use the existing one
        let entry = self.providers.entry(key).or_insert(provider);
        Ok(Arc::new(entry.clone()))
    }
}

impl Default for SolanaProviderCache {
    fn default() -> Self {
        Self::new()
    }
}
