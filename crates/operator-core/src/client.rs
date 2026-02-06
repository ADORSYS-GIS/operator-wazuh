//! Kubernetes client management

use crate::error::Result;
use kube::{Client, Config};

pub struct ClientManager {
    client: Client,
}

impl ClientManager {
    /// Create a new client manager with default configuration
    pub async fn new() -> Result<Self> {
        let config = Config::infer().await?;
        let client = Client::try_from(config)?;

        Ok(Self { client })
    }

    /// Get the underlying Kubernetes client
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Create a client with a specific namespace
    pub async fn with_namespace(namespace: &str) -> Result<Self> {
        let mut config = Config::infer().await?;
        config.default_namespace = namespace.to_string();
        let client = Client::try_from(config)?;

        Ok(Self { client })
    }
}
