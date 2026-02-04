//! API client integration layer for OpenSearch and Wazuh Manager

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::info;

pub struct ApiClient {
    client: Client,
    base_url: String,
}

impl ApiClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }

    /// Perform a GET request
    pub async fn get<T>(&self, path: &str) -> Result<T, reqwest::Error>
    where
        T: for<'de> Deserialize<'de>,
    {
        let url = format!("{}{}", self.base_url, path);
        info!("GET {}", url);
        self.client.get(&url).send().await?.json().await
    }

    /// Perform a POST request
    pub async fn post<T, U>(&self, path: &str, body: &U) -> Result<T, reqwest::Error>
    where
        T: for<'de> Deserialize<'de>,
        U: Serialize,
    {
        let url = format!("{}{}", self.base_url, path);
        info!("POST {}", url);
        self.client.post(&url).json(body).send().await?.json().await
    }
}
