//! WazuhManagerCluster CRD definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::wazuh_ca::WazuhCARef;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.adorsys.team",
    version = "v1alpha1",
    kind = "WazuhManagerCluster",
    plural = "wazuhmanagerclusters",
    namespaced,
    status = "WazuhManagerClusterStatus"
)]
pub struct WazuhManagerClusterSpec {
    /// Number of manager nodes
    pub replicas: i32,
    /// Reference to indexer cluster
    pub indexer_cluster: IndexerRef,
    /// High availability configuration
    pub ha: Option<HaConfig>,
    /// API configuration
    pub api: Option<ApiConfig>,
    /// Secret reference for manager API credentials
    #[serde(rename = "apiSecretRef", default, skip_serializing_if = "Option::is_none")]
    pub api_secret_ref: Option<SecretNameRef>,
    /// Wazuh manager version
    pub version: String,
    /// Nginx sidecar configuration
    pub nginx: Option<NginxConfig>,
    /// TLS configuration
    pub tls: Option<TlsConfig>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct NginxConfig {
    /// Enable Nginx sidecar
    #[serde(default = "default_nginx_enabled")]
    pub enabled: bool,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct TlsConfig {
    /// Enable TLS
    pub enabled: bool,
    /// Reference to shared WazuhCA
    pub ca_ref: Option<WazuhCARef>,
}

fn default_nginx_enabled() -> bool {
    true
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct IndexerRef {
    /// Name of the indexer cluster
    pub name: String,
    /// Namespace of the indexer cluster
    pub namespace: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct HaConfig {
    /// Enable high availability
    pub enabled: bool,
    /// Leader election timeout
    pub election_timeout: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ApiConfig {
    /// Enable REST API
    pub enabled: bool,
    /// API port
    pub port: Option<i32>,
    /// CORS configuration
    pub cors: Option<CorsConfig>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct CorsConfig {
    /// Enable CORS
    pub enabled: bool,
    /// Allowed origins
    pub allowed_origins: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct SecretNameRef {
    /// Secret name in the same namespace
    pub name: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhManagerClusterStatus {
    /// Current status of the cluster
    pub phase: String,
    /// Number of ready nodes
    pub ready_nodes: i32,
    /// Current leader (for HA)
    pub leader: Option<String>,
    /// API endpoints
    pub api_endpoints: Vec<String>,
}
