//! WazuhDashboard CRD definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::wazuh_ca::WazuhCARef;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.adorsys.team",
    version = "v1alpha1",
    kind = "WazuhDashboard",
    plural = "wazuhdashboards",
    namespaced,
    status = "WazuhDashboardStatus"
)]
pub struct WazuhDashboardSpec {
    /// Number of dashboard replicas
    pub replicas: i32,
    /// Reference to indexer cluster
    pub indexer_cluster: IndexerRef,
    /// Reference to manager cluster
    pub manager_cluster: Option<ManagerRef>,
    /// Service configuration
    pub service: ServiceConfig,
    /// Authentication configuration
    pub auth: Option<AuthConfig>,
    /// Nginx configuration
    pub nginx: Option<NginxConfig>,
    /// TLS configuration
    pub tls: Option<TlsConfig>,
    /// Wazuh dashboard version
    pub version: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct NginxConfig {
    /// Enable Nginx sidecar
    pub enabled: bool,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct TlsConfig {
    /// Enable TLS
    pub enabled: bool,
    /// Reference to shared WazuhCA
    pub ca_ref: Option<WazuhCARef>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct IndexerRef {
    /// Name of the indexer cluster
    pub name: String,
    /// Namespace of the indexer cluster
    pub namespace: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ManagerRef {
    /// Name of the manager cluster
    pub name: String,
    /// Namespace of the manager cluster
    pub namespace: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ServiceConfig {
    /// Service type (NodePort, LoadBalancer, ClusterIP)
    pub service_type: String,
    /// Service port
    pub port: Option<i32>,
    /// Node port (for NodePort service)
    pub node_port: Option<i32>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct AuthConfig {
    /// Enable authentication
    pub enabled: bool,
    /// Authentication type (basic, oauth, etc.)
    pub auth_type: Option<String>,
    /// Authentication secret
    pub auth_secret: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhDashboardStatus {
    /// Current status of the dashboard
    pub phase: String,
    /// Number of ready replicas
    pub ready_replicas: i32,
    /// Dashboard URL
    pub url: Option<String>,
    /// Connection status to indexer
    pub indexer_connected: bool,
    /// Connection status to manager
    pub manager_connected: Option<bool>,
}
