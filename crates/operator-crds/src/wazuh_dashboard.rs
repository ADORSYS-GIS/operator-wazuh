//! WazuhDashboard CRD definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::wazuh_ca::WazuhCARef;
use crate::pod_template::PodTemplateSpecPatch;
use crate::WorkloadConfig;

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
    /// Pod template overrides
    #[serde(rename = "podTemplate", default, skip_serializing_if = "Option::is_none")]
    pub pod_template: Option<PodTemplateSpecPatch>,
    /// Workload configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<WorkloadConfig>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct NginxConfig {
    /// Enable Nginx sidecar
    pub enabled: bool,
    /// Custom nginx.conf content
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_config: Option<String>,
    /// Nginx container image config
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageConfig>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ImageConfig {
    /// Image repository (e.g. nginx)
    pub repository: String,
    /// Image tag (e.g. stable-alpine)
    pub tag: String,
    /// Image pull policy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_policy: Option<String>,
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
    /// Manager API auth reference
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<ManagerAuthRef>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ManagerAuthRef {
    /// Secret reference for manager API credentials
    #[serde(rename = "secretRef")]
    pub secret_ref: SecretNameRef,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct SecretNameRef {
    /// Secret name in the same namespace
    pub name: String,
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
