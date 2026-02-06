//! WazuhDashboard CRD definition

use crate::WorkloadConfig;
use crate::pod_template::PodTemplateSpecPatch;
use crate::wazuh_ca::WazuhCARef;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;

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
    #[serde(
        rename = "podTemplate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pod_template: Option<PodTemplateSpecPatch>,
    /// Workload configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<WorkloadConfig>,
    /// Dashboard runtime configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<DashboardConfig>,
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
    /// Dashboard auth reference
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<IndexerAuthRef>,
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
pub struct IndexerAuthRef {
    /// Secret reference for dashboard login credentials in indexer
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
    /// OpenID authentication settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openid: Option<OpenIdConfig>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct DashboardConfig {
    /// Override OPENSEARCH_HOSTS env value (single URL)
    #[serde(
        rename = "opensearchHosts",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub opensearch_hosts: Option<String>,
    /// Override WAZUH_API_URL env value (single URL)
    #[serde(
        rename = "wazuhApiUrl",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub wazuh_api_url: Option<String>,
    /// Routes that can be accessed without authentication
    #[serde(
        rename = "unauthenticatedRoutes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub unauthenticated_routes: Option<Vec<String>>,
    /// Session settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<DashboardSessionConfig>,
    /// Branding settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branding: Option<DashboardBrandingConfig>,
    /// Raw overrides for opensearch_dashboards.yml (highest precedence)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<BTreeMap<String, JsonValue>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct DashboardSessionConfig {
    /// Cookie TTL in milliseconds
    #[serde(
        rename = "cookieTtlMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cookie_ttl_ms: Option<i64>,
    /// Session TTL in milliseconds
    #[serde(
        rename = "sessionTtlMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_ttl_ms: Option<i64>,
    /// Keep session alive
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<bool>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct DashboardBrandingConfig {
    /// Custom title
    #[serde(
        rename = "applicationTitle",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub application_title: Option<String>,
    /// Favicon URL
    #[serde(
        rename = "faviconUrl",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub favicon_url: Option<String>,
    /// Loading logo URL
    #[serde(
        rename = "loadingLogoUrl",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub loading_logo_url: Option<String>,
    /// Main logo URL
    #[serde(rename = "logoUrl", default, skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    /// Mark logo URL
    #[serde(rename = "markUrl", default, skip_serializing_if = "Option::is_none")]
    pub mark_url: Option<String>,
    /// Expanded header usage
    #[serde(
        rename = "useExpandedHeader",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub use_expanded_header: Option<bool>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct OpenIdConfig {
    /// OpenID discovery endpoint
    pub connect_url: String,
    /// OpenID client id
    pub client_id: String,
    /// OpenID client secret (plain text)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// OpenID client secret from Kubernetes secret
    #[serde(
        rename = "clientSecretRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub client_secret_ref: Option<SecretKeyRef>,
    /// OpenID scope
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Base redirect URL
    #[serde(
        rename = "baseRedirectUrl",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub base_redirect_url: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct SecretKeyRef {
    /// Secret name in the same namespace
    pub name: String,
    /// Secret key
    pub key: String,
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
