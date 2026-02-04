//! WazuhIndexerSecurity CRD definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.adorsys.team",
    version = "v1alpha1",
    kind = "WazuhIndexerSecurity",
    plural = "wazuhindexersecurities",
    namespaced,
    status = "WazuhIndexerSecurityStatus"
)]
pub struct WazuhIndexerSecuritySpec {
    /// Role definitions
    pub roles: Vec<RoleDef>,
    /// Tenant definitions
    pub tenants: Vec<TenantDef>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct RoleDef {
    pub name: String,
    pub cluster_permissions: Vec<String>,
    pub index_permissions: Vec<IndexPermission>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct IndexPermission {
    pub index_patterns: Vec<String>,
    pub allowed_actions: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct TenantDef {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhIndexerSecurityStatus {
    pub applied: bool,
    pub error: Option<String>,
}
