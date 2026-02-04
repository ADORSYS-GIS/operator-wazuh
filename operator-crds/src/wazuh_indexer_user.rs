//! WazuhIndexerUser CRD definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.adorsys.team",
    version = "v1alpha1",
    kind = "WazuhIndexerUser",
    plural = "wazuhindexerusers",
    namespaced,
    status = "WazuhIndexerUserStatus"
)]
pub struct WazuhIndexerUserSpec {
    /// Username
    pub username: String,
    /// Roles assigned to the user
    pub roles: Vec<String>,
    /// Password secret reference
    pub password_secret: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhIndexerUserStatus {
    pub created: bool,
    pub error: Option<String>,
}
