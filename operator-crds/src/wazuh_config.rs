//! WazuhConfig CRD definition

use kube::CustomResource;
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.com",
    version = "v1alpha1",
    kind = "WazuhConfig",
    plural = "wazuhconfigs",
    namespaced,
    status = "WazuhConfigStatus"
)]
pub struct WazuhConfigSpec {
    /// XML content of the main configuration (ossec.conf)
    pub content: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhConfigStatus {
    /// Whether the configuration has been applied
    pub applied: bool,
    /// Error message if application failed
    pub error: Option<String>,
    /// Hash of the content
    pub hash: Option<String>,
}
