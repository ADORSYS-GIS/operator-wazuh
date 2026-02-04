//! WazuhRule CRD definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.com",
    version = "v1alpha1",
    kind = "WazuhRule",
    plural = "wazuhrules",
    namespaced,
    status = "WazuhRuleStatus"
)]
pub struct WazuhRuleSpec {
    /// XML content of the rule
    pub content: String,
    /// Filename for the rule (e.g., "local_rules.xml")
    pub filename: String,
    /// Priority for ordering rules
    pub priority: Option<i32>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhRuleStatus {
    /// Whether the rule has been applied
    pub applied: bool,
    /// Error message if application failed
    pub error: Option<String>,
    /// Hash of the content
    pub hash: Option<String>,
}
