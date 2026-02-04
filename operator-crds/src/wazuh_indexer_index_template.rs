//! WazuhIndexerIndexTemplate CRD definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.adorsys.team",
    version = "v1alpha1",
    kind = "WazuhIndexerIndexTemplate",
    plural = "wazuhindexerindextemplates",
    namespaced,
    status = "WazuhIndexerIndexTemplateStatus"
)]
pub struct WazuhIndexerIndexTemplateSpec {
    /// Template name
    pub name: String,
    /// Index patterns
    pub index_patterns: Vec<String>,
    /// Template settings (JSON string)
    pub settings: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhIndexerIndexTemplateStatus {
    pub applied: bool,
    pub error: Option<String>,
}
