//! WazuhDecoder CRD definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.adorsys.team",
    version = "v1alpha1",
    kind = "WazuhDecoder",
    plural = "wazuhdecoders",
    namespaced,
    status = "WazuhDecoderStatus"
)]
pub struct WazuhDecoderSpec {
    /// XML content of the decoder
    pub content: String,
    /// Filename for the decoder (e.g., "local_decoder.xml")
    pub filename: String,
    /// Priority for ordering decoders
    pub priority: Option<i32>,
    /// Selector to target specific manager nodes/clusters
    pub node_selector: Option<BTreeMap<String, String>>,
    /// Multiple selectors (OR). Any matching selector applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selectors: Option<Vec<BTreeMap<String, String>>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhDecoderStatus {
    /// Whether the decoder has been applied
    pub applied: bool,
    /// Error message if application failed
    pub error: Option<String>,
    /// Hash of the content
    pub hash: Option<String>,
}
