//! Volume claim template definitions

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct VolumeClaimTemplate {
    pub metadata: VolumeClaimMetadata,
    /// PVC spec (PersistentVolumeClaimSpec)
    pub spec: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct VolumeClaimMetadata {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}
