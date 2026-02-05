//! Pod template patch definitions for workload customization

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct PodTemplateSpecPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PodMetadataPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<PodSpecPatch>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct PodMetadataPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct PodSpecPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_selector: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tolerations: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affinity: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_class_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_pull_secrets: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_context: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_network: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_policy: Option<String>,
}
