//! WazuhAgentGroup CRD definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.adorsys.team",
    version = "v1alpha1",
    kind = "WazuhAgentGroup",
    plural = "wazuhagentgroups",
    namespaced,
    status = "WazuhAgentGroupStatus"
)]
pub struct WazuhAgentGroupSpec {
    /// Name of the agent group in Wazuh
    pub name: String,
    /// List of agent IDs to include in this group
    pub agent_ids: Option<Vec<String>>,
    /// References to WazuhConfig objects to apply to this group
    pub config_refs: Option<Vec<String>>,
    /// References to WazuhRule objects to apply to this group
    pub rule_refs: Option<Vec<String>>,
    /// References to WazuhDecoder objects to apply to this group
    pub decoder_refs: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhAgentGroupStatus {
    /// Whether the group has been synchronized with Wazuh
    pub synchronized: bool,
    /// Number of agents currently in the group
    pub agent_count: i32,
    /// Error message if synchronization failed
    pub error: Option<String>,
}
