use kube::CustomResource;
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

#[derive(CustomResource, Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[kube(shortname = "wzcl", group = "wazuh.adorsys.team", version = "v1", kind = "WazuhCluster", namespaced)]
#[kube(status = "WazuhClusterStatus")]
pub struct WazuhClusterSpec {
    pub replicas: i32,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
pub struct WazuhClusterStatus {
    pub available_replicas: i32,
}