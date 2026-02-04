//! WazuhListener CRD definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.com",
    version = "v1alpha1",
    kind = "WazuhListener",
    plural = "wazuhlisteners",
    namespaced,
    status = "WazuhListenerStatus"
)]
pub struct WazuhListenerSpec {
    /// Port number to expose
    pub port: i32,
    /// Protocol (TCP or UDP)
    pub protocol: String,
    /// Reference to manager cluster
    pub manager_cluster: ManagerRef,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ManagerRef {
    /// Name of the manager cluster
    pub name: String,
    /// Namespace of the manager cluster
    pub namespace: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhListenerStatus {
    /// Whether the listener is ready
    pub ready: bool,
    /// Service name created for the listener
    pub service_name: Option<String>,
}
