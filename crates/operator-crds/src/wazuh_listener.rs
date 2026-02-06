//! WazuhListener CRD definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.adorsys.team",
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
    /// Service configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ListenerServiceConfig>,
    /// Reference to manager cluster
    pub manager_cluster: Option<ManagerRef>,
    /// Selector to target specific manager nodes/clusters
    pub node_selector: Option<BTreeMap<String, String>>,
    /// Multiple selectors (OR). Any matching selector applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selectors: Option<Vec<BTreeMap<String, String>>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ManagerRef {
    /// Name of the manager cluster
    pub name: String,
    /// Namespace of the manager cluster
    pub namespace: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ListenerServiceConfig {
    /// How to expose the listener (attach to cluster service, or create a dedicated service)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ListenerServiceMode>,
    /// Service type (ClusterIP, NodePort, LoadBalancer)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    /// Create a headless service when true
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headless: Option<bool>,
    /// Extra service labels
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// Extra service annotations
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ListenerServiceMode {
    /// Patch the manager cluster Service ports (default)
    Attach,
    /// Create a dedicated Service for this listener
    Create,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhListenerStatus {
    /// Whether the listener is ready
    pub ready: bool,
    /// Service name created for the listener
    pub service_name: Option<String>,
    /// Service names created for the listener (when multiple selectors are used)
    pub service_names: Option<Vec<String>>,
}
