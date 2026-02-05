//! WazuhManager CRD definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::pod_template::PodTemplateSpecPatch;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.adorsys.team",
    version = "v1alpha1",
    kind = "WazuhManager",
    plural = "wazuhmanagers",
    namespaced,
    status = "WazuhManagerStatus"
)]
pub struct WazuhManagerSpec {
    /// Reference to the WazuhManagerCluster
    pub cluster_ref: WazuhManagerClusterRef,
    /// Number of manager nodes in this workload group
    pub replicas: i32,
    /// Node role (master or worker)
    pub role: WazuhManagerRole,
    /// Nginx sidecar configuration
    pub nginx: Option<NginxConfig>,
    /// Pod template overrides
    #[serde(rename = "podTemplate", default, skip_serializing_if = "Option::is_none")]
    pub pod_template: Option<PodTemplateSpecPatch>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhManagerClusterRef {
    /// Name of the manager cluster
    pub name: String,
    /// Namespace of the manager cluster
    pub namespace: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WazuhManagerRole {
    Master,
    Worker,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct NginxConfig {
    /// Enable Nginx sidecar
    pub enabled: bool,
    /// Custom nginx.conf content
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_config: Option<String>,
    /// Optional CRL URL to fetch into nginx at startup
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_url: Option<String>,
    /// Nginx container image config
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageConfig>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct ImageConfig {
    /// Image repository (e.g. nginx)
    pub repository: String,
    /// Image tag (e.g. stable-alpine)
    pub tag: String,
    /// Image pull policy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_policy: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, Default)]
pub struct WazuhManagerStatus {
    pub ready_replicas: i32,
    pub phase: Option<String>,
}
