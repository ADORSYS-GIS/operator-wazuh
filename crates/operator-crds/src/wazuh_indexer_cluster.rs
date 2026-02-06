//! WazuhIndexerCluster CRD definition

use crate::pod_template::PodTemplateSpecPatch;
use crate::wazuh_ca::WazuhCARef;
use crate::{VolumeClaimTemplate, WorkloadConfig};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.adorsys.team",
    version = "v1alpha1",
    kind = "WazuhIndexerCluster",
    plural = "wazuhindexerclusters",
    namespaced,
    status = "WazuhIndexerClusterStatus"
)]
pub struct WazuhIndexerClusterSpec {
    /// Number of indexer nodes
    pub replicas: i32,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Wazuh indexer version
    pub version: String,
    /// TLS configuration
    pub tls: Option<TlsConfig>,
    /// Pod template overrides
    #[serde(
        rename = "podTemplate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pod_template: Option<PodTemplateSpecPatch>,
    /// Workload configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<WorkloadConfig>,
    /// Additional volume claim templates
    #[serde(
        rename = "volumeClaimTemplates",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub volume_claim_templates: Option<Vec<VolumeClaimTemplate>>,
    /// Disable default PVC templates
    #[serde(
        rename = "disableDefaultPvc",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_default_pvc: Option<bool>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct StorageConfig {
    /// Storage size (e.g., "10Gi")
    pub size: String,
    /// Storage class
    pub storage_class: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct TlsConfig {
    /// Enable TLS
    pub enabled: bool,
    /// Reference to shared WazuhCA
    pub ca_ref: Option<WazuhCARef>,
    /// TLS certificate secret
    pub cert_secret: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhIndexerClusterStatus {
    /// Current status of the cluster
    pub phase: String,
    /// Number of ready nodes
    pub ready_nodes: i32,
    /// Cluster endpoints
    pub endpoints: Vec<String>,
}
