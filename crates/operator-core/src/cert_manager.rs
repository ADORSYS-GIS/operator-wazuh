//! Minimal cert-manager Certificate types used by the operator

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use operator_crds::IssuerRef;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "cert-manager.io",
    version = "v1",
    kind = "Certificate",
    plural = "certificates",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSpec {
    pub secret_name: String,
    pub issuer_ref: IssuerRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub usages: Vec<String>,
}
