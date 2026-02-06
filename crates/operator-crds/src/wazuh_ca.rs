//! WazuhCA CRD definition

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.adorsys.team",
    version = "v1alpha1",
    kind = "WazuhCA",
    plural = "wazuhcas",
    namespaced,
    status = "WazuhCAStatus"
)]
pub struct WazuhCASpec {
    /// CA provider (selfSigned or certManager)
    pub provider: WazuhCAProvider,
    /// Name of the secret to store the CA (selfSigned only)
    pub secret_name: Option<String>,
    /// Subject values used when generating a self-signed CA
    pub subject: Option<WazuhCASubject>,
    /// cert-manager issuer reference (certManager only)
    pub issuer_ref: Option<IssuerRef>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhCASubject {
    /// X.509 Common Name (CN)
    pub cn: Option<String>,
    /// X.509 Country (C)
    pub c: Option<String>,
    /// X.509 State/Province (ST)
    pub st: Option<String>,
    /// X.509 Locality/City (L)
    pub l: Option<String>,
    /// X.509 Organization (O)
    pub o: Option<String>,
    /// X.509 Organizational Unit (OU)
    pub ou: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum WazuhCAProvider {
    SelfSigned,
    CertManager,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct IssuerRef {
    pub name: String,
    pub kind: Option<String>,
    pub group: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhCAStatus {
    pub ready: bool,
    pub message: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhCARef {
    /// Name of the WazuhCA resource
    pub name: String,
    /// Namespace of the WazuhCA resource (defaults to the cluster namespace)
    pub namespace: Option<String>,
}
