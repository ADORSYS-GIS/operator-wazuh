//! Shared CA resolution for Wazuh resources

use crate::error::{Error, Result};
use crate::tls::{CertificateSubject, TlsManager};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams};
use kube::{Resource, ResourceExt};
use operator_crds::{IssuerRef, WazuhCA, WazuhCAProvider, WazuhCARef, WazuhCASubject};
use std::collections::BTreeMap;

pub const DEFAULT_WAZUH_CA_NAME: &str = "wazuh-ca";

pub enum ResolvedCa {
    SelfSigned {
        ca_cert: String,
        ca_key: String,
        ca_secret_name: String,
    },
    CertManager {
        issuer_ref: IssuerRef,
    },
}

pub async fn resolve_wazuh_ca(
    client: kube::Client,
    default_ns: &str,
    ca_ref: &WazuhCARef,
) -> Result<ResolvedCa> {
    let ns = ca_ref.namespace.as_deref().unwrap_or(default_ns);
    let ca_api: Api<WazuhCA> = Api::namespaced(client.clone(), ns);
    let ca = ca_api.get(&ca_ref.name).await.map_err(|e| {
        Error::ReconciliationError(format!(
            "Failed to fetch WazuhCA {}/{}: {}",
            ns, ca_ref.name, e
        ))
    })?;

    resolve_wazuh_ca_from_resource(client, ns, ca).await
}

pub async fn resolve_default_wazuh_ca(
    client: kube::Client,
    namespace: &str,
) -> Result<Option<ResolvedCa>> {
    let ca_api: Api<WazuhCA> = Api::namespaced(client.clone(), namespace);
    let ca = match ca_api.get(DEFAULT_WAZUH_CA_NAME).await {
        Ok(ca) => ca,
        Err(kube::Error::Api(ae)) if ae.code == 404 => return Ok(None),
        Err(e) => {
            return Err(Error::ReconciliationError(format!(
                "Failed to fetch default WazuhCA {}/{}: {}",
                namespace, DEFAULT_WAZUH_CA_NAME, e
            )));
        }
    };

    resolve_wazuh_ca_from_resource(client, namespace, ca)
        .await
        .map(Some)
}

async fn resolve_wazuh_ca_from_resource(
    client: kube::Client,
    ns: &str,
    ca: WazuhCA,
) -> Result<ResolvedCa> {
    match ca.spec.provider {
        WazuhCAProvider::SelfSigned => {
            let ca_secret_name = ca
                .spec
                .secret_name
                .clone()
                .unwrap_or_else(|| format!("{}-ca", ca.name_any()));
            let secret_api: Api<Secret> = Api::namespaced(client, ns);

            if let Ok(secret) = secret_api.get(&ca_secret_name).await {
                if let (Some(ca_cert), Some(ca_key)) = (
                    secret_value(&secret, "ca.crt"),
                    secret_value(&secret, "ca.key"),
                ) {
                    return Ok(ResolvedCa::SelfSigned {
                        ca_cert,
                        ca_key,
                        ca_secret_name,
                    });
                }
            }

            let ca_subject = certificate_subject(ca.spec.subject.as_ref());
            let (ca_cert, ca_key) = TlsManager::generate_ca(Some(&ca_subject))?;
            let mut data = BTreeMap::new();
            data.insert("ca.crt".to_string(), ca_cert.clone());
            data.insert("ca.key".to_string(), ca_key.clone());

            let owner_ref = ca.controller_owner_ref(&()).map(|o| vec![o]);
            let secret = Secret {
                metadata: kube::api::ObjectMeta {
                    name: Some(ca_secret_name.clone()),
                    owner_references: owner_ref,
                    ..Default::default()
                },
                string_data: Some(data),
                ..Default::default()
            };

            secret_api
                .patch(
                    &ca_secret_name,
                    &PatchParams::apply("wazuh-operator"),
                    &Patch::Apply(&secret),
                )
                .await?;

            Ok(ResolvedCa::SelfSigned {
                ca_cert,
                ca_key,
                ca_secret_name,
            })
        }
        WazuhCAProvider::CertManager => {
            let mut issuer_ref = ca.spec.issuer_ref.clone().ok_or_else(|| {
                Error::ValidationError(format!(
                    "WazuhCA {}/{} uses certManager but issuer_ref is missing",
                    ns,
                    ca.name_any()
                ))
            })?;

            if issuer_ref.kind.is_none() {
                issuer_ref.kind = Some("Issuer".to_string());
            }
            if issuer_ref.group.is_none() {
                issuer_ref.group = Some("cert-manager.io".to_string());
            }

            Ok(ResolvedCa::CertManager { issuer_ref })
        }
    }
}

fn certificate_subject(subject: Option<&WazuhCASubject>) -> CertificateSubject {
    let default = CertificateSubject::default();
    let Some(subject) = subject else {
        return default;
    };

    CertificateSubject {
        common_name: subject.cn.clone().unwrap_or(default.common_name),
        country: subject.c.clone().unwrap_or(default.country),
        state_or_province: subject.st.clone().unwrap_or(default.state_or_province),
        locality: subject.l.clone().unwrap_or(default.locality),
        organization: subject.o.clone().unwrap_or(default.organization),
        organizational_unit: subject.ou.clone().unwrap_or(default.organizational_unit),
    }
}

fn secret_value(secret: &Secret, key: &str) -> Option<String> {
    if let Some(data) = &secret.data {
        if let Some(value) = data.get(key) {
            return String::from_utf8(value.0.clone()).ok();
        }
    }
    if let Some(data) = &secret.string_data {
        if let Some(value) = data.get(key) {
            return Some(value.clone());
        }
    }
    None
}
