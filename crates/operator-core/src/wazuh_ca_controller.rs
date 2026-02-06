//! WazuhCA controller implementation

use crate::error::{Error, Result};
use crate::tls::{CertificateSubject, TlsManager};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams, Resource};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{finalizer, Event as FinalizerEvent};
use kube::{ResourceExt};
use operator_crds::{WazuhCA, WazuhCAProvider, WazuhCASubject};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};

pub struct WazuhCaContext {
    pub client: kube::Client,
}

impl WazuhCaContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhCA
pub async fn reconcile(ca: Arc<WazuhCA>, ctx: Arc<WazuhCaContext>) -> Result<Action> {
    let ns = ca
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let ca_api: Api<WazuhCA> = Api::namespaced(ctx.client.clone(), &ns);

    finalizer(
        &ca_api,
        "wazuh.adorsys.team/finalizer",
        ca,
        |event| {
            let ctx = ctx.clone();
            async move {
                match event {
                    FinalizerEvent::Apply(ca) => reconcile_ca(ca, ctx).await,
                    FinalizerEvent::Cleanup(ca) => cleanup_ca(ca, ctx).await,
                }
            }
        },
    )
    .await
    .map_err(|e| Error::ReconciliationError(e.to_string()))
}

async fn reconcile_ca(ca: Arc<WazuhCA>, ctx: Arc<WazuhCaContext>) -> Result<Action> {
    let ns = ca.namespace().unwrap();
    let name = ca.name_any();
    info!("Reconciling WazuhCA: {}/{}", ns, name);

    let client = ctx.client.clone();
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), &ns);

    match ca.spec.provider {
        WazuhCAProvider::SelfSigned => {
            let secret_name = ca
                .spec
                .secret_name
                .clone()
                .unwrap_or_else(|| format!("{}-ca", name));

            let secret_ready = secret_api
                .get(&secret_name)
                .await
                .ok()
                .map_or(false, |s| secret_has_keys(&s, &["ca.crt", "ca.key"]));

            if !secret_ready {
                let ca_subject = certificate_subject(ca.spec.subject.as_ref());
                let (ca_cert, ca_key) = TlsManager::generate_ca(Some(&ca_subject))?;
                let mut data = BTreeMap::new();
                data.insert("ca.crt".to_string(), ca_cert);
                data.insert("ca.key".to_string(), ca_key);

                let owner_ref = ca.controller_owner_ref(&()).map(|o| vec![o]);
                let secret = Secret {
                    metadata: kube::api::ObjectMeta {
                        name: Some(secret_name.clone()),
                        owner_references: owner_ref,
                        ..Default::default()
                    },
                    string_data: Some(data),
                    ..Default::default()
                };

                secret_api
                    .patch(
                        &secret_name,
                        &PatchParams::apply("wazuh-operator"),
                        &Patch::Apply(&secret),
                    )
                    .await?;
            }

            update_status(
                &ca,
                client,
                true,
                Some(format!("Self-signed CA available in secret {}", secret_name)),
            )
            .await?;
        }
        WazuhCAProvider::CertManager => {
            if ca.spec.issuer_ref.is_none() {
                update_status(
                    &ca,
                    client,
                    false,
                    Some("issuer_ref is required for certManager provider".to_string()),
                )
                .await?;
            } else {
                update_status(
                    &ca,
                    client,
                    true,
                    Some("Waiting for cert-manager to issue certificates".to_string()),
                )
                .await?;
            }
        }
    }

    Ok(Action::requeue(Duration::from_secs(60)))
}

async fn cleanup_ca(_ca: Arc<WazuhCA>, _ctx: Arc<WazuhCaContext>) -> Result<Action> {
    Ok(Action::await_change())
}

async fn update_status(
    ca: &WazuhCA,
    client: kube::Client,
    ready: bool,
    message: Option<String>,
) -> Result<()> {
    let ns = ca.namespace().unwrap();
    let name = ca.name_any();
    let ca_api: Api<WazuhCA> = Api::namespaced(client, &ns);

    let status = operator_crds::wazuh_ca::WazuhCAStatus { ready, message };
    let patch = serde_json::json!({ "status": status });

    ca_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    Ok(())
}

/// Error policy for WazuhCA reconciliation
pub fn error_policy(_ca: Arc<WazuhCA>, error: &Error, _ctx: Arc<WazuhCaContext>) -> Action {
    error!("Reconciliation failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

fn secret_has_keys(secret: &Secret, keys: &[&str]) -> bool {
    keys.iter().all(|key| {
        secret
            .data
            .as_ref()
            .map_or(false, |data| data.contains_key(*key))
            || secret
                .string_data
                .as_ref()
                .map_or(false, |data| data.contains_key(*key))
    })
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
