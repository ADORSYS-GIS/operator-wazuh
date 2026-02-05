//! WazuhListener controller implementation

use crate::config_aggregator::ConfigAggregator;
use crate::error::{Error, Result};
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{ConfigMap, Service, ServicePort, ServiceSpec};
use kube::api::{Api, Patch, PatchParams, Resource, ResourceExt};
use kube::runtime::controller::Action;
use operator_crds::{WazuhListener, WazuhManagerCluster};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};

pub struct ListenerContext {
    pub client: kube::Client,
}

impl ListenerContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhListener
pub async fn reconcile(listener: Arc<WazuhListener>, ctx: Arc<ListenerContext>) -> Result<Action> {
    let ns = listener
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let name = listener.name_any();

    info!("Reconciling WazuhListener: {}/{}", ns, name);

    let client = ctx.client.clone();

    // 1. Create/Update Service for the listener
    let svc_api: Api<Service> = Api::namespaced(client.clone(), &ns);
    let svc = generate_listener_service(&listener)?;

    svc_api
        .patch(
            &name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&svc),
        )
        .await?;

    info!("Successfully reconciled Service for listener {}", name);

    // 2. Update manager configuration
    // We trigger a full config aggregation and update for all managers in the namespace
    // This is similar to what ConfigController does.
    let manager_api: Api<WazuhManagerCluster> = Api::namespaced(client.clone(), &ns);
    let managers = manager_api.list(&kube::api::ListParams::default()).await?;

    for manager in managers {
        let manager_name = manager.name_any();

        let ossec_conf = ConfigAggregator::aggregate_configs(client.clone(), &ns, &manager).await?;
        let rules = ConfigAggregator::aggregate_rules(client.clone(), &ns, &manager).await?;
        let decoders = ConfigAggregator::aggregate_decoders(client.clone(), &ns, &manager).await?;
        let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &ns);

        let mut config_data = BTreeMap::new();
        config_data.insert("ossec.conf".to_string(), ossec_conf.clone());

        let cm = ConfigMap {
            metadata: kube::api::ObjectMeta {
                name: Some(format!("{}-config", manager_name)),
                owner_references: manager.controller_owner_ref(&()).map(|o| vec![o]),
                ..Default::default()
            },
            data: Some(config_data),
            ..Default::default()
        };

        cm_api
            .patch(
                &format!("{}-config", manager_name),
                &PatchParams::apply("wazuh-operator"),
                &Patch::Apply(&cm),
            )
            .await?;

        // Trigger rolling restart by updating annotation on StatefulSet
        let sts_api: Api<StatefulSet> = Api::namespaced(client.clone(), &ns);
        let combined_content = format!("{}{:?}{:?}", ossec_conf, rules, decoders);
        let hash = ConfigAggregator::calculate_hash(&combined_content);

        let patch = serde_json::json!({
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "wazuh.adorsys.team/config-hash": hash
                        }
                    }
                }
            }
        });

        sts_api
            .patch(
                &manager_name,
                &PatchParams::apply("wazuh-operator"),
                &Patch::Strategic(&patch),
            )
            .await?;

        info!(
            "Updated ConfigMaps and triggered restart for manager: {}",
            manager_name
        );
    }

    // 3. Update status
    let listener_api: Api<WazuhListener> = Api::namespaced(client, &ns);
    let patch = serde_json::json!({
        "status": {
            "ready": true,
            "service_name": Some(name.clone())
        }
    });

    listener_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    Ok(Action::requeue(Duration::from_secs(60)))
}

fn generate_listener_service(listener: &WazuhListener) -> Result<Service> {
    let name = listener.name_any();
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-manager".to_string());
    labels.insert(
        "cluster".to_string(),
        listener.spec.manager_cluster.name.clone(),
    );

    let owner_ref = listener.controller_owner_ref(&()).map(|o| vec![o]);

    Ok(Service {
        metadata: kube::api::ObjectMeta {
            name: Some(name.clone()),
            labels: Some(labels.clone()),
            owner_references: owner_ref,
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(labels),
            ports: Some(vec![ServicePort {
                name: Some("listener".to_string()),
                port: listener.spec.port,
                protocol: Some(listener.spec.protocol.to_uppercase()),
                ..Default::default()
            }]),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// Error policy for WazuhListener reconciliation
pub fn error_policy(
    _listener: Arc<WazuhListener>,
    error: &Error,
    _ctx: Arc<ListenerContext>,
) -> Action {
    error!("Reconciliation failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}
