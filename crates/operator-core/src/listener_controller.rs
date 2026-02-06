//! WazuhListener controller implementation

use crate::config_aggregator::ConfigAggregator;
use crate::error::{Error, Result};
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{ConfigMap, Service, ServicePort, ServiceSpec};
use kube::api::{Api, Patch, PatchParams, Resource, ResourceExt};
use kube::runtime::controller::Action;
use operator_crds::{ListenerServiceMode, WazuhListener, WazuhManager, WazuhManagerCluster};
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

    // 1. Optionally create Service(s) for the listener
    let mode = listener
        .spec
        .service
        .as_ref()
        .and_then(|s| s.mode.clone())
        .unwrap_or(ListenerServiceMode::Attach);
    let mut service_names = Vec::new();

    if matches!(mode, ListenerServiceMode::Create) {
        let svc_api: Api<Service> = Api::namespaced(client.clone(), &ns);
        let selector_sets = build_listener_selectors(&listener);

        if selector_sets.is_empty() {
            let svc = generate_listener_service(&listener, &name, None)?;
            svc_api
                .patch(
                    &name,
                    &PatchParams::apply("wazuh-operator"),
                    &Patch::Apply(&svc),
                )
                .await?;
            service_names.push(name.clone());
        } else {
            let multiple = selector_sets.len() > 1;
            for (idx, selector) in selector_sets.iter().enumerate() {
                let svc_name = if multiple {
                    format!("{}-{}", name, idx + 1)
                } else {
                    name.clone()
                };
                let svc = generate_listener_service(&listener, &svc_name, Some(selector))?;
                svc_api
                    .patch(
                        &svc_name,
                        &PatchParams::apply("wazuh-operator"),
                        &Patch::Apply(&svc),
                    )
                    .await?;
                service_names.push(svc_name);
            }
        }

        info!("Successfully reconciled Service(s) for listener {}", name);
    } else {
        info!(
            "Listener {} is in attach mode; skipping Service creation",
            name
        );
    }

    // 2. Update manager configuration
    // We trigger a full config aggregation and update for all managers in the namespace
    // This is similar to what ConfigController does.
    let workload_api: Api<WazuhManager> = Api::namespaced(client.clone(), &ns);
    let workloads = workload_api.list(&kube::api::ListParams::default()).await?;

    if !workloads.items.is_empty() {
        for manager in workloads {
            let manager_name = manager.name_any();
            let workload_name = manager
                .spec
                .workload
                .as_ref()
                .and_then(|w| w.name.clone())
                .unwrap_or_else(|| manager_name.clone());
            let cluster_name = manager.spec.cluster_ref.name.clone();

            let mut selector_labels = BTreeMap::new();
            selector_labels.insert("app".to_string(), "wazuh-manager".to_string());
            selector_labels.insert("cluster".to_string(), cluster_name);
            selector_labels.insert("manager".to_string(), manager_name.clone());
            selector_labels.insert(
                "role".to_string(),
                match manager.spec.role {
                    operator_crds::WazuhManagerRole::Master => "master".to_string(),
                    operator_crds::WazuhManagerRole::Worker => "worker".to_string(),
                },
            );
            selector_labels.insert("workload".to_string(), workload_name.clone());
            if let Some(ns_label) = manager.namespace() {
                selector_labels.insert("namespace".to_string(), ns_label);
            }
            if let Some(extra) = &manager.metadata.labels {
                for (k, v) in extra {
                    selector_labels
                        .entry(k.clone())
                        .or_insert_with(|| v.clone());
                }
            }

            let ossec_conf =
                ConfigAggregator::aggregate_configs(client.clone(), &ns, Some(&selector_labels))
                    .await?;
            let rules =
                ConfigAggregator::aggregate_rules(client.clone(), &ns, Some(&selector_labels))
                    .await?;
            let decoders =
                ConfigAggregator::aggregate_decoders(client.clone(), &ns, Some(&selector_labels))
                    .await?;

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

            let rules_cm = ConfigMap {
                metadata: kube::api::ObjectMeta {
                    name: Some(format!("{}-rules", manager.name_any())),
                    owner_references: manager.controller_owner_ref(&()).map(|o| vec![o]),
                    ..Default::default()
                },
                data: Some(rules.clone()),
                ..Default::default()
            };

            cm_api
                .patch(
                    &format!("{}-rules", manager_name),
                    &PatchParams::apply("wazuh-operator"),
                    &Patch::Apply(&rules_cm),
                )
                .await?;

            let decoders_cm = ConfigMap {
                metadata: kube::api::ObjectMeta {
                    name: Some(format!("{}-decoders", manager.name_any())),
                    owner_references: manager.controller_owner_ref(&()).map(|o| vec![o]),
                    ..Default::default()
                },
                data: Some(decoders.clone()),
                ..Default::default()
            };

            cm_api
                .patch(
                    &format!("{}-decoders", manager_name),
                    &PatchParams::apply("wazuh-operator"),
                    &Patch::Apply(&decoders_cm),
                )
                .await?;

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

            let sts_api: Api<StatefulSet> = Api::namespaced(client.clone(), &ns);
            sts_api
                .patch(
                    &workload_name,
                    &PatchParams::default(),
                    &Patch::Merge(&patch),
                )
                .await?;
        }

        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    let manager_api: Api<WazuhManagerCluster> = Api::namespaced(client.clone(), &ns);
    let managers = manager_api.list(&kube::api::ListParams::default()).await?;

    for manager in managers {
        let manager_name = manager.name_any();

        let ossec_conf = ConfigAggregator::aggregate_configs(
            client.clone(),
            &ns,
            manager.metadata.labels.as_ref(),
        )
        .await?;
        let rules = ConfigAggregator::aggregate_rules(
            client.clone(),
            &ns,
            manager.metadata.labels.as_ref(),
        )
        .await?;
        let decoders = ConfigAggregator::aggregate_decoders(
            client.clone(),
            &ns,
            manager.metadata.labels.as_ref(),
        )
        .await?;
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
            "service_name": service_names.first().cloned(),
            "service_names": if service_names.is_empty() { None } else { Some(service_names) }
        }
    });

    listener_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    Ok(Action::requeue(Duration::from_secs(60)))
}

fn generate_listener_service(
    listener: &WazuhListener,
    service_name: &str,
    selector: Option<&BTreeMap<String, String>>,
) -> Result<Service> {
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-manager".to_string());
    if let Some(cluster) = listener.spec.manager_cluster.as_ref() {
        labels.insert("cluster".to_string(), cluster.name.clone());
    }
    if let Some(selector) = selector {
        for (k, v) in selector {
            labels.insert(k.clone(), v.clone());
        }
    }
    if let Some(extra) = listener
        .spec
        .service
        .as_ref()
        .and_then(|s| s.labels.as_ref())
    {
        for (k, v) in extra {
            labels.insert(k.clone(), v.clone());
        }
    }

    let owner_ref = listener.controller_owner_ref(&()).map(|o| vec![o]);
    let mut annotations = BTreeMap::new();
    if let Some(extra) = listener
        .spec
        .service
        .as_ref()
        .and_then(|s| s.annotations.as_ref())
    {
        for (k, v) in extra {
            annotations.insert(k.clone(), v.clone());
        }
    }
    let service_type = listener
        .spec
        .service
        .as_ref()
        .and_then(|s| s.service_type.clone())
        .unwrap_or_else(|| "ClusterIP".to_string());
    let headless = listener
        .spec
        .service
        .as_ref()
        .and_then(|s| s.headless)
        .unwrap_or(false);

    Ok(Service {
        metadata: kube::api::ObjectMeta {
            name: Some(service_name.to_string()),
            labels: Some(labels.clone()),
            annotations: if annotations.is_empty() {
                None
            } else {
                Some(annotations)
            },
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
            type_: Some(service_type),
            cluster_ip: if headless {
                Some("None".to_string())
            } else {
                None
            },
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn build_listener_selectors(listener: &WazuhListener) -> Vec<BTreeMap<String, String>> {
    let mut selectors = Vec::new();
    if let Some(selector) = listener.spec.node_selector.clone() {
        selectors.push(selector);
    }
    if let Some(extra) = listener.spec.selectors.clone() {
        selectors.extend(extra);
    }
    selectors
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
