//! WazuhConfig controller implementation

use crate::config_aggregator::ConfigAggregator;
use crate::error::{Error, Result};
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Api, Patch, PatchParams, Resource, ResourceExt};
use kube::runtime::controller::Action;
use operator_crds::{WazuhConfig, WazuhManager, WazuhManagerCluster};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};

pub struct ConfigContext {
    pub client: kube::Client,
}

impl ConfigContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhConfig
pub async fn reconcile(config: Arc<WazuhConfig>, ctx: Arc<ConfigContext>) -> Result<Action> {
    let ns = config
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let name = config.name_any();

    info!("Reconciling WazuhConfig: {}/{}", ns, name);

    let client = ctx.client.clone();

    // Prefer WazuhManager workloads if present
    let workload_api: Api<WazuhManager> = Api::namespaced(client.clone(), &ns);
    let workloads = workload_api.list(&kube::api::ListParams::default()).await?;
    if !workloads.items.is_empty() {
        for workload in workloads {
            let workload_name = workload.name_any();

            let ossec_conf = ConfigAggregator::aggregate_configs(
                client.clone(),
                &ns,
                workload.metadata.labels.as_ref(),
            )
            .await?;
            let rules = ConfigAggregator::aggregate_rules(
                client.clone(),
                &ns,
                workload.metadata.labels.as_ref(),
            )
            .await?;
            let decoders = ConfigAggregator::aggregate_decoders(
                client.clone(),
                &ns,
                workload.metadata.labels.as_ref(),
            )
            .await?;

            let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &ns);
            let mut config_data = BTreeMap::new();
            config_data.insert("ossec.conf".to_string(), ossec_conf.clone());

            let cm = ConfigMap {
                metadata: kube::api::ObjectMeta {
                    name: Some(format!("{}-config", workload_name)),
                    owner_references: workload.controller_owner_ref(&()).map(|o| vec![o]),
                    ..Default::default()
                },
                data: Some(config_data),
                ..Default::default()
            };

            cm_api
                .patch(
                    &format!("{}-config", workload_name),
                    &PatchParams::apply("wazuh-operator"),
                    &Patch::Apply(&cm),
                )
                .await?;

            let rules_cm = ConfigMap {
                metadata: kube::api::ObjectMeta {
                    name: Some(format!("{}-rules", workload_name)),
                    owner_references: workload.controller_owner_ref(&()).map(|o| vec![o]),
                    ..Default::default()
                },
                data: Some(rules.clone()),
                ..Default::default()
            };

            cm_api
                .patch(
                    &format!("{}-rules", workload_name),
                    &PatchParams::apply("wazuh-operator"),
                    &Patch::Apply(&rules_cm),
                )
                .await?;

            let decoders_cm = ConfigMap {
                metadata: kube::api::ObjectMeta {
                    name: Some(format!("{}-decoders", workload_name)),
                    owner_references: workload.controller_owner_ref(&()).map(|o| vec![o]),
                    ..Default::default()
                },
                data: Some(decoders.clone()),
                ..Default::default()
            };

            cm_api
                .patch(
                    &format!("{}-decoders", workload_name),
                    &PatchParams::apply("wazuh-operator"),
                    &Patch::Apply(&decoders_cm),
                )
                .await?;

            let sts_api: Api<StatefulSet> = Api::namespaced(client.clone(), &ns);
            let patch = serde_json::json!({
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "wazuh.adorsys.team/config-hash": ConfigAggregator::calculate_hash(&ossec_conf)
                            }
                        }
                    }
                }
            });
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

    // 1. Find all WazuhManagerClusters in the namespace to update their ConfigMaps
    let manager_api: Api<WazuhManagerCluster> = Api::namespaced(client.clone(), &ns);
    let managers = manager_api.list(&kube::api::ListParams::default()).await?;

    for manager in managers {
        let manager_name = manager.name_any();

        // 2. Aggregate all configs, rules, and decoders for this specific manager
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

        // Update ossec.conf ConfigMap
        let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &ns);

        // We need to merge the aggregated ossec_conf with the manager-specific parts
        // (like indexer hosts, cluster config).
        // For now, we'll just use the aggregated one if it's not empty,
        // or fallback to a default if we had one.
        // Actually, the manager_controller already generates a base ossec.conf.
        // A better approach is to have the manager_controller handle the base,
        // and this controller handle the overrides or additional files.
        // But the task says "aggregating WazuhConfig, WazuhRule, and WazuhDecoder objects into ConfigMaps".

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

        // Update rules ConfigMap
        let rules_cm = ConfigMap {
            metadata: kube::api::ObjectMeta {
                name: Some(format!("{}-rules", manager_name)),
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

        // Update decoders ConfigMap
        let decoders_cm = ConfigMap {
            metadata: kube::api::ObjectMeta {
                name: Some(format!("{}-decoders", manager_name)),
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

        // 3. Trigger rolling restart by updating annotation on StatefulSet
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

    // 4. Update status of the WazuhConfig
    let config_api: Api<WazuhConfig> = Api::namespaced(client.clone(), &ns);
    let hash = ConfigAggregator::calculate_hash(&config.spec.content);
    let patch = serde_json::json!({
        "status": {
            "applied": true,
            "hash": hash,
            "error": null
        }
    });

    config_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    Ok(Action::requeue(Duration::from_secs(60)))
}

/// Error policy for WazuhConfig reconciliation
pub fn error_policy(config: Arc<WazuhConfig>, error: &Error, ctx: Arc<ConfigContext>) -> Action {
    error!("Reconciliation failed: {:?}", error);

    // Try to update status with error
    let client = ctx.client.clone();
    let ns = config.namespace().unwrap();
    let name = config.name_any();
    let config_api: Api<WazuhConfig> = Api::namespaced(client, &ns);

    let patch = serde_json::json!({
        "status": {
            "applied": false,
            "error": format!("{:?}", error)
        }
    });

    let _ = tokio::spawn(async move {
        let _ = config_api
            .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await;
    });

    Action::requeue(Duration::from_secs(60))
}
