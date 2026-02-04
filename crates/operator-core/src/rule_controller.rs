//! WazuhRule and WazuhDecoder controllers implementation

use crate::config_aggregator::ConfigAggregator;
use crate::error::{Error, Result};
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Api, Patch, PatchParams, Resource, ResourceExt};
use kube::runtime::controller::Action;
use operator_crds::{WazuhDecoder, WazuhManagerCluster, WazuhRule};
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};

pub struct RuleContext {
    pub client: kube::Client,
}

impl RuleContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhRule
pub async fn reconcile_rule(rule: Arc<WazuhRule>, ctx: Arc<RuleContext>) -> Result<Action> {
    let ns = rule
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let name = rule.name_any();

    info!("Reconciling WazuhRule: {}/{}", ns, name);

    let client = ctx.client.clone();
    trigger_aggregation(client.clone(), &ns).await?;

    // Update status
    let rule_api: Api<WazuhRule> = Api::namespaced(client, &ns);
    let hash = ConfigAggregator::calculate_hash(&rule.spec.content);
    let patch = serde_json::json!({
        "status": {
            "applied": true,
            "hash": hash,
            "error": null
        }
    });

    rule_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Error policy for WazuhRule reconciliation
pub fn rule_error_policy(rule: Arc<WazuhRule>, error: &Error, ctx: Arc<RuleContext>) -> Action {
    error!("Rule reconciliation failed: {:?}", error);
    let client = ctx.client.clone();
    let ns = rule.namespace().unwrap();
    let name = rule.name_any();
    let rule_api: Api<WazuhRule> = Api::namespaced(client, &ns);

    let patch = serde_json::json!({
        "status": {
            "applied": false,
            "error": format!("{:?}", error)
        }
    });

    let _ = tokio::spawn(async move {
        let _ = rule_api
            .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await;
    });

    Action::requeue(Duration::from_secs(60))
}

pub struct DecoderContext {
    pub client: kube::Client,
}

impl DecoderContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhDecoder
pub async fn reconcile_decoder(
    decoder: Arc<WazuhDecoder>,
    ctx: Arc<DecoderContext>,
) -> Result<Action> {
    let ns = decoder
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let name = decoder.name_any();

    info!("Reconciling WazuhDecoder: {}/{}", ns, name);

    let client = ctx.client.clone();
    trigger_aggregation(client.clone(), &ns).await?;

    // Update status
    let decoder_api: Api<WazuhDecoder> = Api::namespaced(client, &ns);
    let hash = ConfigAggregator::calculate_hash(&decoder.spec.content);
    let patch = serde_json::json!({
        "status": {
            "applied": true,
            "hash": hash,
            "error": null
        }
    });

    decoder_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Error policy for WazuhDecoder reconciliation
pub fn decoder_error_policy(
    decoder: Arc<WazuhDecoder>,
    error: &Error,
    ctx: Arc<DecoderContext>,
) -> Action {
    error!("Decoder reconciliation failed: {:?}", error);
    let client = ctx.client.clone();
    let ns = decoder.namespace().unwrap();
    let name = decoder.name_any();
    let decoder_api: Api<WazuhDecoder> = Api::namespaced(client, &ns);

    let patch = serde_json::json!({
        "status": {
            "applied": false,
            "error": format!("{:?}", error)
        }
    });

    let _ = tokio::spawn(async move {
        let _ = decoder_api
            .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await;
    });

    Action::requeue(Duration::from_secs(60))
}

/// Shared logic to trigger aggregation and update managers
async fn trigger_aggregation(client: kube::Client, ns: &str) -> Result<()> {
    // 1. Find all WazuhManagerClusters in the namespace to update their ConfigMaps
    let manager_api: Api<WazuhManagerCluster> = Api::namespaced(client.clone(), ns);
    let managers = manager_api.list(&kube::api::ListParams::default()).await?;

    for manager in managers {
        let manager_name = manager.name_any();

        // 2. Aggregate all configs, rules, and decoders for this specific manager
        let ossec_conf = ConfigAggregator::aggregate_configs(client.clone(), ns, &manager).await?;
        let rules = ConfigAggregator::aggregate_rules(client.clone(), ns, &manager).await?;
        let decoders = ConfigAggregator::aggregate_decoders(client.clone(), ns, &manager).await?;
        let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), ns);

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
        let sts_api: Api<StatefulSet> = Api::namespaced(client.clone(), ns);
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

    Ok(())
}
