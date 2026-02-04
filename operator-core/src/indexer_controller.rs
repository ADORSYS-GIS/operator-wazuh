//! WazuhIndexerCluster controller implementation

use k8s_openapi::api::apps::v1::{StatefulSet, StatefulSetUpdateStrategy};
use k8s_openapi::api::core::v1::{
    Container, PersistentVolumeClaim, PersistentVolumeClaimSpec, PodSpec, PodTemplateSpec, Service,
    ServicePort, ServiceSpec, VolumeMount, VolumeResourceRequirements,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, LabelSelector, OwnerReference};
use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams, PostParams, Resource};
use kube::runtime::controller::Action;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{debug, error, info};

use operator_crds::WazuhIndexerCluster;

use crate::error::{Error, Result};

pub struct IndexerContext {
    pub client: kube::Client,
}

impl IndexerContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhIndexerCluster
pub async fn reconcile(
    indexer: Arc<WazuhIndexerCluster>,
    ctx: Arc<IndexerContext>,
) -> Result<Action> {
    let ns = indexer
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let name = indexer.name_any();

    info!("Reconciling WazuhIndexerCluster: {}/{}", ns, name);

    let client = ctx.client.clone();
    let sts_api: Api<StatefulSet> = Api::namespaced(client.clone(), &ns);
    let svc_api: Api<Service> = Api::namespaced(client.clone(), &ns);

    let sts = generate_statefulset(&indexer)?;
    let svc = generate_service(&indexer)?;

    svc_api
        .patch(
            &name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&svc),
        )
        .await?;

    sts_api
        .patch(
            &name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&sts),
        )
        .await?;

    update_status(&indexer, client.clone()).await?;

    info!(
        "Successfully reconciled StatefulSet and Service for {}",
        name
    );

    Ok(Action::requeue(Duration::from_secs(300)))
}

async fn check_quorum(indexer: &WazuhIndexerCluster, client: kube::Client) -> Result<bool> {
    let ns = indexer.namespace().unwrap();
    let name = indexer.name_any();
    let sts_api: Api<StatefulSet> = Api::namespaced(client, &ns);

    let sts = sts_api.get(&name).await?;
    let ready_replicas = sts
        .status
        .as_ref()
        .and_then(|s| s.ready_replicas)
        .unwrap_or(0);

    // Simple quorum check: at least half + 1 nodes must be ready
    let quorum = (indexer.spec.replicas / 2) + 1;
    Ok(ready_replicas >= quorum)
}

async fn update_status(indexer: &WazuhIndexerCluster, client: kube::Client) -> Result<()> {
    let ns = indexer.namespace().unwrap();
    let name = indexer.name_any();
    let indexer_api: Api<WazuhIndexerCluster> = Api::namespaced(client.clone(), &ns);
    let sts_api: Api<StatefulSet> = Api::namespaced(client, &ns);

    let sts = sts_api.get(&name).await?;
    let ready_replicas = sts
        .status
        .as_ref()
        .and_then(|s| s.ready_replicas)
        .unwrap_or(0);
    let phase = if ready_replicas == indexer.spec.replicas {
        "Ready"
    } else {
        "Progressing"
    };

    let mut status = indexer.status.clone().unwrap_or(
        operator_crds::wazuh_indexer_cluster::WazuhIndexerClusterStatus {
            phase: phase.to_string(),
            ready_nodes: ready_replicas,
            endpoints: vec![format!("{}.{}.svc.cluster.local", name, ns)],
        },
    );

    status.phase = phase.to_string();
    status.ready_nodes = ready_replicas;

    let patch = serde_json::json!({
        "status": status
    });

    indexer_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    Ok(())
}

fn generate_service(indexer: &WazuhIndexerCluster) -> Result<Service> {
    let name = indexer.name_any();
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-indexer".to_string());
    labels.insert("cluster".to_string(), name.clone());

    let owner_ref = indexer.controller_owner_ref(&()).map(|o| vec![o]);

    let svc = Service {
        metadata: kube::api::ObjectMeta {
            name: Some(name.clone()),
            labels: Some(labels.clone()),
            owner_references: owner_ref,
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(labels),
            ports: Some(vec![
                ServicePort {
                    name: Some("http".to_string()),
                    port: 9200,
                    ..Default::default()
                },
                ServicePort {
                    name: Some("transport".to_string()),
                    port: 9300,
                    ..Default::default()
                },
            ]),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    Ok(svc)
}

fn generate_statefulset(indexer: &WazuhIndexerCluster) -> Result<StatefulSet> {
    let name = indexer.name_any();
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-indexer".to_string());
    labels.insert("cluster".to_string(), name.clone());

    let owner_ref = indexer.controller_owner_ref(&()).map(|o| vec![o]);

    let sts = StatefulSet {
        metadata: kube::api::ObjectMeta {
            name: Some(name.clone()),
            labels: Some(labels.clone()),
            owner_references: owner_ref,
            ..Default::default()
        },
        spec: Some(k8s_openapi::api::apps::v1::StatefulSetSpec {
            replicas: Some(indexer.spec.replicas),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            service_name: name.clone(),
            template: PodTemplateSpec {
                metadata: Some(kube::api::ObjectMeta {
                    labels: Some(labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "indexer".to_string(),
                        image: Some(format!("wazuh/wazuh-indexer:{}", indexer.spec.version)),
                        env: Some(vec![
                            k8s_openapi::api::core::v1::EnvVar {
                                name: "cluster.name".to_string(),
                                value: Some(name.clone()),
                                ..Default::default()
                            },
                            k8s_openapi::api::core::v1::EnvVar {
                                name: "node.name".to_string(),
                                value_from: Some(k8s_openapi::api::core::v1::EnvVarSource {
                                    field_ref: Some(
                                        k8s_openapi::api::core::v1::ObjectFieldSelector {
                                            field_path: "metadata.name".to_string(),
                                            ..Default::default()
                                        },
                                    ),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                            k8s_openapi::api::core::v1::EnvVar {
                                name: "discovery.seed_hosts".to_string(),
                                value: Some(format!("{}-headless", name)),
                                ..Default::default()
                            },
                            k8s_openapi::api::core::v1::EnvVar {
                                name: "cluster.initial_master_nodes".to_string(),
                                value: Some(
                                    (0..indexer.spec.replicas)
                                        .map(|i| format!("{}-{}", name, i))
                                        .collect::<Vec<_>>()
                                        .join(","),
                                ),
                                ..Default::default()
                            },
                        ]),
                        volume_mounts: Some(vec![VolumeMount {
                            name: "indexer-data".to_string(),
                            mount_path: "/var/lib/wazuh-indexer".to_string(),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            },
            volume_claim_templates: Some(vec![PersistentVolumeClaim {
                metadata: kube::api::ObjectMeta {
                    name: Some("indexer-data".to_string()),
                    ..Default::default()
                },
                spec: Some(PersistentVolumeClaimSpec {
                    access_modes: Some(vec!["ReadWriteOnce".to_string()]),
                    storage_class_name: indexer.spec.storage.storage_class.clone(),
                    resources: Some(VolumeResourceRequirements {
                        requests: Some({
                            let mut requests = BTreeMap::new();
                            requests.insert(
                                "storage".to_string(),
                                Quantity(indexer.spec.storage.size.clone()),
                            );
                            requests
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                status: None,
            }]),
            update_strategy: Some(StatefulSetUpdateStrategy {
                type_: Some("RollingUpdate".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    Ok(sts)
}

/// Error policy for WazuhIndexerCluster reconciliation
pub fn error_policy(
    _indexer: Arc<WazuhIndexerCluster>,
    error: &Error,
    _ctx: Arc<IndexerContext>,
) -> Action {
    error!("Reconciliation failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}
