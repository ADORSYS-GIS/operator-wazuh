//! WazuhIndexerCluster controller implementation

use k8s_openapi::api::apps::v1::{StatefulSet, StatefulSetUpdateStrategy};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, ContainerPort, EnvVar, EnvVarSource, ObjectFieldSelector,
    PersistentVolumeClaim, PersistentVolumeClaimSpec, PodSpec, PodTemplateSpec, Service,
    ServicePort, ServiceSpec, VolumeMount, VolumeResourceRequirements,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, LabelSelector, OwnerReference};
use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams, Resource};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{finalizer, Event as FinalizerEvent};
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
    let indexer_api: Api<WazuhIndexerCluster> = Api::namespaced(ctx.client.clone(), &ns);

    finalizer(&indexer_api, "wazuh.adorsys.team/finalizer", indexer, |event| {
        let ctx = ctx.clone();
        async move {
            match event {
                FinalizerEvent::Apply(indexer) => reconcile_indexer(indexer, ctx).await,
                FinalizerEvent::Cleanup(indexer) => cleanup_indexer(indexer, ctx).await,
            }
        }
    })
    .await
    .map_err(|e| Error::ReconciliationError(e.to_string()))
}

async fn reconcile_indexer(
    indexer: Arc<WazuhIndexerCluster>,
    ctx: Arc<IndexerContext>,
) -> Result<Action> {
    let ns = indexer.namespace().unwrap();
    let name = indexer.name_any();

    info!("Reconciling WazuhIndexerCluster: {}/{}", ns, name);

    let client = ctx.client.clone();
    let sts_api: Api<StatefulSet> = Api::namespaced(client.clone(), &ns);
    let svc_api: Api<Service> = Api::namespaced(client.clone(), &ns);
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &ns);

    // 1. Generate and Apply ConfigMap
    let cm = generate_configmap(&indexer)?;
    cm_api
        .patch(
            &format!("{}-config", name),
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&cm),
        )
        .await?;

    // 2. Generate and Apply Headless Service
    let headless_svc = generate_headless_service(&indexer)?;
    svc_api
        .patch(
            &format!("{}-headless", name),
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&headless_svc),
        )
        .await?;

    // 3. Generate and Apply Client Service
    let svc = generate_service(&indexer)?;
    svc_api
        .patch(
            &name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&svc),
        )
        .await?;

    // 4. Generate and Apply StatefulSet
    let sts = generate_statefulset(&indexer)?;
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

async fn cleanup_indexer(
    indexer: Arc<WazuhIndexerCluster>,
    _ctx: Arc<IndexerContext>,
) -> Result<Action> {
    let ns = indexer.namespace().unwrap();
    let name = indexer.name_any();
    info!("Cleaning up WazuhIndexerCluster: {}/{}", ns, name);

    // K8s garbage collection handles owned resources (StatefulSet, Service, ConfigMap)
    // because we set owner references.
    // If we had external resources (e.g. cloud LB, external DB), we would clean them here.

    Ok(Action::await_change())
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

fn generate_configmap(indexer: &WazuhIndexerCluster) -> Result<ConfigMap> {
    let name = indexer.name_any();
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-indexer".to_string());
    labels.insert("cluster".to_string(), name.clone());
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "wazuh-operator".to_string(),
    );

    let mut annotations = BTreeMap::new();
    annotations.insert(
        "app.kubernetes.io/created-by".to_string(),
        "wazuh-operator".to_string(),
    );

    let owner_ref = indexer.controller_owner_ref(&()).map(|o| vec![o]);

    let mut data = BTreeMap::new();
    data.insert(
        "opensearch.yml".to_string(),
        format!(
            r#"cluster.name: {}
network.host: 0.0.0.0
bootstrap.memory_lock: true
discovery.seed_hosts: ["{}-headless"]
cluster.initial_master_nodes: [{}]
plugins.security.disabled: true
"#,
            name,
            name,
            (0..indexer.spec.replicas)
                .map(|i| format!("{}-{}", name, i))
                .collect::<Vec<_>>()
                .join(",")
        ),
    );

    Ok(ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(format!("{}-config", name)),
            labels: Some(labels),
            annotations: Some(annotations),
            owner_references: owner_ref,
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    })
}

fn generate_headless_service(indexer: &WazuhIndexerCluster) -> Result<Service> {
    let name = indexer.name_any();
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-indexer".to_string());
    labels.insert("cluster".to_string(), name.clone());
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "wazuh-operator".to_string(),
    );

    let mut annotations = BTreeMap::new();
    annotations.insert(
        "app.kubernetes.io/created-by".to_string(),
        "wazuh-operator".to_string(),
    );

    let owner_ref = indexer.controller_owner_ref(&()).map(|o| vec![o]);

    Ok(Service {
        metadata: kube::api::ObjectMeta {
            name: Some(format!("{}-headless", name)),
            labels: Some(labels.clone()),
            annotations: Some(annotations),
            owner_references: owner_ref,
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            cluster_ip: Some("None".to_string()),
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
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn generate_service(indexer: &WazuhIndexerCluster) -> Result<Service> {
    let name = indexer.name_any();
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-indexer".to_string());
    labels.insert("cluster".to_string(), name.clone());
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "wazuh-operator".to_string(),
    );

    let mut annotations = BTreeMap::new();
    annotations.insert(
        "app.kubernetes.io/created-by".to_string(),
        "wazuh-operator".to_string(),
    );

    let owner_ref = indexer.controller_owner_ref(&()).map(|o| vec![o]);

    let svc = Service {
        metadata: kube::api::ObjectMeta {
            name: Some(name.clone()),
            labels: Some(labels.clone()),
            annotations: Some(annotations),
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
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "wazuh-operator".to_string(),
    );

    let mut annotations = BTreeMap::new();
    annotations.insert(
        "app.kubernetes.io/created-by".to_string(),
        "wazuh-operator".to_string(),
    );

    let owner_ref = indexer.controller_owner_ref(&()).map(|o| vec![o]);

    let sts = StatefulSet {
        metadata: kube::api::ObjectMeta {
            name: Some(name.clone()),
            labels: Some(labels.clone()),
            annotations: Some(annotations.clone()),
            owner_references: owner_ref,
            ..Default::default()
        },
        spec: Some(k8s_openapi::api::apps::v1::StatefulSetSpec {
            replicas: Some(indexer.spec.replicas),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            service_name: Some(name.clone()),
            template: PodTemplateSpec {
                metadata: Some(kube::api::ObjectMeta {
                    labels: Some(labels),
                    annotations: Some(annotations),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "indexer".to_string(),
                        image: Some(format!("wazuh/wazuh-indexer:{}", indexer.spec.version)),
                        ports: Some(vec![
                            ContainerPort {
                                name: Some("http".to_string()),
                                container_port: 9200,
                                ..Default::default()
                            },
                            ContainerPort {
                                name: Some("transport".to_string()),
                                container_port: 9300,
                                ..Default::default()
                            },
                        ]),
                        env: Some(vec![
                            EnvVar {
                                name: "node.name".to_string(),
                                value_from: Some(EnvVarSource {
                                    field_ref: Some(ObjectFieldSelector {
                                        field_path: "metadata.name".to_string(),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                            EnvVar {
                                name: "OPENSEARCH_JAVA_OPTS".to_string(),
                                value: Some("-Xms512m -Xmx512m".to_string()),
                                ..Default::default()
                            },
                        ]),
                        volume_mounts: Some(vec![
                            VolumeMount {
                                name: "indexer-data".to_string(),
                                mount_path: "/usr/share/opensearch/data".to_string(),
                                ..Default::default()
                            },
                            VolumeMount {
                                name: "config".to_string(),
                                mount_path: "/usr/share/opensearch/config/opensearch.yml".to_string(),
                                sub_path: Some("opensearch.yml".to_string()),
                                ..Default::default()
                            },
                        ]),
                        ..Default::default()
                    }],
                    volumes: Some(vec![k8s_openapi::api::core::v1::Volume {
                        name: "config".to_string(),
                        config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                            name: format!("{}-config", name),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
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
