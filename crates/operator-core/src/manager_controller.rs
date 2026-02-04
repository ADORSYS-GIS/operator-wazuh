//! WazuhManagerCluster controller implementation

use crate::error::{Error, Result};
use crate::tls::TlsManager;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, EnvVar, PodSpec, PodTemplateSpec, Secret, Service, ServicePort,
    ServiceSpec, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams, Resource};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{finalizer, Event as FinalizerEvent};
use operator_crds::{WazuhIndexerCluster, WazuhManagerCluster};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};

pub struct ManagerContext {
    pub client: kube::Client,
}

impl ManagerContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhManagerCluster
pub async fn reconcile(
    manager: Arc<WazuhManagerCluster>,
    ctx: Arc<ManagerContext>,
) -> Result<Action> {
    let ns = manager
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let manager_api: Api<WazuhManagerCluster> = Api::namespaced(ctx.client.clone(), &ns);

    finalizer(&manager_api, "wazuh.adorsys.team/finalizer", manager, |event| {
        let ctx = ctx.clone();
        async move {
            match event {
                FinalizerEvent::Apply(manager) => reconcile_manager(manager, ctx).await,
                FinalizerEvent::Cleanup(manager) => cleanup_manager(manager, ctx).await,
            }
        }
    })
    .await
    .map_err(|e| Error::ReconciliationError(e.to_string()))
}

async fn reconcile_manager(
    manager: Arc<WazuhManagerCluster>,
    ctx: Arc<ManagerContext>,
) -> Result<Action> {
    let ns = manager.namespace().unwrap();
    let name = manager.name_any();

    info!("Reconciling WazuhManagerCluster: {}/{}", ns, name);

    let client = ctx.client.clone();

    // 1. Resolve indexer reference
    let indexer = resolve_indexer(&manager, client.clone()).await?;
    info!("Resolved indexer: {}", indexer.name_any());

    // 2. Generate TLS certificates
    let (ca_cert, ca_key) = TlsManager::generate_ca()?;
    let (server_cert, server_key) = TlsManager::generate_server_cert(
        &ca_cert,
        &ca_key,
        &format!("{}.{}.svc.cluster.local", name, ns),
        vec![name.clone(), format!("{}.{}", name, ns)],
    )?;

    info!("Generated TLS certificates for {}", name);

    // 3. Generate Cluster Key Secret
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), &ns);
    let key_secret = generate_cluster_key_secret(&manager)?;

    secret_api
        .patch(
            &format!("{}-key", name),
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&key_secret),
        )
        .await?;

    info!("Successfully reconciled Cluster Key Secret for {}", name);

    // 4. Generate ossec.conf ConfigMap
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &ns);
    let cm = generate_config_map(&manager, &indexer)?;

    cm_api
        .patch(
            &format!("{}-config", name),
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&cm),
        )
        .await?;

    // Generate rules ConfigMap
    let rules_cm = generate_rules_config_map(&manager)?;
    cm_api
        .patch(
            &format!("{}-rules", name),
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&rules_cm),
        )
        .await?;

    // Generate decoders ConfigMap
    let decoders_cm = generate_decoders_config_map(&manager)?;
    cm_api
        .patch(
            &format!("{}-decoders", name),
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&decoders_cm),
        )
        .await?;

    info!("Successfully reconciled ConfigMaps for {}", name);

    // 4. Create Services
    let svc_api: Api<Service> = Api::namespaced(client.clone(), &ns);
    let svc = generate_manager_service(&manager)?;

    svc_api
        .patch(
            &name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&svc),
        )
        .await?;

    info!("Successfully reconciled Service for {}", name);

    // 5. Create Headless Service
    let headless_svc = generate_manager_headless_service(&manager)?;
    svc_api
        .patch(
            &format!("{}-headless", name),
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&headless_svc),
        )
        .await?;

    info!("Successfully reconciled Headless Service for {}", name);

    // 6. Create StatefulSet
    let sts_api: Api<StatefulSet> = Api::namespaced(client.clone(), &ns);
    let sts = generate_manager_statefulset(&manager, &indexer)?;

    sts_api
        .patch(
            &name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&sts),
        )
        .await?;

    info!("Successfully reconciled StatefulSet for {}", name);

    // 7. Update status
    update_manager_status(&manager, client).await?;

    Ok(Action::requeue(Duration::from_secs(300)))
}

async fn cleanup_manager(
    manager: Arc<WazuhManagerCluster>,
    _ctx: Arc<ManagerContext>,
) -> Result<Action> {
    let ns = manager.namespace().unwrap();
    let name = manager.name_any();
    info!("Cleaning up WazuhManagerCluster: {}/{}", ns, name);

    Ok(Action::await_change())
}

async fn update_manager_status(manager: &WazuhManagerCluster, client: kube::Client) -> Result<()> {
    let ns = manager.namespace().unwrap();
    let name = manager.name_any();
    let manager_api: Api<WazuhManagerCluster> = Api::namespaced(client.clone(), &ns);
    let sts_api: Api<StatefulSet> = Api::namespaced(client, &ns);

    let sts = sts_api.get(&name).await?;
    let ready_replicas = sts
        .status
        .as_ref()
        .and_then(|s| s.ready_replicas)
        .unwrap_or(0);
    let phase = if ready_replicas == manager.spec.replicas {
        "Ready"
    } else {
        "Progressing"
    };

    let mut status = manager.status.clone().unwrap_or(
        operator_crds::wazuh_manager_cluster::WazuhManagerClusterStatus {
            phase: phase.to_string(),
            ready_nodes: ready_replicas,
            leader: Some(format!("{}-0", name)),
            api_endpoints: vec![format!("{}.{}.svc.cluster.local", name, ns)],
        },
    );

    status.phase = phase.to_string();
    status.ready_nodes = ready_replicas;

    let patch = serde_json::json!({
        "status": status
    });

    manager_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    Ok(())
}

fn generate_manager_statefulset(
    manager: &WazuhManagerCluster,
    indexer: &WazuhIndexerCluster,
) -> Result<StatefulSet> {
    let name = manager.name_any();
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-manager".to_string());
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

    let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);

    Ok(StatefulSet {
        metadata: kube::api::ObjectMeta {
            name: Some(name.clone()),
            labels: Some(labels.clone()),
            annotations: Some(annotations.clone()),
            owner_references: owner_ref,
            ..Default::default()
        },
        spec: Some(k8s_openapi::api::apps::v1::StatefulSetSpec {
            replicas: Some(manager.spec.replicas),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            service_name: Some(format!("{}-headless", name)),
            template: PodTemplateSpec {
                metadata: Some(kube::api::ObjectMeta {
                    labels: Some(labels),
                    annotations: Some({
                        let mut ann = annotations;
                        ann.insert(
                            "wazuh.adorsys.team/config-hash".to_string(),
                            "PLACEHOLDER_HASH".to_string(),
                        );
                        ann
                    }),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "manager".to_string(),
                        image: Some(format!("wazuh/wazuh-manager:{}", manager.spec.version)),
                        env: Some(vec![
                            EnvVar {
                                name: "INDEXER_URL".to_string(),
                                value: Some(format!(
                                    "https://{}.{}.svc.cluster.local:9200",
                                    indexer.name_any(),
                                    indexer.namespace().unwrap()
                                )),
                                ..Default::default()
                            },
                            EnvVar {
                                name: "INDEXER_USER".to_string(),
                                value: Some("admin".to_string()),
                                ..Default::default()
                            },
                            EnvVar {
                                name: "INDEXER_PASSWORD".to_string(),
                                value: Some("admin".to_string()),
                                ..Default::default()
                            },
                        ]),
                        volume_mounts: Some(vec![
                            VolumeMount {
                                name: "config".to_string(),
                                mount_path: "/var/ossec/etc/ossec.conf".to_string(),
                                sub_path: Some("ossec.conf".to_string()),
                                ..Default::default()
                            },
                            VolumeMount {
                                name: "rules".to_string(),
                                mount_path: "/var/ossec/etc/rules/local_rules.xml".to_string(),
                                sub_path: Some("local_rules.xml".to_string()),
                                ..Default::default()
                            },
                            VolumeMount {
                                name: "decoders".to_string(),
                                mount_path: "/var/ossec/etc/decoders/local_decoder.xml".to_string(),
                                sub_path: Some("local_decoder.xml".to_string()),
                                ..Default::default()
                            },
                        ]),
                        ..Default::default()
                    }],
                    volumes: Some(vec![
                        k8s_openapi::api::core::v1::Volume {
                            name: "config".to_string(),
                            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                                name: format!("{}-config", name),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        k8s_openapi::api::core::v1::Volume {
                            name: "rules".to_string(),
                            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                                name: format!("{}-rules", name),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                        k8s_openapi::api::core::v1::Volume {
                            name: "decoders".to_string(),
                            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                                name: format!("{}-decoders", name),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn generate_cluster_key_secret(manager: &WazuhManagerCluster) -> Result<Secret> {
    let name = manager.name_any();
    let mut data = BTreeMap::new();

    // TODO
    //  In a real implementation, we would check if the secret already exists
    //  and reuse the key. For now, we generate a new one.
    let key = "REPLACE_WITH_RANDOM_KEY_32_CHARS_LONG";
    data.insert("cluster-key".to_string(), key.to_string());

    let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);

    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-manager".to_string());
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

    Ok(Secret {
        metadata: kube::api::ObjectMeta {
            name: Some(format!("{}-key", name)),
            labels: Some(labels),
            annotations: Some(annotations),
            owner_references: owner_ref,
            ..Default::default()
        },
        string_data: Some(data),
        ..Default::default()
    })
}

fn generate_manager_service(manager: &WazuhManagerCluster) -> Result<Service> {
    let name = manager.name_any();
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-manager".to_string());
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

    let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);

    Ok(Service {
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
                    name: Some("agent-auth".to_string()),
                    port: 1515,
                    ..Default::default()
                },
                ServicePort {
                    name: Some("agent-conn".to_string()),
                    port: 1514,
                    ..Default::default()
                },
                ServicePort {
                    name: Some("api".to_string()),
                    port: 55000,
                    ..Default::default()
                },
            ]),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn generate_manager_headless_service(manager: &WazuhManagerCluster) -> Result<Service> {
    let name = manager.name_any();
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-manager".to_string());
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

    let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);

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
            ports: Some(vec![ServicePort {
                name: Some("cluster".to_string()),
                port: 1516,
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn generate_config_map(
    manager: &WazuhManagerCluster,
    indexer: &WazuhIndexerCluster,
) -> Result<ConfigMap> {
    let name = manager.name_any();
    let indexer_name = indexer.name_any();
    let indexer_ns = indexer.namespace().unwrap();

    let ossec_conf = format!(
        r#"<ossec_config>
  <cluster>
    <name>wazuh</name>
    <node_name>NODE_NAME</node_name>
    <node_type>NODE_TYPE</node_type>
    <key>CLUSTER_KEY</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>{}-headless.{}.svc.cluster.local</node>
    </nodes>
    <hidden>no</hidden>
  </cluster>
  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://{}.{}.svc.cluster.local:9200</host>
    </hosts>
  </indexer>
</ossec_config>"#,
        name,
        manager.namespace().unwrap(),
        indexer_name,
        indexer_ns
    );

    let mut data = BTreeMap::new();
    data.insert("ossec.conf".to_string(), ossec_conf);

    let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);

    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-manager".to_string());
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

fn generate_rules_config_map(manager: &WazuhManagerCluster) -> Result<ConfigMap> {
    let name = manager.name_any();
    let mut data = BTreeMap::new();
    data.insert(
        "local_rules.xml".to_string(),
        "<group name=\"local, \">\n</group>".to_string(),
    );

    let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);

    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-manager".to_string());
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

    Ok(ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(format!("{}-rules", name)),
            labels: Some(labels),
            annotations: Some(annotations),
            owner_references: owner_ref,
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    })
}

fn generate_decoders_config_map(manager: &WazuhManagerCluster) -> Result<ConfigMap> {
    let name = manager.name_any();
    let mut data = BTreeMap::new();
    data.insert(
        "local_decoder.xml".to_string(),
        "<decoder name=\"local_decoder\">\n</decoder>".to_string(),
    );

    let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);

    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-manager".to_string());
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

    Ok(ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(format!("{}-decoders", name)),
            labels: Some(labels),
            annotations: Some(annotations),
            owner_references: owner_ref,
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    })
}

async fn resolve_indexer(
    manager: &WazuhManagerCluster,
    client: kube::Client,
) -> Result<WazuhIndexerCluster> {
    let ns = manager
        .spec
        .indexer_cluster
        .namespace
        .clone()
        .unwrap_or_else(|| manager.namespace().unwrap());
    let name = &manager.spec.indexer_cluster.name;

    let indexer_api: Api<WazuhIndexerCluster> = Api::namespaced(client, &ns);
    let indexer = indexer_api.get(name).await?;

    Ok(indexer)
}

/// Error policy for WazuhManagerCluster reconciliation
pub fn error_policy(
    _manager: Arc<WazuhManagerCluster>,
    error: &Error,
    _ctx: Arc<ManagerContext>,
) -> Action {
    error!("Reconciliation failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}
