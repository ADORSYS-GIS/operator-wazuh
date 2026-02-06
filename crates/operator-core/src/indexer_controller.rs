//! WazuhIndexerCluster controller implementation

use crate::ca::{resolve_default_wazuh_ca, resolve_wazuh_ca, ResolvedCa};
use crate::cert_manager::Certificate;
use crate::tls::TlsManager;
use crate::pod_template::apply_pod_template_patch;
use crate::volume_claim::{merge_volume_claims, pvc_from_template};
use k8s_openapi::api::apps::v1::{StatefulSet, StatefulSetUpdateStrategy};
use k8s_openapi::api::core::v1::{
    Capabilities, ConfigMap, Container, ContainerPort, EnvVar, EnvVarSource, ObjectFieldSelector,
    PersistentVolumeClaim, PersistentVolumeClaimSpec, PodSecurityContext, PodSpec,
    PodTemplateSpec, SecurityContext, Service, ServicePort, ServiceSpec, VolumeMount,
    VolumeResourceRequirements,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams, Resource};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};

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

    finalizer(
        &indexer_api,
        "wazuh.adorsys.team/finalizer",
        indexer,
        |event| {
            let ctx = ctx.clone();
            async move {
                match event {
                    FinalizerEvent::Apply(indexer) => reconcile_indexer(indexer, ctx).await,
                    FinalizerEvent::Cleanup(indexer) => cleanup_indexer(indexer, ctx).await,
                }
            }
        },
    )
    .await
    .map_err(|e| Error::ReconciliationError(e.to_string()))
}

async fn reconcile_indexer(
    indexer: Arc<WazuhIndexerCluster>,
    ctx: Arc<IndexerContext>,
) -> Result<Action> {
    let ns = indexer.namespace().unwrap();
    let name = indexer.name_any();
    let workload_name = indexer
        .spec
        .workload
        .as_ref()
        .and_then(|w| w.name.clone())
        .unwrap_or_else(|| name.clone());

    info!("Reconciling WazuhIndexerCluster: {}/{}", ns, name);

    let client = ctx.client.clone();
    let sts_api: Api<StatefulSet> = Api::namespaced(client.clone(), &ns);
    let svc_api: Api<Service> = Api::namespaced(client.clone(), &ns);
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &ns);
    let secret_api: Api<k8s_openapi::api::core::v1::Secret> = Api::namespaced(client.clone(), &ns);

    // 0. Ensure TLS (shared WazuhCA if configured)
    let tls_config = indexer.spec.tls.as_ref();
    let tls_secret_name = tls_config
        .and_then(|t| t.cert_secret.clone())
        .unwrap_or_else(|| format!("{}-tls", name));
    let admin_tls_secret_name = format!("{}-admin-tls", name);

    let mut alt_names = vec![
        name.clone(),
        format!("{}.{}", name, ns),
        format!("{}.{}.svc.cluster.local", name, ns),
        format!("{}-headless", name),
        format!("{}-headless.{}", name, ns),
        format!("{}-headless.{}.svc.cluster.local", name, ns),
    ];
    for i in 0..indexer.spec.replicas {
        alt_names.push(format!("{}-{}", workload_name, i));
        alt_names.push(format!("{}-{}.{}-headless", workload_name, i, name));
        alt_names.push(format!(
            "{}-{}.{}-headless.{}",
            workload_name, i, name, ns
        ));
        alt_names.push(format!(
            "{}-{}.{}-headless.{}.svc.cluster.local",
            workload_name, i, name, ns
        ));
    }

    let server_keys = ["ca.crt", "tls.crt", "tls.key"];
    let admin_keys = ["ca.crt", "tls.crt", "tls.key"];

    let ca_ref = tls_config.and_then(|t| t.ca_ref.as_ref());
    let resolved_ca = if let Some(ca_ref) = ca_ref {
        Some(resolve_wazuh_ca(client.clone(), &ns, ca_ref).await?)
    } else {
        resolve_default_wazuh_ca(client.clone(), &ns).await?
    };

    if let Some(resolved_ca) = resolved_ca {
        match resolved_ca {
            ResolvedCa::SelfSigned { ca_cert, ca_key, .. } => {
                let server_ready = secret_api
                    .get(&tls_secret_name)
                    .await
                    .ok()
                    .map_or(false, |s| secret_has_keys(&s, &server_keys));
                let admin_ready = secret_api
                    .get(&admin_tls_secret_name)
                    .await
                    .ok()
                    .map_or(false, |s| secret_has_keys(&s, &admin_keys));

                if !server_ready || !admin_ready {
                    let (server_cert, server_key) = TlsManager::generate_server_cert(
                        &ca_cert,
                        &ca_key,
                        &format!("{}.{}.svc.cluster.local", name, ns),
                        alt_names.clone(),
                    )?;
                    let (admin_cert, admin_key) = TlsManager::generate_server_cert(
                        &ca_cert,
                        &ca_key,
                        "admin",
                        vec!["admin".to_string()],
                    )?;

                    let owner_ref = indexer.controller_owner_ref(&()).map(|o| vec![o]);
                    let mut server_data = BTreeMap::new();
                    server_data.insert("ca.crt".to_string(), ca_cert.clone());
                    server_data.insert("tls.crt".to_string(), server_cert);
                    server_data.insert("tls.key".to_string(), server_key);
                    let server_secret = k8s_openapi::api::core::v1::Secret {
                        metadata: kube::api::ObjectMeta {
                            name: Some(tls_secret_name.clone()),
                            owner_references: owner_ref.clone(),
                            ..Default::default()
                        },
                        string_data: Some(server_data),
                        ..Default::default()
                    };

                    let mut admin_data = BTreeMap::new();
                    admin_data.insert("ca.crt".to_string(), ca_cert);
                    admin_data.insert("tls.crt".to_string(), admin_cert);
                    admin_data.insert("tls.key".to_string(), admin_key);
                    let admin_secret = k8s_openapi::api::core::v1::Secret {
                        metadata: kube::api::ObjectMeta {
                            name: Some(admin_tls_secret_name.clone()),
                            owner_references: owner_ref,
                            ..Default::default()
                        },
                        string_data: Some(admin_data),
                        ..Default::default()
                    };

                    secret_api
                        .patch(
                            &tls_secret_name,
                            &PatchParams::apply("wazuh-operator"),
                            &Patch::Apply(&server_secret),
                        )
                        .await?;
                    secret_api
                        .patch(
                            &admin_tls_secret_name,
                            &PatchParams::apply("wazuh-operator"),
                            &Patch::Apply(&admin_secret),
                        )
                        .await?;
                }
            }
            ResolvedCa::CertManager { issuer_ref } => {
                let cert_api: Api<Certificate> = Api::namespaced(client.clone(), &ns);
                let owner_ref = indexer.controller_owner_ref(&()).map(|o| vec![o]);

                let server_cert = Certificate {
                    metadata: kube::api::ObjectMeta {
                        name: Some(tls_secret_name.clone()),
                        owner_references: owner_ref.clone(),
                        ..Default::default()
                    },
                    spec: crate::cert_manager::CertificateSpec {
                        secret_name: tls_secret_name.clone(),
                        issuer_ref: issuer_ref.clone(),
                        common_name: Some(format!("{}.{}.svc.cluster.local", name, ns)),
                        dns_names: alt_names.clone(),
                        usages: vec!["server auth".to_string(), "client auth".to_string()],
                    },
                };

                let admin_cert = Certificate {
                    metadata: kube::api::ObjectMeta {
                        name: Some(admin_tls_secret_name.clone()),
                        owner_references: owner_ref,
                        ..Default::default()
                    },
                    spec: crate::cert_manager::CertificateSpec {
                        secret_name: admin_tls_secret_name.clone(),
                        issuer_ref,
                        common_name: Some("admin".to_string()),
                        dns_names: Vec::new(),
                        usages: vec!["client auth".to_string()],
                    },
                };

                cert_api
                    .patch(
                        &tls_secret_name,
                        &PatchParams::apply("wazuh-operator"),
                        &Patch::Apply(&server_cert),
                    )
                    .await?;
                cert_api
                    .patch(
                        &admin_tls_secret_name,
                        &PatchParams::apply("wazuh-operator"),
                        &Patch::Apply(&admin_cert),
                    )
                    .await?;
            }
        }
    } else {
        let server_ready = secret_api
            .get(&tls_secret_name)
            .await
            .ok()
            .map_or(false, |s| secret_has_keys(&s, &server_keys));
        let admin_ready = secret_api
            .get(&admin_tls_secret_name)
            .await
            .ok()
            .map_or(false, |s| secret_has_keys(&s, &admin_keys));

        if !server_ready || !admin_ready {
            let (ca_cert, ca_key) = TlsManager::generate_ca(None)?;
            let (server_cert, server_key) = TlsManager::generate_server_cert(
                &ca_cert,
                &ca_key,
                &format!("{}.{}.svc.cluster.local", name, ns),
                alt_names.clone(),
            )?;
            let (admin_cert, admin_key) = TlsManager::generate_server_cert(
                &ca_cert,
                &ca_key,
                "admin",
                vec!["admin".to_string()],
            )?;

            let owner_ref = indexer.controller_owner_ref(&()).map(|o| vec![o]);
            let mut server_data = BTreeMap::new();
            server_data.insert("ca.crt".to_string(), ca_cert.clone());
            server_data.insert("tls.crt".to_string(), server_cert);
            server_data.insert("tls.key".to_string(), server_key);
            let server_secret = k8s_openapi::api::core::v1::Secret {
                metadata: kube::api::ObjectMeta {
                    name: Some(tls_secret_name.clone()),
                    owner_references: owner_ref.clone(),
                    ..Default::default()
                },
                string_data: Some(server_data),
                ..Default::default()
            };

            let mut admin_data = BTreeMap::new();
            admin_data.insert("ca.crt".to_string(), ca_cert);
            admin_data.insert("tls.crt".to_string(), admin_cert);
            admin_data.insert("tls.key".to_string(), admin_key);
            let admin_secret = k8s_openapi::api::core::v1::Secret {
                metadata: kube::api::ObjectMeta {
                    name: Some(admin_tls_secret_name.clone()),
                    owner_references: owner_ref,
                    ..Default::default()
                },
                string_data: Some(admin_data),
                ..Default::default()
            };

            secret_api
                .patch(
                    &tls_secret_name,
                    &PatchParams::apply("wazuh-operator"),
                    &Patch::Apply(&server_secret),
                )
                .await?;
            secret_api
                .patch(
                    &admin_tls_secret_name,
                    &PatchParams::apply("wazuh-operator"),
                    &Patch::Apply(&admin_secret),
                )
                .await?;
        }
    }

    let tls_secret_rv = secret_api
        .get(&tls_secret_name)
        .await
        .ok()
        .and_then(|s| s.metadata.resource_version)
        .unwrap_or_else(|| "missing".to_string());

    // 1. Generate and Apply ConfigMap
    let cm = generate_configmap(&indexer, &workload_name)?;
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
    let sts = generate_statefulset(&indexer, &workload_name, &tls_secret_rv)?;
    sts_api
        .patch(
            &workload_name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&sts),
        )
        .await?;

    update_status(&indexer, client.clone()).await?;

    info!(
        "Successfully reconciled StatefulSet and Service for {}",
        name
    );

    Ok(Action::requeue(Duration::from_secs(60)))
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
    let workload_name = indexer
        .spec
        .workload
        .as_ref()
        .and_then(|w| w.name.clone())
        .unwrap_or_else(|| name.clone());
    let sts_api: Api<StatefulSet> = Api::namespaced(client, &ns);

    let sts = sts_api.get(&workload_name).await?;
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
    let workload_name = indexer
        .spec
        .workload
        .as_ref()
        .and_then(|w| w.name.clone())
        .unwrap_or_else(|| name.clone());
    let indexer_api: Api<WazuhIndexerCluster> = Api::namespaced(client.clone(), &ns);
    let sts_api: Api<StatefulSet> = Api::namespaced(client, &ns);

    let sts = sts_api.get(&workload_name).await?;
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

fn generate_configmap(indexer: &WazuhIndexerCluster, workload_name: &str) -> Result<ConfigMap> {
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
    let ns = indexer.namespace().unwrap();
    data.insert(
        "opensearch.yml".to_string(),
        format!(
            r#"cluster.name: {}
network.host: 0.0.0.0
bootstrap.memory_lock: true
bootstrap.system_call_filter: false
discovery.seed_hosts: ["{}-0.{}-headless.{}.svc.cluster.local"]
cluster.initial_master_nodes: [{}]
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer
plugins.security.disabled: false
plugins.security.ssl.transport.pemcert_filepath: /usr/share/wazuh-indexer/config/certs/tls.crt
plugins.security.ssl.transport.pemkey_filepath: /usr/share/wazuh-indexer/config/certs/tls.key
plugins.security.ssl.transport.pemtrustedcas_filepath: /usr/share/wazuh-indexer/config/certs/ca.crt
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: /usr/share/wazuh-indexer/config/certs/tls.crt
plugins.security.ssl.http.pemkey_filepath: /usr/share/wazuh-indexer/config/certs/tls.key
plugins.security.ssl.http.pemtrustedcas_filepath: /usr/share/wazuh-indexer/config/certs/ca.crt
plugins.security.allow_unsafe_democertificates: true
plugins.security.authcz.admin_dn:
  - CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US
  - C=US,L=California,O=Wazuh,OU=Wazuh,CN=admin
plugins.security.nodes_dn:
  - "CN=*,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.restapi.roles_enabled:
  - "all_access"
  - "security_rest_api_access"
plugins.security.allow_default_init_securityindex: true
cluster.routing.allocation.disk.threshold_enabled: false
compatibility.override_main_response_version: true
"#,
            name,
            workload_name,
            name,
            ns,
            (0..indexer.spec.replicas)
                .map(|i| format!("{}-{}", workload_name, i))
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
            ports: Some(vec![ServicePort {
                name: Some("http".to_string()),
                port: 9200,
                ..Default::default()
            }]),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    Ok(svc)
}

fn generate_statefulset(
    indexer: &WazuhIndexerCluster,
    workload_name: &str,
    tls_secret_rv: &str,
) -> Result<StatefulSet> {
    let name = indexer.name_any();
    let tls_secret_name = indexer
        .spec
        .tls
        .as_ref()
        .and_then(|t| t.cert_secret.clone())
        .unwrap_or_else(|| format!("{}-tls", name));
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
            name: Some(workload_name.to_string()),
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
            service_name: Some(format!("{}-headless", name.clone())),
            template: {
                let mut tpl = PodTemplateSpec {
                    metadata: Some(kube::api::ObjectMeta {
                        labels: Some(labels),
                        annotations: Some({
                            let mut pod_annotations = annotations;
                            pod_annotations.insert(
                                "wazuh.adorsys.team/tls-secret-rv".to_string(),
                                tls_secret_rv.to_string(),
                            );
                            pod_annotations
                        }),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        security_context: Some(PodSecurityContext {
                            fs_group: Some(101),
                            ..Default::default()
                        }),
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
                                name: "OPENSEARCH_JAVA_OPTS".to_string(),
                                value: Some("-Xms1g -Xmx1g -Dlog4j2.formatMsgNoLookups=true".to_string()),
                                ..Default::default()
                            },
                            EnvVar {
                                name: "NETWORK_HOST".to_string(),
                                value: Some("0.0.0.0".to_string()),
                                ..Default::default()
                            },
                            // EnvVar {
                            //     name: "node.name".to_string(),
                            //     value_from: Some(EnvVarSource {
                            //         field_ref: Some(ObjectFieldSelector {
                            //             field_path: "metadata.name".to_string(),
                            //             ..Default::default()
                            //         }),
                            //         ..Default::default()
                            //     }),
                            //     ..Default::default()
                            // },
                            EnvVar {
                                name: "NODE_NAME".to_string(),
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
                                name: "DISCOVERY_SERVICE".to_string(),
                                value: Some(format!("{}-0.{}-headless.{}.svc.cluster.local", name, name, indexer.namespace().unwrap())),
                                ..Default::default()
                            },
                            EnvVar {
                                name: "KUBERNETES_NAMESPACE".to_string(),
                                value_from: Some(EnvVarSource {
                                    field_ref: Some(ObjectFieldSelector {
                                        field_path: "metadata.namespace".to_string(),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        ]),
                        security_context: Some(SecurityContext {
                            run_as_user: Some(1000),
                            run_as_group: Some(1000),
                            capabilities: Some(Capabilities {
                                add: Some(vec!["SYS_CHROOT".to_string()]),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        volume_mounts: Some(vec![
                            VolumeMount {
                                name: "indexer-data".to_string(),
                                mount_path: "/var/lib/wazuh-indexer".to_string(),
                                ..Default::default()
                            },
                            VolumeMount {
                                name: "config".to_string(),
                                mount_path: "/usr/share/wazuh-indexer/config/opensearch.yml"
                                    .to_string(),
                                sub_path: Some("opensearch.yml".to_string()),
                                ..Default::default()
                            },
                            VolumeMount {
                                name: "tls".to_string(),
                                mount_path: "/usr/share/wazuh-indexer/config/certs".to_string(),
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
                            name: "tls".to_string(),
                            secret: Some(k8s_openapi::api::core::v1::SecretVolumeSource {
                                secret_name: Some(tls_secret_name),
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                }),
                };
                if let Some(patch) = &indexer.spec.pod_template {
                    let _ = apply_pod_template_patch(&mut tpl, patch);
                }
                tpl
            },
            volume_claim_templates: {
                let mut defaults = Vec::new();
                if !indexer.spec.disable_default_pvc.unwrap_or(false) {
                    defaults.push(PersistentVolumeClaim {
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
                    });
                }
                let mut overrides = Vec::new();
                if let Some(templates) = indexer.spec.volume_claim_templates.as_ref() {
                    for tmpl in templates {
                        overrides.push(pvc_from_template(tmpl)?);
                    }
                }
                let merged = merge_volume_claims(defaults, overrides);
                if merged.is_empty() { None } else { Some(merged) }
            },
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

fn secret_has_keys(
    secret: &k8s_openapi::api::core::v1::Secret,
    keys: &[&str],
) -> bool {
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
