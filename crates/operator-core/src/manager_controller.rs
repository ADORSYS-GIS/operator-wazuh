//! WazuhManagerCluster controller implementation

use crate::ca::{ResolvedCa, resolve_default_wazuh_ca, resolve_wazuh_ca};
use crate::cert_manager::Certificate;
use crate::error::{Error, Result};
use crate::tls::TlsManager;
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{
    Capabilities, ConfigMap, Container, EnvVar, EnvVarSource, Pod, PodSecurityContext, PodSpec,
    PodTemplateSpec, Secret, SecretKeySelector, SecurityContext, Service, ServicePort, ServiceSpec,
    VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::ResourceExt;
use kube::api::{Api, ListParams, Patch, PatchParams, Resource};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use operator_crds::{
    ListenerServiceMode, WazuhIndexerCluster, WazuhListener, WazuhManager, WazuhManagerCluster,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};
use uuid::Uuid;

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

    finalizer(
        &manager_api,
        "wazuh.adorsys.team/finalizer",
        manager,
        |event| {
            let ctx = ctx.clone();
            async move {
                match event {
                    FinalizerEvent::Apply(manager) => reconcile_manager(manager, ctx).await,
                    FinalizerEvent::Cleanup(manager) => cleanup_manager(manager, ctx).await,
                }
            }
        },
    )
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
    let api_secret_name = manager
        .spec
        .api_secret_ref
        .as_ref()
        .map(|s| s.name.clone())
        .ok_or_else(|| {
            Error::ValidationError(format!(
                "Missing API credentials secret for manager cluster {}/{}: set spec.apiSecretRef.name",
                ns, name
            ))
        })?;

    // 1. Resolve indexer reference
    let indexer = resolve_indexer(&manager, client.clone()).await?;
    info!("Resolved indexer: {}", indexer.name_any());

    // Detect WazuhManager workloads for this cluster (new model)
    let workload_api: Api<WazuhManager> = Api::namespaced(client.clone(), &ns);
    let workloads = workload_api.list(&ListParams::default()).await?;
    let has_workloads = workloads.iter().any(|workload| {
        let ref_ns = workload
            .spec
            .cluster_ref
            .namespace
            .clone()
            .unwrap_or_else(|| ns.clone());
        workload.spec.cluster_ref.name == name && ref_ns == ns
    });

    // 2. Ensure TLS (shared WazuhCA if configured)
    let tls_secret_name = format!("{}-tls", name);
    let mut alt_names = vec![
        name.clone(),
        format!("{}.{}", name, ns),
        format!("{}.{}.svc.cluster.local", name, ns),
        format!("{}-headless", name),
        format!("{}-headless.{}", name, ns),
        format!("{}-headless.{}.svc.cluster.local", name, ns),
    ];
    for i in 0..manager.spec.replicas {
        alt_names.push(format!("{}-{}", name, i));
        alt_names.push(format!("{}-{}.{}-headless", name, i, name));
        alt_names.push(format!("{}-{}.{}-headless.{}", name, i, name, ns));
        alt_names.push(format!(
            "{}-{}.{}-headless.{}.svc.cluster.local",
            name, i, name, ns
        ));
    }

    let server_keys = ["ca.crt", "tls.crt", "tls.key"];
    let ca_ref = manager.spec.tls.as_ref().and_then(|t| t.ca_ref.as_ref());
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), &ns);

    let resolved_ca = if let Some(ca_ref) = ca_ref {
        Some(resolve_wazuh_ca(client.clone(), &ns, ca_ref).await?)
    } else {
        resolve_default_wazuh_ca(client.clone(), &ns).await?
    };

    if let Some(resolved_ca) = resolved_ca {
        match resolved_ca {
            ResolvedCa::SelfSigned {
                ca_cert, ca_key, ..
            } => {
                let server_ready = secret_api
                    .get(&tls_secret_name)
                    .await
                    .ok()
                    .map_or(false, |s| secret_has_keys(&s, &server_keys));
                if !server_ready {
                    let (server_cert, server_key) = TlsManager::generate_server_cert(
                        &ca_cert,
                        &ca_key,
                        &format!("{}.{}.svc.cluster.local", name, ns),
                        alt_names.clone(),
                    )?;

                    let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);
                    let mut tls_data = BTreeMap::new();
                    tls_data.insert("ca.crt".to_string(), ca_cert);
                    tls_data.insert("tls.crt".to_string(), server_cert);
                    tls_data.insert("tls.key".to_string(), server_key);

                    let tls_secret = Secret {
                        metadata: kube::api::ObjectMeta {
                            name: Some(tls_secret_name.clone()),
                            owner_references: owner_ref,
                            ..Default::default()
                        },
                        string_data: Some(tls_data),
                        ..Default::default()
                    };

                    secret_api
                        .patch(
                            &tls_secret_name,
                            &PatchParams::apply("wazuh-operator"),
                            &Patch::Apply(&tls_secret),
                        )
                        .await?;
                }
            }
            ResolvedCa::CertManager { issuer_ref } => {
                let cert_api: Api<Certificate> = Api::namespaced(client.clone(), &ns);
                let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);

                let server_cert = Certificate {
                    metadata: kube::api::ObjectMeta {
                        name: Some(tls_secret_name.clone()),
                        owner_references: owner_ref,
                        ..Default::default()
                    },
                    spec: crate::cert_manager::CertificateSpec {
                        secret_name: tls_secret_name.clone(),
                        issuer_ref,
                        common_name: Some(format!("{}.{}.svc.cluster.local", name, ns)),
                        dns_names: alt_names.clone(),
                        usages: vec!["server auth".to_string(), "client auth".to_string()],
                    },
                };

                cert_api
                    .patch(
                        &tls_secret_name,
                        &PatchParams::apply("wazuh-operator"),
                        &Patch::Apply(&server_cert),
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
        if !server_ready {
            let (ca_cert, ca_key) = TlsManager::generate_ca(None)?;
            let (server_cert, server_key) = TlsManager::generate_server_cert(
                &ca_cert,
                &ca_key,
                &format!("{}.{}.svc.cluster.local", name, ns),
                alt_names.clone(),
            )?;

            let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);
            let mut tls_data = BTreeMap::new();
            tls_data.insert("ca.crt".to_string(), ca_cert);
            tls_data.insert("tls.crt".to_string(), server_cert);
            tls_data.insert("tls.key".to_string(), server_key);

            let tls_secret = Secret {
                metadata: kube::api::ObjectMeta {
                    name: Some(tls_secret_name.clone()),
                    owner_references: owner_ref,
                    ..Default::default()
                },
                string_data: Some(tls_data),
                ..Default::default()
            };

            secret_api
                .patch(
                    &tls_secret_name,
                    &PatchParams::apply("wazuh-operator"),
                    &Patch::Apply(&tls_secret),
                )
                .await?;
        }
    }

    // 3. Generate Cluster Key Secret
    let key_secret_name = format!("{}-key", name);
    let existing_key_secret = match secret_api.get(&key_secret_name).await {
        Ok(s) => Some(s),
        Err(kube::Error::Api(ae)) if ae.code == 404 => None,
        Err(e) => return Err(e.into()),
    };
    let key_secret = generate_cluster_key_secret(&manager, existing_key_secret.as_ref())?;

    let key_secret = secret_api
        .patch(
            &key_secret_name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&key_secret),
        )
        .await?;
    let key_secret_rv = key_secret
        .metadata
        .resource_version
        .clone()
        .unwrap_or_default();

    info!("Successfully reconciled Cluster Key Secret for {}", name);

    // 4. Generate ConfigMaps (legacy path only)
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &ns);
    if !has_workloads {
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

        // Generate Nginx ConfigMap if enabled
        let nginx_enabled = manager
            .spec
            .nginx
            .as_ref()
            .map(|n| n.enabled)
            .unwrap_or(false);
        if nginx_enabled {
            let nginx_cm = generate_nginx_config_map(&manager)?;
            cm_api
                .patch(
                    &format!("{}-nginx-config", name),
                    &PatchParams::apply("wazuh-operator"),
                    &Patch::Apply(&nginx_cm),
                )
                .await?;
        }

        info!("Successfully reconciled ConfigMaps for {}", name);
    }

    // 4. Create Services
    let listener_api: Api<WazuhListener> = Api::namespaced(client.clone(), &ns);
    let listeners = listener_api.list(&ListParams::default()).await?;
    let extra_ports = collect_attached_listener_service_ports(&listeners, &name, &ns);

    let svc_api: Api<Service> = Api::namespaced(client.clone(), &ns);
    let svc = generate_manager_service(&manager, &extra_ports)?;

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

    let tls_secret_rv = secret_api
        .get(&tls_secret_name)
        .await
        .ok()
        .and_then(|s| s.metadata.resource_version)
        .unwrap_or_else(|| "missing".to_string());

    // 6. Create StatefulSet (legacy path only)
    if !has_workloads {
        let sts_api: Api<StatefulSet> = Api::namespaced(client.clone(), &ns);
        let sts = generate_manager_statefulset(
            &manager,
            &indexer,
            &api_secret_name,
            &tls_secret_rv,
            &key_secret_rv,
        )?;

        sts_api
            .patch(
                &name,
                &PatchParams::apply("wazuh-operator"),
                &Patch::Apply(&sts),
            )
            .await?;

        info!("Successfully reconciled StatefulSet for {}", name);
    }

    // 7. Update status
    update_manager_status(&manager, client, has_workloads).await?;

    Ok(Action::requeue(Duration::from_secs(60)))
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

async fn update_manager_status(
    manager: &WazuhManagerCluster,
    client: kube::Client,
    has_workloads: bool,
) -> Result<()> {
    let ns = manager.namespace().unwrap();
    let name = manager.name_any();
    let manager_api: Api<WazuhManagerCluster> = Api::namespaced(client.clone(), &ns);
    let (ready_replicas, desired_replicas) = if has_workloads {
        let pod_api: Api<Pod> = Api::namespaced(client.clone(), &ns);
        let selector = format!("app=wazuh-manager,cluster={}", name);
        let pods = pod_api
            .list(&ListParams::default().labels(&selector))
            .await?;
        let ready = pods.items.iter().filter(|p| pod_ready(p)).count() as i32;

        let workload_api: Api<WazuhManager> = Api::namespaced(client.clone(), &ns);
        let workloads = workload_api.list(&ListParams::default()).await?;
        let desired = workloads
            .iter()
            .filter(|workload| {
                let ref_ns = workload
                    .spec
                    .cluster_ref
                    .namespace
                    .clone()
                    .unwrap_or_else(|| ns.clone());
                workload.spec.cluster_ref.name == name && ref_ns == ns
            })
            .map(|workload| workload.spec.replicas)
            .sum();

        (ready, desired)
    } else {
        let sts_api: Api<StatefulSet> = Api::namespaced(client.clone(), &ns);
        let sts = sts_api.get(&name).await?;
        let ready = sts
            .status
            .as_ref()
            .and_then(|s| s.ready_replicas)
            .unwrap_or(0);
        (ready, manager.spec.replicas)
    };

    let phase = if desired_replicas > 0 && ready_replicas == desired_replicas {
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

fn pod_ready(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .map(|conditions| {
            conditions
                .iter()
                .any(|cond| cond.type_ == "Ready" && cond.status == "True")
        })
        .unwrap_or(false)
}

fn generate_manager_statefulset(
    manager: &WazuhManagerCluster,
    indexer: &WazuhIndexerCluster,
    api_secret_name: &str,
    tls_secret_rv: &str,
    key_secret_rv: &str,
) -> Result<StatefulSet> {
    let name = manager.name_any();
    let nginx_enabled = manager
        .spec
        .nginx
        .as_ref()
        .map(|n| n.enabled)
        .unwrap_or(false);

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

    let mut containers = vec![Container {
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
                name: "INDEXER_USERNAME".to_string(),
                value: Some("admin".to_string()),
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
            EnvVar {
                name: "API_USERNAME".to_string(),
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        key: "username".to_string(),
                        name: api_secret_name.to_string(),
                        optional: Some(false),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            EnvVar {
                name: "API_PASSWORD".to_string(),
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        key: "password".to_string(),
                        name: api_secret_name.to_string(),
                        optional: Some(false),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            EnvVar {
                name: "WAZUH_CLUSTER_KEY".to_string(),
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        key: "cluster-key".to_string(),
                        name: format!("{}-key", name),
                        optional: Some(false),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]),
        security_context: Some(SecurityContext {
            capabilities: Some(Capabilities {
                add: Some(vec!["SYS_CHROOT".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        }),
        volume_mounts: Some(vec![
            VolumeMount {
                name: "config".to_string(),
                mount_path: "/wazuh-config-mount/etc".to_string(),
                ..Default::default()
            },
            VolumeMount {
                name: "rules".to_string(),
                mount_path: "/wazuh-config-mount/etc/rules".to_string(),
                ..Default::default()
            },
            VolumeMount {
                name: "decoders".to_string(),
                mount_path: "/wazuh-config-mount/etc/decoders".to_string(),
                ..Default::default()
            },
            VolumeMount {
                name: "tls".to_string(),
                mount_path: "/wazuh-config-mount/etc/certs".to_string(),
                ..Default::default()
            },
        ]),
        ..Default::default()
    }];

    if nginx_enabled {
        containers.push(Container {
            name: "nginx".to_string(),
            image: Some("nginx:latest".to_string()),
            volume_mounts: Some(vec![
                VolumeMount {
                    name: "nginx-config".to_string(),
                    mount_path: "/etc/nginx/nginx.conf".to_string(),
                    sub_path: Some("nginx.conf".to_string()),
                    ..Default::default()
                },
                VolumeMount {
                    name: "tls".to_string(),
                    mount_path: "/etc/nginx/certs".to_string(),
                    read_only: Some(true),
                    ..Default::default()
                },
            ]),
            ports: Some(vec![k8s_openapi::api::core::v1::ContainerPort {
                container_port: 8443,
                name: Some("https".to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        });
    }

    let mut volumes = vec![
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
        k8s_openapi::api::core::v1::Volume {
            name: "tls".to_string(),
            secret: Some(k8s_openapi::api::core::v1::SecretVolumeSource {
                secret_name: Some(format!("{}-tls", name)),
                ..Default::default()
            }),
            ..Default::default()
        },
    ];

    if nginx_enabled {
        volumes.push(k8s_openapi::api::core::v1::Volume {
            name: "nginx-config".to_string(),
            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                name: format!("{}-nginx-config", name),
                ..Default::default()
            }),
            ..Default::default()
        });
    }

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
                            "wazuh.adorsys.team/tls-secret-rv".to_string(),
                            tls_secret_rv.to_string(),
                        );
                        ann.insert(
                            "wazuh.adorsys.team/cluster-key-secret-rv".to_string(),
                            key_secret_rv.to_string(),
                        );
                        ann
                    }),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    security_context: Some(PodSecurityContext {
                        fs_group: Some(101),
                        ..Default::default()
                    }),
                    containers,
                    volumes: Some(volumes),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn generate_cluster_key_secret(
    manager: &WazuhManagerCluster,
    existing: Option<&Secret>,
) -> Result<Secret> {
    let name = manager.name_any();
    let mut data = BTreeMap::new();

    let existing_key = existing
        .and_then(|s| {
            if let Some(string_data) = s.string_data.as_ref() {
                return string_data.get("cluster-key").cloned();
            }
            let data = s.data.as_ref()?;
            let bs = data.get("cluster-key")?;
            String::from_utf8(bs.0.clone()).ok()
        })
        .map(|s| s.trim().to_string())
        .filter(|s| s.len() == 32);

    let key = existing_key.unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    data.insert("cluster-key".to_string(), key);

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

fn generate_manager_service(
    manager: &WazuhManagerCluster,
    extra_ports: &[ServicePort],
) -> Result<Service> {
    let name = manager.name_any();
    let nginx_enabled = manager
        .spec
        .nginx
        .as_ref()
        .map(|n| n.enabled)
        .unwrap_or(false);
    let api_port = if nginx_enabled { 8443 } else { 55000 };

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

    let mut ports = vec![
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
            port: api_port,
            target_port: Some(
                k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(api_port),
            ),
            ..Default::default()
        },
    ];
    for p in extra_ports {
        if ports.iter().any(|existing| existing.port == p.port) {
            continue;
        }
        ports.push(p.clone());
    }

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
            ports: Some(ports),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn collect_attached_listener_service_ports(
    listeners: &kube::api::ObjectList<WazuhListener>,
    cluster_name: &str,
    namespace: &str,
) -> Vec<ServicePort> {
    let mut ports = Vec::new();

    for listener in listeners.items.iter() {
        let mode = listener
            .spec
            .service
            .as_ref()
            .and_then(|s| s.mode.clone())
            .unwrap_or(ListenerServiceMode::Attach);
        if !matches!(mode, ListenerServiceMode::Attach) {
            continue;
        }
        let mref = match listener.spec.manager_cluster.as_ref() {
            Some(r) => r,
            None => continue,
        };
        let ref_ns = mref
            .namespace
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or(namespace);
        if mref.name != cluster_name || ref_ns != namespace {
            continue;
        }
        // Attach mode is cluster-wide; use create mode for per-workload selectors.
        if listener.spec.node_selector.is_some()
            || listener
                .spec
                .selectors
                .as_ref()
                .map_or(false, |s| !s.is_empty())
        {
            continue;
        }

        let proto = listener.spec.protocol.to_uppercase();
        let port_name = format!("lst-{}-{}", listener.spec.port, proto.to_lowercase());
        ports.push(ServicePort {
            name: Some(port_name.chars().take(15).collect()),
            port: listener.spec.port,
            protocol: Some(proto),
            ..Default::default()
        });
    }

    ports.sort_by(|a, b| a.port.cmp(&b.port));
    ports.dedup_by(|a, b| a.port == b.port);
    ports
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
	    <node_name>to_be_replaced_by_hostname</node_name>
	    <node_type>NODE_TYPE</node_type>
	    <key>to_be_replaced_by_cluster_key</key>
	    <port>1516</port>
	    <bind_addr>0.0.0.0</bind_addr>
	    <nodes>
	        <node>{}-headless.{}.svc.cluster.local</node>
	    </nodes>
	    <hidden>no</hidden>
	  </cluster>
	  <remote>
	    <connection>secure</connection>
	    <port>1514</port>
	    <protocol>tcp</protocol>
	  </remote>
	  <auth>
	    <disabled>no</disabled>
	    <port>1515</port>
	  </auth>
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
        "<group name=\"local,\">\n</group>".to_string(),
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
        "<decoder name=\"local_decoder\">\n  <prematch>^$</prematch>\n</decoder>".to_string(),
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

fn generate_nginx_config_map(manager: &WazuhManagerCluster) -> Result<ConfigMap> {
    let name = manager.name_any();
    let mut data = BTreeMap::new();
    let config = r#"
events {
  worker_connections 1024;
}
http {
  server {
    listen 8443 ssl;
    ssl_certificate /etc/nginx/certs/tls.crt;
    ssl_certificate_key /etc/nginx/certs/tls.key;
    
    location / {
      proxy_pass https://127.0.0.1:55000;
      proxy_ssl_verify off;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
    }
  }
}
"#;
    data.insert("nginx.conf".to_string(), config.to_string());

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
            name: Some(format!("{}-nginx-config", name)),
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
