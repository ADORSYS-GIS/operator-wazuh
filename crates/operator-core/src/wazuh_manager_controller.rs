//! WazuhManager controller implementation

use crate::config_aggregator::{ConfigAggregator, ListenerPort};
use crate::error::{Error, Result};
use k8s_openapi::api::apps::v1::{StatefulSet, StatefulSetUpdateStrategy};
use k8s_openapi::api::core::v1::{
    Capabilities, ConfigMap, Container, ContainerPort, EnvVar, EnvVarSource, ObjectFieldSelector,
    PodSecurityContext, PodSpec, PodTemplateSpec, SecurityContext, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::api::{Api, Patch, PatchParams, Resource};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{finalizer, Event as FinalizerEvent};
use kube::{ResourceExt};
use crate::pod_template::apply_pod_template_patch;
use crate::volume_claim::{merge_volume_claims, pvc_from_template};
use operator_crds::{
    WazuhIndexerCluster, WazuhManager, WazuhManagerCluster, WazuhManagerRole,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};

pub struct WazuhManagerContext {
    pub client: kube::Client,
}

impl WazuhManagerContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhManager
pub async fn reconcile(manager: Arc<WazuhManager>, ctx: Arc<WazuhManagerContext>) -> Result<Action> {
    let ns = manager
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let manager_api: Api<WazuhManager> = Api::namespaced(ctx.client.clone(), &ns);

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
    manager: Arc<WazuhManager>,
    ctx: Arc<WazuhManagerContext>,
) -> Result<Action> {
    let ns = manager.namespace().unwrap();
    let name = manager.name_any();
    let workload_name = manager
        .spec
        .workload
        .as_ref()
        .and_then(|w| w.name.clone())
        .unwrap_or_else(|| name.clone());

    info!("Reconciling WazuhManager: {}/{}", ns, name);

    let client = ctx.client.clone();

    // 1. Resolve cluster reference
    let cluster = resolve_cluster(&manager, client.clone()).await?;
    let cluster_name = cluster.name_any();
    let cluster_ns = cluster.namespace().unwrap();

    // 2. Resolve indexer reference from cluster
    let indexer = resolve_indexer(&cluster, client.clone()).await?;

    // 3. Build master nodes list
    let master_nodes = collect_master_nodes(client.clone(), &cluster_name, &cluster_ns).await?;

    // 4. Aggregate configs/rules/decoders/listeners for this manager
    let selector_labels = build_selector_labels(&manager, &cluster_name, &workload_name);
    let extra_config =
        ConfigAggregator::aggregate_configs(client.clone(), &ns, Some(&selector_labels)).await?;
    let mut rules =
        ConfigAggregator::aggregate_rules(client.clone(), &ns, Some(&selector_labels)).await?;
    let mut decoders =
        ConfigAggregator::aggregate_decoders(client.clone(), &ns, Some(&selector_labels)).await?;
    let listener_ports =
        ConfigAggregator::collect_listener_ports(client.clone(), &ns, Some(&selector_labels))
            .await?;

    if rules.is_empty() {
        rules.insert(
            "local_rules.xml".to_string(),
            "<group name=\"local, \">\n</group>".to_string(),
        );
    }
    if decoders.is_empty() {
        decoders.insert(
            "local_decoder.xml".to_string(),
            "<decoder name=\"local_decoder\">\n</decoder>".to_string(),
        );
    }

    let ossec_conf = build_ossec_conf(&manager, &indexer, &master_nodes, &extra_config)?;
    let combined_content = format!("{}{:?}{:?}", ossec_conf, rules, decoders);
    let config_hash = ConfigAggregator::calculate_hash(&combined_content);

    // 5. Generate ConfigMaps
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &ns);
    let cm = generate_config_map(&manager, &cluster, &ossec_conf)?;
    cm_api
        .patch(
            &format!("{}-config", name),
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&cm),
        )
        .await?;

    let rules_cm = generate_rules_config_map(&manager, rules)?;
    cm_api
        .patch(
            &format!("{}-rules", name),
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&rules_cm),
        )
        .await?;

    let decoders_cm = generate_decoders_config_map(&manager, decoders)?;
    cm_api
        .patch(
            &format!("{}-decoders", name),
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&decoders_cm),
        )
        .await?;

    // Optional nginx configmap
    let nginx_enabled = manager
        .spec
        .nginx
        .as_ref()
        .map(|n| n.enabled)
        .unwrap_or(true);
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

    // 6. Create StatefulSet
    let tls_secret_name = format!("{}-tls", cluster_name);
    let secret_api: Api<k8s_openapi::api::core::v1::Secret> = Api::namespaced(client.clone(), &cluster_ns);
    let tls_secret_rv = secret_api
        .get(&tls_secret_name)
        .await
        .ok()
        .and_then(|s| s.metadata.resource_version)
        .unwrap_or_else(|| "missing".to_string());

    let sts_api: Api<StatefulSet> = Api::namespaced(client.clone(), &ns);
    let sts = generate_statefulset(
        &manager,
        &workload_name,
        &cluster,
        &indexer,
        &tls_secret_rv,
        &config_hash,
        &listener_ports,
    )?;
    sts_api
        .patch(
            &workload_name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&sts),
        )
        .await?;

    info!("Successfully reconciled WazuhManager {}", name);

    Ok(Action::requeue(Duration::from_secs(60)))
}

async fn cleanup_manager(
    manager: Arc<WazuhManager>,
    _ctx: Arc<WazuhManagerContext>,
) -> Result<Action> {
    let ns = manager.namespace().unwrap();
    let name = manager.name_any();
    info!("Cleaning up WazuhManager: {}/{}", ns, name);

    Ok(Action::await_change())
}

async fn resolve_cluster(
    manager: &WazuhManager,
    client: kube::Client,
) -> Result<WazuhManagerCluster> {
    let ns = manager
        .spec
        .cluster_ref
        .namespace
        .clone()
        .unwrap_or_else(|| manager.namespace().unwrap());
    let name = &manager.spec.cluster_ref.name;

    let cluster_api: Api<WazuhManagerCluster> = Api::namespaced(client, &ns);
    let cluster = cluster_api.get(name).await?;

    Ok(cluster)
}

async fn resolve_indexer(
    cluster: &WazuhManagerCluster,
    client: kube::Client,
) -> Result<WazuhIndexerCluster> {
    let ns = cluster
        .spec
        .indexer_cluster
        .namespace
        .clone()
        .unwrap_or_else(|| cluster.namespace().unwrap());
    let name = &cluster.spec.indexer_cluster.name;

    let indexer_api: Api<WazuhIndexerCluster> = Api::namespaced(client, &ns);
    let indexer = indexer_api.get(name).await?;

    Ok(indexer)
}

async fn collect_master_nodes(
    client: kube::Client,
    cluster_name: &str,
    cluster_ns: &str,
) -> Result<Vec<String>> {
    let manager_api: Api<WazuhManager> = Api::namespaced(client, cluster_ns);
    let managers = manager_api.list(&kube::api::ListParams::default()).await?;
    let mut nodes = Vec::new();

    for manager in managers {
        let ref_ns = manager
            .spec
            .cluster_ref
            .namespace
            .clone()
            .unwrap_or_else(|| cluster_ns.to_string());
        if manager.spec.cluster_ref.name != cluster_name || ref_ns != cluster_ns {
            continue;
        }
        if !matches!(manager.spec.role, WazuhManagerRole::Master) {
            continue;
        }
        let workload_name = manager
            .spec
            .workload
            .as_ref()
            .and_then(|w| w.name.clone())
            .unwrap_or_else(|| manager.name_any());
        for i in 0..manager.spec.replicas {
            nodes.push(format!(
                "{}-{}.{}-headless.{}.svc.cluster.local",
                workload_name,
                i,
                cluster_name,
                cluster_ns
            ));
        }
    }

    Ok(nodes)
}

fn build_selector_labels(
    manager: &WazuhManager,
    cluster_name: &str,
    workload_name: &str,
) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-manager".to_string());
    labels.insert("cluster".to_string(), cluster_name.to_string());
    labels.insert("manager".to_string(), manager.name_any());
    labels.insert(
        "role".to_string(),
        match manager.spec.role {
            WazuhManagerRole::Master => "master".to_string(),
            WazuhManagerRole::Worker => "worker".to_string(),
        },
    );
    labels.insert("workload".to_string(), workload_name.to_string());
    if let Some(ns) = manager.namespace() {
        labels.insert("namespace".to_string(), ns);
    }
    if let Some(extra) = &manager.metadata.labels {
        for (k, v) in extra {
            labels.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    labels
}

fn merge_ossec_conf(base: String, extra: &str) -> String {
    let extra = extra.trim();
    if extra.is_empty() {
        return base;
    }
    if let Some(idx) = base.rfind("</ossec_config>") {
        let (head, tail) = base.split_at(idx);
        format!("{}\n{}\n{}", head, extra, tail)
    } else {
        format!("{}\n{}", base, extra)
    }
}

fn build_ossec_conf(
    manager: &WazuhManager,
    indexer: &WazuhIndexerCluster,
    master_nodes: &[String],
    extra_config: &str,
) -> Result<String> {
    let node_type = match manager.spec.role {
        WazuhManagerRole::Master => "master",
        WazuhManagerRole::Worker => "worker",
    };
    let nodes_block = if master_nodes.is_empty() {
        "".to_string()
    } else {
        master_nodes
            .iter()
            .map(|node| format!("    <node>{}</node>", node))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let indexer_name = indexer.name_any();
    let indexer_ns = indexer.namespace().unwrap_or_default();
    let base = format!(
        r#"<ossec_config>
  <cluster>
    <name>wazuh</name>
    <node_name>NODE_NAME</node_name>
    <node_type>{}</node_type>
    <key>CLUSTER_KEY</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
{}
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
        node_type, nodes_block, indexer_name, indexer_ns
    );

    Ok(merge_ossec_conf(base, extra_config))
}

fn generate_config_map(
    manager: &WazuhManager,
    cluster: &WazuhManagerCluster,
    ossec_conf: &str,
) -> Result<ConfigMap> {
    let name = manager.name_any();
    let cluster_name = cluster.name_any();

    let mut data = BTreeMap::new();
    data.insert("ossec.conf".to_string(), ossec_conf.to_string());

    let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);

    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-manager".to_string());
    labels.insert("cluster".to_string(), cluster_name);
    labels.insert("manager".to_string(), name.clone());
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "wazuh-operator".to_string(),
    );
    if let Some(extra) = &manager.metadata.labels {
        for (k, v) in extra {
            labels.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

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

fn generate_rules_config_map(
    manager: &WazuhManager,
    rules: BTreeMap<String, String>,
) -> Result<ConfigMap> {
    let name = manager.name_any();

    let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);

    Ok(ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(format!("{}-rules", name)),
            owner_references: owner_ref,
            ..Default::default()
        },
        data: Some(rules),
        ..Default::default()
    })
}

fn generate_decoders_config_map(
    manager: &WazuhManager,
    decoders: BTreeMap<String, String>,
) -> Result<ConfigMap> {
    let name = manager.name_any();

    let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);

    Ok(ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(format!("{}-decoders", name)),
            owner_references: owner_ref,
            ..Default::default()
        },
        data: Some(decoders),
        ..Default::default()
    })
}

fn generate_nginx_config_map(manager: &WazuhManager) -> Result<ConfigMap> {
    let name = manager.name_any();
    let custom = manager
        .spec
        .nginx
        .as_ref()
        .and_then(|n| n.custom_config.clone());
    let crl_url = manager
        .spec
        .nginx
        .as_ref()
        .and_then(|n| n.crl_url.clone())
        .unwrap_or_default();

    let default_conf = r#"
events {
    worker_connections 1024;
}
http {
    server {
        listen 8443 ssl;
        server_name _;
        ssl_certificate /etc/nginx/certs/tls.crt;
        ssl_certificate_key /etc/nginx/certs/tls.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_crl /etc/nginx/crl/crl.pem;

        location / {
            proxy_pass http://127.0.0.1:55000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /healthz {
            access_log off;
            return 200 \"OK\";
        }
    }
}
"#;

    let mut data = BTreeMap::new();
    data.insert(
        "nginx.conf".to_string(),
        custom.unwrap_or_else(|| default_conf.to_string()),
    );
    data.insert("crl_url".to_string(), crl_url);

    let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);

    Ok(ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(format!("{}-nginx-config", name)),
            owner_references: owner_ref,
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    })
}

fn generate_statefulset(
    manager: &WazuhManager,
    workload_name: &str,
    cluster: &WazuhManagerCluster,
    indexer: &WazuhIndexerCluster,
    tls_secret_rv: &str,
    config_hash: &str,
    listener_ports: &[ListenerPort],
) -> Result<StatefulSet> {
    let name = manager.name_any();
    let cluster_name = cluster.name_any();
    let role_label = match manager.spec.role {
        WazuhManagerRole::Master => "master",
        WazuhManagerRole::Worker => "worker",
    };

    let nginx_enabled = manager
        .spec
        .nginx
        .as_ref()
        .map(|n| n.enabled)
        .unwrap_or(true);

    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-manager".to_string());
    labels.insert("cluster".to_string(), cluster_name.clone());
    labels.insert("manager".to_string(), name.clone());
    labels.insert("role".to_string(), role_label.to_string());
    labels.insert("workload".to_string(), workload_name.to_string());
    if let Some(ns) = manager.namespace() {
        labels.insert("namespace".to_string(), ns);
    }
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "wazuh-operator".to_string(),
    );
    if let Some(extra) = &manager.metadata.labels {
        for (k, v) in extra {
            labels.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    let mut annotations = BTreeMap::new();
    annotations.insert(
        "app.kubernetes.io/created-by".to_string(),
        "wazuh-operator".to_string(),
    );

    let owner_ref = manager.controller_owner_ref(&()).map(|o| vec![o]);

    let mut manager_ports = Vec::new();
    for entry in listener_ports {
        let proto = entry.protocol.to_lowercase();
        let name = format!("lst-{}-{}", entry.port, proto);
        manager_ports.push(ContainerPort {
            container_port: entry.port,
            name: Some(name.chars().take(15).collect()),
            protocol: Some(proto.to_uppercase()),
            ..Default::default()
        });
    }

    let mut containers = vec![Container {
        name: "manager".to_string(),
        image: Some(format!("wazuh/wazuh-manager:{}", cluster.spec.version)),
        ports: if manager_ports.is_empty() {
            None
        } else {
            Some(manager_ports)
        },
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
            VolumeMount {
                name: "tls".to_string(),
                mount_path: "/var/ossec/etc/certs".to_string(),
                ..Default::default()
            },
        ]),
        ..Default::default()
    }];

    if nginx_enabled {
        let nginx_image = manager
            .spec
            .nginx
            .as_ref()
            .and_then(|n| n.image.as_ref())
            .map(|img| format!("{}:{}", img.repository, img.tag))
            .unwrap_or_else(|| "nginx:stable-alpine".to_string());
        let nginx_pull_policy = manager
            .spec
            .nginx
            .as_ref()
            .and_then(|n| n.image.as_ref())
            .and_then(|img| img.pull_policy.clone());

        containers.push(Container {
            name: "nginx".to_string(),
            image: Some(nginx_image),
            image_pull_policy: nginx_pull_policy,
            ports: Some(vec![k8s_openapi::api::core::v1::ContainerPort {
                container_port: 8443,
                name: Some("https".to_string()),
                ..Default::default()
            }]),
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
                    ..Default::default()
                },
                VolumeMount {
                    name: "nginx-crl".to_string(),
                    mount_path: "/etc/nginx/crl".to_string(),
                    ..Default::default()
                },
                VolumeMount {
                    name: "nginx-crl-config".to_string(),
                    mount_path: "/etc/nginx/crl-config".to_string(),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        });
    }

    let mut volumes = vec![
        Volume {
            name: "config".to_string(),
            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                name: format!("{}-config", name),
                ..Default::default()
            }),
            ..Default::default()
        },
        Volume {
            name: "rules".to_string(),
            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                name: format!("{}-rules", name),
                ..Default::default()
            }),
            ..Default::default()
        },
        Volume {
            name: "decoders".to_string(),
            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                name: format!("{}-decoders", name),
                ..Default::default()
            }),
            ..Default::default()
        },
        Volume {
            name: "tls".to_string(),
            secret: Some(k8s_openapi::api::core::v1::SecretVolumeSource {
                secret_name: Some(format!("{}-tls", cluster_name)),
                ..Default::default()
            }),
            ..Default::default()
        },
    ];

    if nginx_enabled {
        volumes.push(Volume {
            name: "nginx-config".to_string(),
            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                name: format!("{}-nginx-config", name),
                ..Default::default()
            }),
            ..Default::default()
        });
        volumes.push(Volume {
            name: "nginx-crl-config".to_string(),
            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                name: format!("{}-nginx-config", name),
                ..Default::default()
            }),
            ..Default::default()
        });
        volumes.push(Volume {
            name: "nginx-crl".to_string(),
            empty_dir: Some(k8s_openapi::api::core::v1::EmptyDirVolumeSource::default()),
            ..Default::default()
        });
    }

    Ok(StatefulSet {
        metadata: kube::api::ObjectMeta {
            name: Some(workload_name.to_string()),
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
            service_name: Some(format!("{}-headless", cluster_name)),
            template: {
                let mut tpl = PodTemplateSpec {
                    metadata: Some(kube::api::ObjectMeta {
                        labels: Some(labels),
                        annotations: Some({
                            let mut ann = annotations;
                            ann.insert(
                                "wazuh.adorsys.team/tls-secret-rv".to_string(),
                                tls_secret_rv.to_string(),
                            );
                            ann.insert(
                                "wazuh.adorsys.team/config-hash".to_string(),
                                config_hash.to_string(),
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
                        init_containers: if nginx_enabled {
                            Some(vec![Container {
                                name: "nginx-crl-fetch".to_string(),
                                image: Some("curlimages/curl:8.5.0".to_string()),
                                command: Some(vec![
                                    "/bin/sh".to_string(),
                                    "-c".to_string(),
                                    "CRL_URL=$(cat /etc/nginx/crl-config/crl_url 2>/dev/null); if [ -n \"$CRL_URL\" ]; then curl -fsSL \"$CRL_URL\" -o /etc/nginx/crl/crl.pem; fi".to_string(),
                                ]),
                                volume_mounts: Some(vec![
                                    VolumeMount {
                                        name: "nginx-crl".to_string(),
                                        mount_path: "/etc/nginx/crl".to_string(),
                                        ..Default::default()
                                    },
                                    VolumeMount {
                                        name: "nginx-crl-config".to_string(),
                                        mount_path: "/etc/nginx/crl-config".to_string(),
                                        ..Default::default()
                                    },
                                ]),
                                ..Default::default()
                            }])
                        } else {
                            None
                        },
                        containers,
                        volumes: Some(volumes),
                        ..Default::default()
                    }),
                };
                if let Some(patch) = &manager.spec.pod_template {
                    let _ = apply_pod_template_patch(&mut tpl, patch);
                }
                tpl
            },
            volume_claim_templates: {
                let defaults = Vec::new();
                let mut overrides = Vec::new();
                if let Some(templates) = manager.spec.volume_claim_templates.as_ref() {
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
    })
}

/// Error policy for WazuhManager reconciliation
pub fn error_policy(_manager: Arc<WazuhManager>, error: &Error, _ctx: Arc<WazuhManagerContext>) -> Action {
    error!("Reconciliation failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}
