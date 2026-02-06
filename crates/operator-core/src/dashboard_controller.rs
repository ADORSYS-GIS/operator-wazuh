//! WazuhDashboard controller implementation

use crate::ca::{resolve_default_wazuh_ca, resolve_wazuh_ca, ResolvedCa};
use crate::cert_manager::Certificate;
use crate::error::{Error, Result};
use crate::pod_template::apply_pod_template_patch;
use crate::tls::TlsManager;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, EnvVar, EnvVarSource, PodSpec, PodTemplateSpec, Secret,
    SecretKeySelector, Service, ServicePort, ServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::api::{Api, Patch, PatchParams, Resource};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{finalizer, Event as FinalizerEvent};
use kube::ResourceExt;
use operator_crds::{WazuhDashboard, WazuhIndexerCluster, WazuhManagerCluster};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};

pub struct DashboardContext {
    pub client: kube::Client,
}

impl DashboardContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhDashboard
pub async fn reconcile(
    dashboard: Arc<WazuhDashboard>,
    ctx: Arc<DashboardContext>,
) -> Result<Action> {
    let ns = dashboard
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let dashboard_api: Api<WazuhDashboard> = Api::namespaced(ctx.client.clone(), &ns);

    finalizer(
        &dashboard_api,
        "wazuh.adorsys.team/finalizer",
        dashboard,
        |event| {
            let ctx = ctx.clone();
            async move {
                match event {
                    FinalizerEvent::Apply(dashboard) => reconcile_dashboard(dashboard, ctx).await,
                    FinalizerEvent::Cleanup(dashboard) => cleanup_dashboard(dashboard, ctx).await,
                }
            }
        },
    )
    .await
    .map_err(|e| Error::ReconciliationError(e.to_string()))
}

async fn reconcile_dashboard(
    dashboard: Arc<WazuhDashboard>,
    ctx: Arc<DashboardContext>,
) -> Result<Action> {
    let ns = dashboard.namespace().unwrap();
    let name = dashboard.name_any();
    let workload_name = dashboard
        .spec
        .workload
        .as_ref()
        .and_then(|w| w.name.clone())
        .unwrap_or_else(|| name.clone());

    info!("Reconciling WazuhDashboard: {}/{}", ns, name);

    let client = ctx.client.clone();
    let manager_api_secret_name = resolve_dashboard_manager_api_secret_name(&dashboard)?;
    let indexer_auth_secret_name = resolve_dashboard_indexer_auth_secret_name(&dashboard)?;

    // 1. Resolve indexer reference
    let indexer = resolve_dashboard_indexer(&dashboard, client.clone()).await?;
    info!("Resolved indexer for dashboard: {}", indexer.name_any());

    // 2. Resolve manager reference (optional)
    let manager = if dashboard.spec.manager_cluster.is_some() {
        let manager = resolve_dashboard_manager(&dashboard, client.clone()).await?;
        info!("Resolved manager for dashboard: {}", manager.name_any());
        Some(manager)
    } else {
        None
    };

    let opensearch_hosts = resolve_dashboard_opensearch_hosts(&dashboard, &indexer);
    let wazuh_api_url = resolve_dashboard_wazuh_api_url(&dashboard, manager.as_ref());

    // 3. Generate opensearch_dashboards.yml ConfigMap
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &ns);
    let cm = generate_dashboard_config_map(&dashboard, wazuh_api_url.as_deref())?;

    cm_api
        .patch(
            &format!("{}-config", name),
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&cm),
        )
        .await?;

    info!("Successfully reconciled ConfigMap for dashboard {}", name);

    // 5. Ensure TLS (shared WazuhCA if configured)
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), &ns);
    let tls_secret_name = format!("{}-tls", name);
    let alt_names = vec![
        name.clone(),
        format!("{}.{}", name, ns),
        format!("{}.{}.svc.cluster.local", name, ns),
    ];
    let server_keys = ["ca.crt", "tls.crt", "tls.key"];
    let ca_ref = dashboard.spec.tls.as_ref().and_then(|t| t.ca_ref.as_ref());
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
                let server_secret = secret_api.get(&tls_secret_name).await.ok();
                let server_ready = server_secret
                    .as_ref()
                    .map_or(false, |s| secret_has_keys(s, &server_keys));
                let server_ca_matches = server_secret
                    .as_ref()
                    .and_then(|s| secret_value(s, "ca.crt"))
                    .map_or(false, |crt| crt == ca_cert);
                if !server_ready || !server_ca_matches {
                    let (server_cert, server_key) = TlsManager::generate_server_cert(
                        &ca_cert,
                        &ca_key,
                        &format!("{}.{}.svc.cluster.local", name, ns),
                        alt_names.clone(),
                    )?;

                    let owner_ref = dashboard.controller_owner_ref(&()).map(|o| vec![o]);
                    let mut tls_data = BTreeMap::new();
                    tls_data.insert("ca.crt".to_string(), ca_cert);
                    tls_data.insert("tls.crt".to_string(), server_cert);
                    tls_data.insert("tls.key".to_string(), server_key);

                    let mut labels = BTreeMap::new();
                    labels.insert("app".to_string(), "wazuh-dashboard".to_string());
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

                    let tls_secret = Secret {
                        metadata: kube::api::ObjectMeta {
                            name: Some(tls_secret_name.clone()),
                            labels: Some(labels),
                            annotations: Some(annotations),
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
                let owner_ref = dashboard.controller_owner_ref(&()).map(|o| vec![o]);

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
                        usages: vec!["server auth".to_string()],
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

            let owner_ref = dashboard.controller_owner_ref(&()).map(|o| vec![o]);
            let mut tls_data = BTreeMap::new();
            tls_data.insert("ca.crt".to_string(), ca_cert);
            tls_data.insert("tls.crt".to_string(), server_cert);
            tls_data.insert("tls.key".to_string(), server_key);

            let mut labels = BTreeMap::new();
            labels.insert("app".to_string(), "wazuh-dashboard".to_string());
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

            let tls_secret = Secret {
                metadata: kube::api::ObjectMeta {
                    name: Some(tls_secret_name.clone()),
                    labels: Some(labels),
                    annotations: Some(annotations),
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

    let tls_secret_rv = secret_api
        .get(&tls_secret_name)
        .await
        .ok()
        .and_then(|s| s.metadata.resource_version)
        .unwrap_or_else(|| "missing".to_string());

    // 6. Create Deployment
    let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), &ns);
    let deploy = generate_dashboard_deployment(
        &dashboard,
        &indexer_auth_secret_name,
        &opensearch_hosts,
        wazuh_api_url.as_deref(),
        manager_api_secret_name.as_deref(),
        &tls_secret_rv,
        &workload_name,
    )?;

    deploy_api
        .patch(
            &workload_name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&deploy),
        )
        .await?;

    info!("Successfully reconciled Deployment for dashboard {}", name);

    // 7. Create Service
    let svc_api: Api<Service> = Api::namespaced(client.clone(), &ns);
    let svc = generate_dashboard_service(&dashboard)?;

    svc_api
        .patch(
            &name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&svc),
        )
        .await?;

    info!("Successfully reconciled Service for dashboard {}", name);

    // 8. Create Ingress (optional)
    // For now, we skip ingress implementation as it's optional and requires more complex configuration
    info!(
        "Skipping optional Ingress reconciliation for dashboard {}",
        name
    );

    // 9. Update status
    update_dashboard_status(&dashboard, client).await?;

    Ok(Action::requeue(Duration::from_secs(60)))
}

async fn cleanup_dashboard(
    dashboard: Arc<WazuhDashboard>,
    _ctx: Arc<DashboardContext>,
) -> Result<Action> {
    let ns = dashboard.namespace().unwrap();
    let name = dashboard.name_any();
    info!("Cleaning up WazuhDashboard: {}/{}", ns, name);

    Ok(Action::await_change())
}

async fn update_dashboard_status(dashboard: &WazuhDashboard, client: kube::Client) -> Result<()> {
    let ns = dashboard.namespace().unwrap();
    let name = dashboard.name_any();
    let workload_name = dashboard
        .spec
        .workload
        .as_ref()
        .and_then(|w| w.name.clone())
        .unwrap_or_else(|| name.clone());
    let dashboard_api: Api<WazuhDashboard> = Api::namespaced(client.clone(), &ns);
    let deploy_api: Api<Deployment> = Api::namespaced(client, &ns);

    let deploy = deploy_api.get(&workload_name).await?;
    let ready_replicas = deploy
        .status
        .as_ref()
        .and_then(|s| s.ready_replicas)
        .unwrap_or(0);
    let phase = if ready_replicas == dashboard.spec.replicas {
        "Ready"
    } else {
        "Progressing"
    };

    let mut status =
        dashboard
            .status
            .clone()
            .unwrap_or(operator_crds::wazuh_dashboard::WazuhDashboardStatus {
                phase: phase.to_string(),
                ready_replicas,
                url: Some(format!("{}.{}.svc.cluster.local", name, ns)),
                indexer_connected: true,       // Placeholder
                manager_connected: Some(true), // Placeholder
            });

    status.phase = phase.to_string();
    status.ready_replicas = ready_replicas;

    let patch = serde_json::json!({
        "status": status
    });

    dashboard_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;

    Ok(())
}

fn generate_dashboard_service(dashboard: &WazuhDashboard) -> Result<Service> {
    let name = dashboard.name_any();
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-dashboard".to_string());
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

    let owner_ref = dashboard.controller_owner_ref(&()).map(|o| vec![o]);

    let nginx_enabled = dashboard
        .spec
        .nginx
        .as_ref()
        .map(|n| n.enabled)
        .unwrap_or(true);
    let (port, target_port, port_name) = if nginx_enabled {
        (443, 8443, "https")
    } else {
        (5601, 5601, "http")
    };

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
            ports: Some(vec![ServicePort {
                name: Some(port_name.to_string()),
                port,
                target_port: Some(
                    k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(target_port),
                ),
                ..Default::default()
            }]),
            type_: Some(dashboard.spec.service.service_type.clone()),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn generate_dashboard_deployment(
    dashboard: &WazuhDashboard,
    indexer_auth_secret_name: &str,
    opensearch_hosts: &str,
    wazuh_api_url: Option<&str>,
    manager_api_secret_name: Option<&str>,
    tls_secret_rv: &str,
    workload_name: &str,
) -> Result<Deployment> {
    let name = dashboard.name_any();
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-dashboard".to_string());
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

    let owner_ref = dashboard.controller_owner_ref(&()).map(|o| vec![o]);

    let nginx_enabled = dashboard
        .spec
        .nginx
        .as_ref()
        .map(|n| n.enabled)
        .unwrap_or(true);

    let mut dashboard_env = vec![EnvVar {
        name: "OPENSEARCH_HOSTS".to_string(),
        value: Some(opensearch_hosts.to_string()),
        ..Default::default()
    }];

    if let Some(url) = wazuh_api_url {
        dashboard_env.push(EnvVar {
            name: "WAZUH_API_URL".to_string(),
            value: Some(url.to_string()),
            ..Default::default()
        });
    }

    if let Some(secret_name) = manager_api_secret_name {
        dashboard_env.push(EnvVar {
            name: "API_USERNAME".to_string(),
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    key: "username".to_string(),
                    name: secret_name.to_string(),
                    optional: Some(false),
                }),
                ..Default::default()
            }),
            ..Default::default()
        });
        dashboard_env.push(EnvVar {
            name: "API_PASSWORD".to_string(),
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    key: "password".to_string(),
                    name: secret_name.to_string(),
                    optional: Some(false),
                }),
                ..Default::default()
            }),
            ..Default::default()
        });
    }
    dashboard_env.push(EnvVar {
        name: "DASHBOARD_USERNAME".to_string(),
        value_from: Some(EnvVarSource {
            secret_key_ref: Some(SecretKeySelector {
                key: "username".to_string(),
                name: indexer_auth_secret_name.to_string(),
                optional: Some(false),
            }),
            ..Default::default()
        }),
        ..Default::default()
    });
    dashboard_env.push(EnvVar {
        name: "DASHBOARD_PASSWORD".to_string(),
        value_from: Some(EnvVarSource {
            secret_key_ref: Some(SecretKeySelector {
                key: "password".to_string(),
                name: indexer_auth_secret_name.to_string(),
                optional: Some(false),
            }),
            ..Default::default()
        }),
        ..Default::default()
    });
    if let Some(openid_secret_ref) = dashboard
        .spec
        .auth
        .as_ref()
        .and_then(|auth| auth.openid.as_ref())
        .and_then(|oidc| oidc.client_secret_ref.as_ref())
    {
        dashboard_env.push(EnvVar {
            name: "OPENSEARCH_OPENID_CLIENT_SECRET".to_string(),
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    key: openid_secret_ref.key.clone(),
                    name: openid_secret_ref.name.clone(),
                    optional: Some(false),
                }),
                ..Default::default()
            }),
            ..Default::default()
        });
    }

    let mut containers = vec![Container {
        name: "dashboard".to_string(),
        image: Some(format!("wazuh/wazuh-dashboard:{}", dashboard.spec.version)),
        env: Some(dashboard_env),
        volume_mounts: Some(vec![
            VolumeMount {
                name: "config".to_string(),
                mount_path: "/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml"
                    .to_string(),
                sub_path: Some("opensearch_dashboards.yml".to_string()),
                ..Default::default()
            },
            VolumeMount {
                name: "tls".to_string(),
                mount_path: "/usr/share/wazuh-dashboard/certs".to_string(),
                ..Default::default()
            },
        ]),
        ..Default::default()
    }];

    if nginx_enabled {
        let nginx_image = dashboard
            .spec
            .nginx
            .as_ref()
            .and_then(|n| n.image.as_ref())
            .map(|img| format!("{}:{}", img.repository, img.tag))
            .unwrap_or_else(|| "nginx:stable-alpine".to_string());
        let nginx_pull_policy = dashboard
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
                    name: "config".to_string(),
                    mount_path: "/etc/nginx/nginx.conf".to_string(),
                    sub_path: Some("nginx.conf".to_string()),
                    ..Default::default()
                },
                VolumeMount {
                    name: "tls".to_string(),
                    mount_path: "/etc/nginx/certs".to_string(),
                    ..Default::default()
                },
            ]),
            liveness_probe: Some(k8s_openapi::api::core::v1::Probe {
                http_get: Some(k8s_openapi::api::core::v1::HTTPGetAction {
                    path: Some("/healthz".to_string()),
                    port: k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8443),
                    scheme: Some("HTTPS".to_string()),
                    ..Default::default()
                }),
                initial_delay_seconds: Some(10),
                period_seconds: Some(10),
                ..Default::default()
            }),
            readiness_probe: Some(k8s_openapi::api::core::v1::Probe {
                http_get: Some(k8s_openapi::api::core::v1::HTTPGetAction {
                    path: Some("/healthz".to_string()),
                    port: k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8443),
                    scheme: Some("HTTPS".to_string()),
                    ..Default::default()
                }),
                initial_delay_seconds: Some(5),
                period_seconds: Some(5),
                ..Default::default()
            }),
            ..Default::default()
        });
    }

    Ok(Deployment {
        metadata: kube::api::ObjectMeta {
            name: Some(workload_name.to_string()),
            labels: Some(labels.clone()),
            annotations: Some(annotations.clone()),
            owner_references: owner_ref,
            ..Default::default()
        },
        spec: Some(k8s_openapi::api::apps::v1::DeploymentSpec {
            replicas: Some(dashboard.spec.replicas),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
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
                        containers,
                        volumes: Some(vec![
                            Volume {
                                name: "config".to_string(),
                                config_map: Some(
                                    k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                                        name: format!("{}-config", name),
                                        ..Default::default()
                                    },
                                ),
                                ..Default::default()
                            },
                            Volume {
                                name: "tls".to_string(),
                                secret: Some(k8s_openapi::api::core::v1::SecretVolumeSource {
                                    secret_name: Some(format!("{}-tls", name)),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        ]),
                        ..Default::default()
                    }),
                };
                if let Some(patch) = &dashboard.spec.pod_template {
                    let _ = apply_pod_template_patch(&mut tpl, patch);
                }
                tpl
            },
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn resolve_dashboard_manager_api_secret_name(dashboard: &WazuhDashboard) -> Result<Option<String>> {
    let manager_ref = match dashboard.spec.manager_cluster.as_ref() {
        Some(m) => m,
        None => return Ok(None),
    };

    let auth = manager_ref.auth.as_ref().ok_or_else(|| {
        Error::ValidationError(format!(
            "Missing spec.manager_cluster.auth.secretRef.name for dashboard {}/{}",
            dashboard.namespace().unwrap_or_default(),
            dashboard.name_any()
        ))
    })?;
    let secret_name = auth.secret_ref.name.trim();
    if secret_name.is_empty() {
        return Err(Error::ValidationError(format!(
            "Empty spec.manager_cluster.auth.secretRef.name for dashboard {}/{}",
            dashboard.namespace().unwrap_or_default(),
            dashboard.name_any()
        )));
    }
    Ok(Some(secret_name.to_string()))
}

fn resolve_dashboard_indexer_auth_secret_name(dashboard: &WazuhDashboard) -> Result<String> {
    if let Some(auth) = dashboard.spec.indexer_cluster.auth.as_ref() {
        let secret_name = auth.secret_ref.name.trim();
        if secret_name.is_empty() {
            return Err(Error::ValidationError(format!(
                "Empty spec.indexer_cluster.auth.secretRef.name for dashboard {}/{}",
                dashboard.namespace().unwrap_or_default(),
                dashboard.name_any()
            )));
        }
        return Ok(secret_name.to_string());
    }

    // Backward compatibility fallback to legacy auth.auth_secret
    if let Some(auth) = dashboard.spec.auth.as_ref() {
        if let Some(secret_name) = auth.auth_secret.as_ref() {
            let secret_name = secret_name.trim();
            if !secret_name.is_empty() {
                return Ok(secret_name.to_string());
            }
        }
    }

    Err(Error::ValidationError(format!(
        "Missing indexer dashboard credentials for dashboard {}/{}: set spec.indexer_cluster.auth.secretRef.name",
        dashboard.namespace().unwrap_or_default(),
        dashboard.name_any()
    )))
}

async fn resolve_dashboard_manager(
    dashboard: &WazuhDashboard,
    client: kube::Client,
) -> Result<WazuhManagerCluster> {
    let manager_ref = dashboard
        .spec
        .manager_cluster
        .as_ref()
        .ok_or_else(|| Error::ValidationError("Manager reference is required".to_string()))?;
    let ns = manager_ref
        .namespace
        .clone()
        .unwrap_or_else(|| dashboard.namespace().unwrap());
    let name = &manager_ref.name;

    let manager_api: Api<WazuhManagerCluster> = Api::namespaced(client, &ns);
    let manager = manager_api.get(name).await?;

    Ok(manager)
}

async fn resolve_dashboard_indexer(
    dashboard: &WazuhDashboard,
    client: kube::Client,
) -> Result<WazuhIndexerCluster> {
    let ns = dashboard
        .spec
        .indexer_cluster
        .namespace
        .clone()
        .unwrap_or_else(|| dashboard.namespace().unwrap());
    let name = &dashboard.spec.indexer_cluster.name;

    let indexer_api: Api<WazuhIndexerCluster> = Api::namespaced(client, &ns);
    let indexer = indexer_api.get(name).await?;

    Ok(indexer)
}

fn generate_dashboard_config_map(
    dashboard: &WazuhDashboard,
    wazuh_api_url: Option<&str>,
) -> Result<ConfigMap> {
    let name = dashboard.name_any();
    let config_yml = build_opensearch_dashboards_config(dashboard)?;

    let custom_nginx = dashboard
        .spec
        .nginx
        .as_ref()
        .and_then(|n| n.custom_config.clone());

    let nginx_conf = r#"
events {
    worker_connections 1024;
}
http {
    upstream dashboard {
        server 127.0.0.1:5601;
    }
    server {
        listen 8443 ssl;
        server_name _;
        ssl_certificate /etc/nginx/certs/tls.crt;
        ssl_certificate_key /etc/nginx/certs/tls.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location / {
            proxy_pass https://dashboard;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_ssl_verify off;
            proxy_ssl_server_name on;
        }

        location /healthz {
            access_log off;
            return 200 "OK";
        }
    }
}
"#;

    let mut data = BTreeMap::new();
    data.insert("opensearch_dashboards.yml".to_string(), config_yml);
    if let Some(url) = wazuh_api_url {
        data.insert(
            "wazuh.yml".to_string(),
            format!(
                "hosts:\n  - url: \"{}\"\n",
                url
            ),
        );
    }
    data.insert(
        "nginx.conf".to_string(),
        custom_nginx.unwrap_or_else(|| nginx_conf.to_string()),
    );

    let owner_ref = dashboard.controller_owner_ref(&()).map(|o| vec![o]);

    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-dashboard".to_string());
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

fn build_opensearch_dashboards_config(dashboard: &WazuhDashboard) -> Result<String> {
    let mut config = r#"server.host: "0.0.0.0"
server.port: 5601
opensearch.hosts: ["${OPENSEARCH_HOSTS}"]
opensearch.ssl.verificationMode: none
opensearch.username: "${DASHBOARD_USERNAME}"
opensearch.password: "${DASHBOARD_PASSWORD}"
server.ssl.enabled: true
server.ssl.key: "/usr/share/wazuh-dashboard/certs/tls.key"
server.ssl.certificate: "/usr/share/wazuh-dashboard/certs/tls.crt"
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/ca.crt"]
"#
    .to_string();

    if let Some(custom) = dashboard.spec.custom_opensearch_dashboard.as_ref() {
        let custom = custom.trim();
        if !custom.is_empty() {
            config.push('\n');
            config.push_str(custom);
            config.push('\n');
        }
    }

    Ok(config)
}

fn resolve_dashboard_opensearch_hosts(
    dashboard: &WazuhDashboard,
    indexer: &WazuhIndexerCluster,
) -> String {
    if let Some(hosts) = dashboard
        .spec
        .config
        .as_ref()
        .and_then(|cfg| cfg.opensearch_hosts.as_ref())
    {
        let hosts = hosts.trim();
        if !hosts.is_empty() {
            return hosts.to_string();
        }
    }

    format!(
        "https://{}.{}.svc.cluster.local:9200",
        indexer.name_any(),
        indexer.namespace().unwrap_or_default()
    )
}

fn resolve_dashboard_wazuh_api_url(
    dashboard: &WazuhDashboard,
    manager: Option<&WazuhManagerCluster>,
) -> Option<String> {
    if let Some(url) = dashboard
        .spec
        .config
        .as_ref()
        .and_then(|cfg| cfg.wazuh_api_url.as_ref())
    {
        let url = url.trim();
        if !url.is_empty() {
            return Some(url.to_string());
        }
    }

    let manager = manager?;
    let manager_ns = manager.namespace().unwrap_or_default();
    let manager_name = manager.name_any();

    Some(format!(
        "https://{}.{}.svc.cluster.local",
        manager_name, manager_ns
    ))
}

/// Error policy for WazuhDashboard reconciliation
pub fn error_policy(
    _dashboard: Arc<WazuhDashboard>,
    error: &Error,
    _ctx: Arc<DashboardContext>,
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

fn secret_value(secret: &Secret, key: &str) -> Option<String> {
    if let Some(data) = &secret.data {
        if let Some(value) = data.get(key) {
            return String::from_utf8(value.0.clone()).ok();
        }
    }
    if let Some(data) = &secret.string_data {
        if let Some(value) = data.get(key) {
            return Some(value.clone());
        }
    }
    None
}
