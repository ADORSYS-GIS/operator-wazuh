//! WazuhDashboard controller implementation

use crate::error::{Error, Result};
use crate::tls::TlsManager;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, PodSpec, PodTemplateSpec, Secret, Service, ServicePort, ServiceSpec,
    Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams, Resource};
use kube::runtime::controller::Action;
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
    let name = dashboard.name_any();

    info!("Reconciling WazuhDashboard: {}/{}", ns, name);

    let client = ctx.client.clone();

    // 1. Resolve indexer reference
    let indexer = resolve_dashboard_indexer(&dashboard, client.clone()).await?;
    info!("Resolved indexer for dashboard: {}", indexer.name_any());

    // 2. Generate opensearch_dashboards.yml ConfigMap
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &ns);
    let cm = generate_dashboard_config_map(&dashboard, &indexer)?;

    cm_api
        .patch(
            &format!("{}-config", name),
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&cm),
        )
        .await?;

    info!("Successfully reconciled ConfigMap for dashboard {}", name);

    // 3. Implement Wazuh API Plugin Configuration
    if let Some(manager_ref) = &dashboard.spec.manager_cluster {
        let manager = resolve_dashboard_manager(&dashboard, client.clone()).await?;
        info!("Resolved manager for dashboard: {}", manager.name_any());

        // Update ConfigMap with wazuh.yml
        let mut data = cm.data.clone().unwrap_or_default();
        let wazuh_yml = format!(
            r#"hosts:
  - url: https://{}.{}.svc.cluster.local:55000
    user: admin
    password: admin
"#,
            manager.name_any(),
            manager.namespace().unwrap()
        );
        data.insert("wazuh.yml".to_string(), wazuh_yml);

        let mut updated_cm = cm.clone();
        updated_cm.data = Some(data);

        cm_api
            .patch(
                &format!("{}-config", name),
                &PatchParams::apply("wazuh-operator"),
                &Patch::Apply(&updated_cm),
            )
            .await?;

        info!(
            "Successfully updated ConfigMap with wazuh.yml for dashboard {}",
            name
        );
    }

    // 4. Implement TLS and Secret Mounting
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), &ns);
    let (ca_cert, ca_key) = TlsManager::generate_ca()?;
    let (server_cert, server_key) = TlsManager::generate_server_cert(
        &ca_cert,
        &ca_key,
        &format!("{}.{}.svc.cluster.local", name, ns),
        vec![name.clone(), format!("{}.{}", name, ns)],
    )?;

    let mut tls_data = BTreeMap::new();
    tls_data.insert("ca.crt".to_string(), ca_cert);
    tls_data.insert("tls.crt".to_string(), server_cert);
    tls_data.insert("tls.key".to_string(), server_key);

    let owner_ref = dashboard.controller_owner_ref(&()).map(|o| vec![o]);

    let tls_secret = Secret {
        metadata: kube::api::ObjectMeta {
            name: Some(format!("{}-tls", name)),
            owner_references: owner_ref,
            ..Default::default()
        },
        string_data: Some(tls_data),
        ..Default::default()
    };

    secret_api
        .patch(
            &format!("{}-tls", name),
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&tls_secret),
        )
        .await?;

    info!("Successfully reconciled TLS Secret for dashboard {}", name);

    // 5. Create Deployment
    let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), &ns);
    let deploy = generate_dashboard_deployment(&dashboard)?;

    deploy_api
        .patch(
            &name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&deploy),
        )
        .await?;

    info!("Successfully reconciled Deployment for dashboard {}", name);

    // 6. Create Service
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

    // 7. Create Ingress (optional)
    // For now, we skip ingress implementation as it's optional and requires more complex configuration
    info!(
        "Skipping optional Ingress reconciliation for dashboard {}",
        name
    );

    // 8. Update status
    update_dashboard_status(&dashboard, client).await?;

    Ok(Action::requeue(Duration::from_secs(300)))
}

async fn update_dashboard_status(dashboard: &WazuhDashboard, client: kube::Client) -> Result<()> {
    let ns = dashboard.namespace().unwrap();
    let name = dashboard.name_any();
    let dashboard_api: Api<WazuhDashboard> = Api::namespaced(client.clone(), &ns);
    let deploy_api: Api<Deployment> = Api::namespaced(client, &ns);

    let deploy = deploy_api.get(&name).await?;
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

    let owner_ref = dashboard.controller_owner_ref(&()).map(|o| vec![o]);

    Ok(Service {
        metadata: kube::api::ObjectMeta {
            name: Some(name.clone()),
            labels: Some(labels.clone()),
            owner_references: owner_ref,
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(labels),
            ports: Some(vec![ServicePort {
                name: Some("http".to_string()),
                port: 5601,
                ..Default::default()
            }]),
            type_: Some(dashboard.spec.service.service_type.clone()),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn generate_dashboard_deployment(dashboard: &WazuhDashboard) -> Result<Deployment> {
    let name = dashboard.name_any();
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-dashboard".to_string());
    labels.insert("cluster".to_string(), name.clone());

    let owner_ref = dashboard.controller_owner_ref(&()).map(|o| vec![o]);

    Ok(Deployment {
        metadata: kube::api::ObjectMeta {
            name: Some(name.clone()),
            labels: Some(labels.clone()),
            owner_references: owner_ref,
            ..Default::default()
        },
        spec: Some(k8s_openapi::api::apps::v1::DeploymentSpec {
            replicas: Some(dashboard.spec.replicas),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(kube::api::ObjectMeta {
                    labels: Some(labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "dashboard".to_string(),
                        image: Some(format!("wazuh/wazuh-dashboard:{}", dashboard.spec.version)),
                        volume_mounts: Some(vec![
                            VolumeMount {
                                name: "config".to_string(),
                                mount_path:
                                    "/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml"
                                        .to_string(),
                                sub_path: Some("opensearch_dashboards.yml".to_string()),
                                ..Default::default()
                            },
                            VolumeMount {
                                name: "tls".to_string(),
                                mount_path: "/usr/share/wazuh-dashboard/config/certs".to_string(),
                                ..Default::default()
                            },
                        ]),
                        ..Default::default()
                    }],
                    volumes: Some(vec![
                        Volume {
                            name: "config".to_string(),
                            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                                name: format!("{}-config", name),
                                ..Default::default()
                            }),
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
            },
            ..Default::default()
        }),
        ..Default::default()
    })
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
    indexer: &WazuhIndexerCluster,
) -> Result<ConfigMap> {
    let name = dashboard.name_any();
    let indexer_name = indexer.name_any();
    let indexer_ns = indexer.namespace().unwrap();

    let config_yml = format!(
        r#"server.name: wazuh-dashboard
server.host: "0.0.0.0"
opensearch.hosts: ["https://{}.{}.svc.cluster.local:9200"]
opensearch.ssl.verificationMode: none
opensearch.username: "admin"
opensearch.password: "admin"
"#,
        indexer_name, indexer_ns
    );

    let mut data = BTreeMap::new();
    data.insert("opensearch_dashboards.yml".to_string(), config_yml);

    let owner_ref = dashboard.controller_owner_ref(&()).map(|o| vec![o]);

    Ok(ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(format!("{}-config", name)),
            owner_references: owner_ref,
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    })
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
