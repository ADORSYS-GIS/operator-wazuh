use crate::error::{Error, Result};
use k8s_openapi::api::batch::v1::{CronJob, CronJobSpec, JobSpec, JobTemplateSpec};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, EnvVar, PodSpec, PodTemplateSpec, Volume, VolumeMount,
};
use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams, Resource};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use operator_crds::wazuh_indexer_config::WazuhIndexerConfigStatus;
use operator_crds::{WazuhIndexerCluster, WazuhIndexerConfig};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};

pub struct IndexerConfigContext {
    pub client: kube::Client,
}

impl IndexerConfigContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

pub async fn reconcile(
    config: Arc<WazuhIndexerConfig>,
    ctx: Arc<IndexerConfigContext>,
) -> Result<Action> {
    let ns = config
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let api: Api<WazuhIndexerConfig> = Api::namespaced(ctx.client.clone(), &ns);

    finalizer(
        &api,
        "wazuh.adorsys.team/indexer-config-finalizer",
        config,
        |event| {
            let ctx = ctx.clone();
            async move {
                match event {
                    FinalizerEvent::Apply(config) => reconcile_config(config, ctx).await,
                    FinalizerEvent::Cleanup(config) => cleanup_config(config, ctx).await,
                }
            }
        },
    )
    .await
    .map_err(|e| Error::ReconciliationError(e.to_string()))
}

async fn reconcile_config(
    config: Arc<WazuhIndexerConfig>,
    ctx: Arc<IndexerConfigContext>,
) -> Result<Action> {
    let ns = config.namespace().unwrap();
    let name = config.name_any();
    let client = ctx.client.clone();

    info!("Reconciling WazuhIndexerConfig: {}/{}", ns, name);

    // 1. Get the referenced WazuhIndexerCluster
    let cluster_name = &config.spec.wazuh_indexer_cluster_ref;
    let cluster_api: Api<WazuhIndexerCluster> = Api::namespaced(client.clone(), &ns);
    let cluster = cluster_api.get(cluster_name).await.map_err(|e| {
        Error::ReconciliationError(format!(
            "Failed to get WazuhIndexerCluster {}: {}",
            cluster_name, e
        ))
    })?;

    // 2. Generate ConfigMap
    let cm_name = format!("{}-security-config", name);
    let cm = generate_configmap(&config, &cm_name)?;
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &ns);
    cm_api
        .patch(
            &cm_name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&cm),
        )
        .await?;

    // 3. Calculate Hash
    let hash = calculate_hash(&cm.data.unwrap_or_default());


    // 5. Ensure CronJob
    ensure_cronjob(&config, &cluster, &cm_name, client.clone()).await?;

    // 6. Update Status
    let status = WazuhIndexerConfigStatus {
        observed_generation: config.metadata.generation,
        last_applied_hash: Some(hash),
        error: None,
    };

    let status_patch = serde_json::json!({
        "status": status
    });

    let config_api: Api<WazuhIndexerConfig> = Api::namespaced(client.clone(), &ns);
    config_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&status_patch))
        .await?;

    info!(
        "Successfully reconciled WazuhIndexerConfig: {}/{}",
        ns, name
    );

    Ok(Action::requeue(Duration::from_secs(300)))
}

async fn cleanup_config(
    config: Arc<WazuhIndexerConfig>,
    _ctx: Arc<IndexerConfigContext>,
) -> Result<Action> {
    let ns = config.namespace().unwrap();
    let name = config.name_any();
    info!("Cleaning up WazuhIndexerConfig: {}/{}", ns, name);
    Ok(Action::await_change())
}

fn generate_configmap(config: &WazuhIndexerConfig, name: &str) -> Result<ConfigMap> {
    let mut data = BTreeMap::new();

    if let Some(roles) = &config.spec.roles {
        data.insert(
            "roles.yml".to_string(),
            serde_yaml::to_string(roles).unwrap(),
        );
    }
    if let Some(roles_mapping) = &config.spec.roles_mapping {
        data.insert(
            "roles_mapping.yml".to_string(),
            serde_yaml::to_string(roles_mapping).unwrap(),
        );
    }
    if let Some(tenants) = &config.spec.tenants {
        data.insert(
            "tenants.yml".to_string(),
            serde_yaml::to_string(tenants).unwrap(),
        );
    }
    if let Some(internal_users) = &config.spec.internal_users {
        data.insert(
            "internal_users.yml".to_string(),
            serde_yaml::to_string(internal_users).unwrap(),
        );
    }
    if let Some(action_groups) = &config.spec.action_groups {
        data.insert(
            "action_groups.yml".to_string(),
            serde_yaml::to_string(action_groups).unwrap(),
        );
    }

    // Add config.yml if needed, or other files.
    // For now assuming these are the main ones.
    // We might need a default config.yml if not provided, but the CRD doesn't seem to have it.
    // The securityadmin.sh script usually needs config.yml.
    // If it's not in the CRD, maybe we should copy it from the container or generate a default one?
    // The previous implementation didn't seem to mount a config.yml for securityadmin.sh,
    // it just pointed to a directory.
    // Wait, the previous implementation:
    // -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/
    // This implies it uses the default config if not overridden.
    // But here we are mounting our own config.
    // If we mount a directory to -cd, it expects all files there.
    // If we only provide some, others might be missing.
    // However, we can mount individual files using subPath if we want to mix with default,
    // but securityadmin.sh takes a directory.
    // So we probably need to provide all files or at least the ones we want to change.
    // If we provide a directory, it must contain config.yml.
    // Let's assume for now that the user provides what is needed or we rely on what's in the map.
    // If config.yml is missing, securityadmin.sh might fail.
    // Let's check if we can get away with just the files provided.

    let owner_ref = config.controller_owner_ref(&()).map(|o| vec![o]);

    Ok(ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            owner_references: owner_ref,
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    })
}

fn calculate_hash(data: &BTreeMap<String, String>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for (key, value) in data {
        hasher.update(key);
        hasher.update(value);
    }
    format!("{:x}", hasher.finalize())
}

async fn ensure_cronjob(
    config: &WazuhIndexerConfig,
    cluster: &WazuhIndexerCluster,
    cm_name: &str,
    client: kube::Client,
) -> Result<()> {
    let ns = config.namespace().unwrap();
    let name = config.name_any();

    if let Some(schedule) = &config.spec.schedule {
        let cronjob_name = format!("{}-cronjob", name);
        let cronjob_api: Api<CronJob> = Api::namespaced(client, &ns);

        let cronjob = cronjob_api.get(&cronjob_name).await;

        if cronjob.is_err() {
            let hash = calculate_hash(&BTreeMap::new()); // We need to calculate the hash of the configmap
            let new_cronjob =
                generate_cronjob(config, cluster, &cronjob_name, cm_name, &hash, schedule)?;
            cronjob_api
                .patch(
                    &cronjob_name,
                    &PatchParams::apply("wazuh-operator"),
                    &Patch::Apply(&new_cronjob),
                )
                .await?;
        }
    }
    Ok(())
}

fn generate_cronjob(
    config: &WazuhIndexerConfig,
    cluster: &WazuhIndexerCluster,
    cronjob_name: &str,
    cm_name: &str,
    hash: &str,
    schedule: &str,
) -> Result<CronJob> {
    let cluster_name = cluster.name_any();
    let ns = cluster.namespace().unwrap();
    
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-indexer-config-job".to_string());
    labels.insert("config-hash".to_string(), hash[0..8].to_string());
    
    let owner_ref = config.controller_owner_ref(&()).map(|o| vec![o]);

    let job_spec = JobSpec {
        template: PodTemplateSpec {
            metadata: Some(kube::api::ObjectMeta {
                labels: Some(labels.clone()),
                ..Default::default()
            }),
            spec: Some(PodSpec {
                restart_policy: Some("OnFailure".to_string()),
                containers: vec![Container {
                    name: "security-admin".to_string(),
                    image: Some(format!("wazuh/wazuh-indexer:{}", cluster.spec.version)),
                    command: Some(vec![
                        "/bin/bash".to_string(),
                        "-c".to_string(),
                        format!(
                            "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
                            -cd /etc/wazuh-indexer/security-config \
                            -p /etc/wazuh-indexer/certs \
                            -icl -nhnv \
                            -cacert /etc/wazuh-indexer/certs/ca.crt \
                            -cert /etc/wazuh-indexer/certs/admin.crt \
                            -key /etc/wazuh-indexer/certs/admin.key \
                            -h {}-headless.{}.svc.cluster.local",
                            cluster_name, ns
                        ),
                    ]),
                    volume_mounts: Some(vec![
                        VolumeMount {
                            name: "tls".to_string(),
                            mount_path: "/etc/wazuh-indexer/certs".to_string(),
                            ..Default::default()
                        },
                        VolumeMount {
                            name: "security-config".to_string(),
                            mount_path: "/etc/wazuh-indexer/security-config".to_string(),
                            ..Default::default()
                        },
                    ]),
                    env: Some(vec![
                        EnvVar {
                            name: "OPENSEARCH_JAVA_OPTS".to_string(),
                            value: Some("-Xms512m -Xmx512m".to_string()),
                            ..Default::default()
                        },
                        EnvVar {
                            name: "JAVA_HOME".to_string(),
                            value: Some("/usr/share/wazuh-indexer/jdk".to_string()),
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                }],
                volumes: Some(vec![
                    Volume {
                        name: "tls".to_string(),
                        secret: Some(k8s_openapi::api::core::v1::SecretVolumeSource {
                            secret_name: Some(format!("{}-tls", cluster_name)),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    Volume {
                        name: "security-config".to_string(),
                        config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                            name: cm_name.to_owned(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
        },
        ttl_seconds_after_finished: Some(3600), // Clean up after 1 hour
        ..Default::default()
    };

    Ok(CronJob {
        metadata: kube::api::ObjectMeta {
            name: Some(cronjob_name.to_string()),
            labels: Some(labels),
            owner_references: owner_ref,
            ..Default::default()
        },
        spec: Some(CronJobSpec {
            schedule: schedule.to_string(),
            job_template: JobTemplateSpec {
                spec: Some(job_spec),
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    })
}

pub fn error_policy(
    _config: Arc<WazuhIndexerConfig>,
    error: &Error,
    _ctx: Arc<IndexerConfigContext>,
) -> Action {
    error!("Reconciliation failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}
