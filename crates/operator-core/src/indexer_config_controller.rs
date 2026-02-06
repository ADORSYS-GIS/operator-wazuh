use crate::error::{Error, Result};
use k8s_openapi::api::batch::v1::{CronJob, CronJobSpec, JobSpec, JobTemplateSpec};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, EnvVar, PodSpec, PodTemplateSpec, Secret, Volume, VolumeMount,
};
use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams, Resource};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use operator_crds::wazuh_indexer_config::InternalUser;
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
    let cluster_ref = &config.spec.wazuh_indexer_cluster_ref;
    let cluster_ns = cluster_ref.namespace.clone().unwrap_or_else(|| ns.clone());
    let cluster_api: Api<WazuhIndexerCluster> = Api::namespaced(client.clone(), &cluster_ns);
    let cluster_name = &cluster_ref.name;
    let cluster = cluster_api.get(cluster_name).await.map_err(|e| {
        Error::ReconciliationError(format!(
            "Failed to get WazuhIndexerCluster {}: {}",
            cluster_name, e
        ))
    })?;

    // 2. Generate ConfigMap
    let cm_name = format!("{}-security-config", name);
    let resolved_internal_users =
        resolve_internal_users(client.clone(), &ns, config.spec.internal_users.as_ref()).await?;
    let cm = generate_configmap(&config, &cm_name, resolved_internal_users)?;
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
    ensure_cronjob(&config, &cluster, &cm_name, &hash, client.clone()).await?;

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

    Ok(Action::requeue(Duration::from_secs(60)))
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

fn generate_configmap(
    config: &WazuhIndexerConfig,
    name: &str,
    internal_users: Option<BTreeMap<String, InternalUser>>,
) -> Result<ConfigMap> {
    let mut data = BTreeMap::new();

    if let Some(roles) = &config.spec.roles {
        let value = with_security_meta(
            serde_yaml::to_value(roles)
                .map_err(|e| Error::ValidationError(format!("Failed to encode roles: {}", e)))?,
            "roles",
        );
        data.insert(
            "roles.yml".to_string(),
            serde_yaml::to_string(&value).map_err(|e| {
                Error::ValidationError(format!("Failed to render roles.yml: {}", e))
            })?,
        );
    }
    if let Some(roles_mapping) = &config.spec.roles_mapping {
        let value = with_security_meta(
            serde_yaml::to_value(roles_mapping).map_err(|e| {
                Error::ValidationError(format!("Failed to encode roles_mapping: {}", e))
            })?,
            "rolesmapping",
        );
        data.insert(
            "roles_mapping.yml".to_string(),
            serde_yaml::to_string(&value).map_err(|e| {
                Error::ValidationError(format!("Failed to render roles_mapping.yml: {}", e))
            })?,
        );
    }
    if let Some(tenants) = &config.spec.tenants {
        let value = with_security_meta(
            serde_yaml::to_value(tenants)
                .map_err(|e| Error::ValidationError(format!("Failed to encode tenants: {}", e)))?,
            "tenants",
        );
        data.insert(
            "tenants.yml".to_string(),
            serde_yaml::to_string(&value).map_err(|e| {
                Error::ValidationError(format!("Failed to render tenants.yml: {}", e))
            })?,
        );
    }
    if let Some(internal_users) = internal_users
        .as_ref()
        .or(config.spec.internal_users.as_ref())
    {
        let value = with_security_meta(
            serde_yaml::to_value(internal_users).map_err(|e| {
                Error::ValidationError(format!("Failed to encode internal_users: {}", e))
            })?,
            "internalusers",
        );
        data.insert(
            "internal_users.yml".to_string(),
            serde_yaml::to_string(&value).map_err(|e| {
                Error::ValidationError(format!("Failed to render internal_users.yml: {}", e))
            })?,
        );
    }
    if let Some(action_groups) = &config.spec.action_groups {
        let value = with_security_meta(
            serde_yaml::to_value(action_groups).map_err(|e| {
                Error::ValidationError(format!("Failed to encode action_groups: {}", e))
            })?,
            "actiongroups",
        );
        data.insert(
            "action_groups.yml".to_string(),
            serde_yaml::to_string(&value).map_err(|e| {
                Error::ValidationError(format!("Failed to render action_groups.yml: {}", e))
            })?,
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

fn with_security_meta(mut doc: serde_yaml::Value, doc_type: &str) -> serde_yaml::Value {
    let Some(map) = doc.as_mapping_mut() else {
        return doc;
    };
    if map.contains_key(serde_yaml::Value::String("_meta".to_string())) {
        return doc;
    }

    let mut meta = serde_yaml::Mapping::new();
    meta.insert(
        serde_yaml::Value::String("type".to_string()),
        serde_yaml::Value::String(doc_type.to_string()),
    );
    meta.insert(
        serde_yaml::Value::String("config_version".to_string()),
        serde_yaml::Value::Number(serde_yaml::Number::from(2)),
    );
    map.insert(
        serde_yaml::Value::String("_meta".to_string()),
        serde_yaml::Value::Mapping(meta),
    );
    doc
}

async fn resolve_internal_users(
    client: kube::Client,
    ns: &str,
    internal_users: Option<&BTreeMap<String, InternalUser>>,
) -> Result<Option<BTreeMap<String, InternalUser>>> {
    let internal_users = match internal_users {
        Some(users) => users,
        None => return Ok(None),
    };

    let secret_api: Api<Secret> = Api::namespaced(client, ns);
    let mut resolved = BTreeMap::new();

    for (name, user) in internal_users {
        let mut resolved_user = user.clone();

        if resolved_user.hash.is_none() {
            if let Some(hash_ref) = resolved_user.hash_secret_ref.as_ref() {
                let secret = secret_api.get(&hash_ref.name).await.map_err(|e| {
                    Error::ValidationError(format!(
                        "Failed to fetch hashSecretRef {}/{}: {}",
                        ns, hash_ref.name, e
                    ))
                })?;
                let key = hash_ref.key.as_deref().unwrap_or("hash");
                let value = secret_value(&secret, key).ok_or_else(|| {
                    Error::ValidationError(format!(
                        "Secret {}/{} is missing key {}",
                        ns, hash_ref.name, key
                    ))
                })?;
                resolved_user.hash = Some(value);
            }
        }

        resolved_user.hash_secret_ref = None;
        resolved.insert(name.clone(), resolved_user);
    }

    Ok(Some(resolved))
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
    hash: &str,
    client: kube::Client,
) -> Result<()> {
    let ns = config.namespace().unwrap();
    let name = config.name_any();

    if let Some(schedule) = &config.spec.schedule {
        let cronjob_name = format!("{}-cronjob", name);
        let cronjob_api: Api<CronJob> = Api::namespaced(client, &ns);

        let new_cronjob =
            generate_cronjob(config, cluster, &cronjob_name, cm_name, hash, schedule)?;
        cronjob_api
            .patch(
                &cronjob_name,
                &PatchParams::apply("wazuh-operator"),
                &Patch::Apply(&new_cronjob),
            )
            .await?;
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
    let tls_secret_name = cluster
        .spec
        .tls
        .as_ref()
        .and_then(|t| t.cert_secret.clone())
        .unwrap_or_else(|| format!("{}-tls", cluster_name));

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
                            "set -euo pipefail\n\
                            HOST={}.{}.svc.cluster.local\n\
                            TOOL=/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh\n\
                            BASE_ARGS='-p 9200 -icl -nhnv -cacert /usr/share/wazuh-indexer/config/certs/ca.crt -cert /usr/share/wazuh-indexer/config/admin-certs/tls.crt -key /usr/share/wazuh-indexer/config/admin-certs/tls.key -h '\n\
                            run_cfg() {{\n\
                              local file=\"$1\"\n\
                              local t=\"$2\"\n\
                              if [ -f \"$file\" ]; then\n\
                                echo \"Applying ${{file}} as ${{t}}\"\n\
                                $TOOL -f \"$file\" -t \"$t\" $BASE_ARGS\"$HOST\"\n\
                              fi\n\
                            }}\n\
                            run_cfg /etc/wazuh-indexer/security-config/config.yml config\n\
                            run_cfg /etc/wazuh-indexer/security-config/roles.yml roles\n\
                            run_cfg /etc/wazuh-indexer/security-config/roles_mapping.yml rolesmapping\n\
                            run_cfg /etc/wazuh-indexer/security-config/internal_users.yml internalusers\n\
                            run_cfg /etc/wazuh-indexer/security-config/action_groups.yml actiongroups\n\
                            run_cfg /etc/wazuh-indexer/security-config/tenants.yml tenants\n\
                            run_cfg /etc/wazuh-indexer/security-config/nodes_dn.yml nodesdn\n\
                            run_cfg /etc/wazuh-indexer/security-config/whitelist.yml whitelist\n\
                            run_cfg /etc/wazuh-indexer/security-config/allowlist.yml allowlist\n\
                            echo 'Security config apply completed'",
                            cluster_name, ns
                        ),
                    ]),
                    volume_mounts: Some(vec![
                        VolumeMount {
                            name: "tls".to_string(),
                            mount_path: "/usr/share/wazuh-indexer/config/certs".to_string(),
                            ..Default::default()
                        },
                        VolumeMount {
                            name: "admin-tls".to_string(),
                            mount_path: "/usr/share/wazuh-indexer/config/admin-certs".to_string(),
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
                            secret_name: Some(tls_secret_name),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    Volume {
                        name: "admin-tls".to_string(),
                        secret: Some(k8s_openapi::api::core::v1::SecretVolumeSource {
                            secret_name: Some(format!("{}-admin-tls", cluster_name)),
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
