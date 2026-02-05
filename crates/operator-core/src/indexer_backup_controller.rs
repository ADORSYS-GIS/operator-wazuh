use crate::error::{Error, Result};
use k8s_openapi::api::batch::v1::{CronJob, CronJobSpec, JobSpec, JobTemplateSpec};
use k8s_openapi::api::core::v1::{
    Container, EnvVar, EnvVarSource, PersistentVolumeClaimVolumeSource, PodSpec, PodTemplateSpec,
    SecretKeySelector, Volume, VolumeMount,
};
use kube::ResourceExt;
use kube::api::{Api, ObjectMeta, Patch, PatchParams, Resource};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use operator_crds::wazuh_indexer_backup::{BackupStorage, WazuhIndexerBackup};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};

pub struct IndexerBackupContext {
    pub client: kube::Client,
}

impl IndexerBackupContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

pub async fn reconcile(
    backup: Arc<WazuhIndexerBackup>,
    ctx: Arc<IndexerBackupContext>,
) -> Result<Action> {
    let ns = backup
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let api: Api<WazuhIndexerBackup> = Api::namespaced(ctx.client.clone(), &ns);

    finalizer(
        &api,
        "wazuh.adorsys.team/indexer-backup-finalizer",
        backup,
        |event| {
            let ctx = ctx.clone();
            async move {
                match event {
                    FinalizerEvent::Apply(backup) => reconcile_backup(backup, ctx).await,
                    FinalizerEvent::Cleanup(backup) => cleanup_backup(backup, ctx).await,
                }
            }
        },
    )
    .await
    .map_err(|e| Error::ReconciliationError(e.to_string()))
}

async fn reconcile_backup(
    backup: Arc<WazuhIndexerBackup>,
    ctx: Arc<IndexerBackupContext>,
) -> Result<Action> {
    let ns = backup.namespace().unwrap();
    let name = backup.name_any();

    info!("Reconciling WazuhIndexerBackup: {}/{}", ns, name);

    let client = ctx.client.clone();
    let cronjob_api: Api<CronJob> = Api::namespaced(client, &ns);

    let cronjob = generate_cronjob(&backup)?;

    cronjob_api
        .patch(
            &name,
            &PatchParams::apply("wazuh-operator"),
            &Patch::Apply(&cronjob),
        )
        .await?;

    Ok(Action::requeue(Duration::from_secs(60)))
}

async fn cleanup_backup(
    backup: Arc<WazuhIndexerBackup>,
    _ctx: Arc<IndexerBackupContext>,
) -> Result<Action> {
    let ns = backup.namespace().unwrap();
    let name = backup.name_any();
    info!("Cleaning up WazuhIndexerBackup: {}/{}", ns, name);

    // CronJob will be deleted by owner reference
    Ok(Action::await_change())
}

fn generate_cronjob(backup: &WazuhIndexerBackup) -> Result<CronJob> {
    let name = backup.name_any();
    let ns = backup.namespace().unwrap();

    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "wazuh-indexer-backup".to_string());
    labels.insert("backup".to_string(), name.clone());
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "wazuh-operator".to_string(),
    );

    let owner_ref = backup.controller_owner_ref(&()).map(|o| vec![o]);

    let (container, volumes) = match &backup.spec.storage {
        BackupStorage::S3(s3) => {
            let container = Container {
                name: "backup".to_string(),
                image: Some("amazon/aws-cli:latest".to_string()), // Placeholder image
                command: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
                args: Some(vec![format!(
                    "echo 'Taking snapshot of {} to s3://{}'; aws s3 cp ...",
                    backup.spec.wazuh_indexer_cluster_ref, s3.bucket
                )]),
                env: Some(vec![
                    EnvVar {
                        name: "AWS_ACCESS_KEY_ID".to_string(),
                        value_from: Some(EnvVarSource {
                            secret_key_ref: Some(SecretKeySelector {
                                name: s3.access_key_id_secret_ref.clone(),
                                key: "access-key-id".to_string(), // Assuming key name
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    EnvVar {
                        name: "AWS_SECRET_ACCESS_KEY".to_string(),
                        value_from: Some(EnvVarSource {
                            secret_key_ref: Some(SecretKeySelector {
                                name: s3.secret_access_key_secret_ref.clone(),
                                key: "secret-access-key".to_string(), // Assuming key name
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    EnvVar {
                        name: "AWS_ENDPOINT_URL".to_string(),
                        value: Some(s3.endpoint.clone()),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            };
            (container, None)
        }
        BackupStorage::Pvc(pvc) => {
            let container = Container {
                name: "backup".to_string(),
                image: Some("busybox:latest".to_string()), // Placeholder image
                command: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
                args: Some(vec![format!(
                    "echo 'Simulating snapshot of {} to /backup'; touch /backup/snapshot-$(date +%s).tar.gz",
                    backup.spec.wazuh_indexer_cluster_ref
                )]),
                volume_mounts: Some(vec![VolumeMount {
                    name: "backup-storage".to_string(),
                    mount_path: "/backup".to_string(),
                    ..Default::default()
                }]),
                ..Default::default()
            };
            let volumes = vec![Volume {
                name: "backup-storage".to_string(),
                persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                    claim_name: pvc.claim_name.clone(),
                    ..Default::default()
                }),
                ..Default::default()
            }];
            (container, Some(volumes))
        }
    };

    Ok(CronJob {
        metadata: ObjectMeta {
            name: Some(name),
            namespace: Some(ns),
            labels: Some(labels),
            owner_references: owner_ref,
            ..Default::default()
        },
        spec: Some(CronJobSpec {
            schedule: backup.spec.schedule.clone(),
            concurrency_policy: Some("Forbid".to_string()),
            starting_deadline_seconds: Some(60),
            job_template: JobTemplateSpec {
                spec: Some(JobSpec {
                    template: PodTemplateSpec {
                        spec: Some(PodSpec {
                            containers: vec![container],
                            volumes,
                            restart_policy: Some("OnFailure".to_string()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        }),
        ..Default::default()
    })
}

pub fn error_policy(
    _backup: Arc<WazuhIndexerBackup>,
    error: &Error,
    _ctx: Arc<IndexerBackupContext>,
) -> Action {
    error!("Reconciliation failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}
