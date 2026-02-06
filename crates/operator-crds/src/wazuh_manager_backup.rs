use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wazuh.adorsys.team",
    version = "v1alpha1",
    kind = "WazuhManagerBackup",
    plural = "wazuhmanagerbackups",
    namespaced,
    status = "WazuhManagerBackupStatus"
)]
pub struct WazuhManagerBackupSpec {
    /// Reference to the WazuhManagerCluster to be backed up
    #[serde(rename = "wazuhManagerClusterRef")]
    pub wazuh_manager_cluster_ref: String,
    /// Storage configuration for the backup
    pub storage: BackupStorage,
    /// Cron schedule for the backup
    pub schedule: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum BackupStorage {
    S3(S3Storage),
    Pvc(PvcStorage),
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct S3Storage {
    pub bucket: String,
    pub endpoint: String,
    #[serde(rename = "accessKeyIdSecretRef")]
    pub access_key_id_secret_ref: String,
    #[serde(rename = "secretAccessKeySecretRef")]
    pub secret_access_key_secret_ref: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct PvcStorage {
    #[serde(rename = "claimName")]
    pub claim_name: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WazuhManagerBackupStatus {
    /// Last backup time
    pub last_backup: Option<String>,
    /// Status of the last backup
    pub last_backup_status: Option<String>,
}
