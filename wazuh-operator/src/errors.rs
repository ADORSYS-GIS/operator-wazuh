use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to create WazuhCluster: {0}")]
    WazuhClusterCreationFailed(#[source] kube::Error),

    #[error("MissingObjectKey: {0}")]
    MissingObjectKey(&'static str),
}