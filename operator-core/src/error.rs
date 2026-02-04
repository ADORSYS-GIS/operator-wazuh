//! Error handling for the Wazuh operator

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Kubernetes config error: {0}")]
    KubeConfigError(#[from] kube::config::InferConfigError),

    #[error("TLS generation error: {0}")]
    TlsError(#[from] rcgen::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Reconciliation error: {0}")]
    ReconciliationError(String),
}
