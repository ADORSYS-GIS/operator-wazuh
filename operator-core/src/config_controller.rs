//! WazuhConfig controller implementation

use kube::runtime::controller::Action;
use kube::ResourceExt;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{info, error};
use operator_crds::WazuhConfig;
use crate::error::{Error, Result};

pub struct ConfigContext {
    pub client: kube::Client,
}

impl ConfigContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhConfig
pub async fn reconcile(config: Arc<WazuhConfig>, ctx: Arc<ConfigContext>) -> Result<Action> {
    let ns = config.namespace().ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let name = config.name_any();
    
    info!("Reconciling WazuhConfig: {}/{}", ns, name);

    // TODO: Implement actual reconciliation logic:
    // 1. Generate ossec.conf ConfigMap
    // 2. Update status

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Error policy for WazuhConfig reconciliation
pub fn error_policy(_config: Arc<WazuhConfig>, error: &Error, _ctx: Arc<ConfigContext>) -> Action {
    error!("Reconciliation failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}
