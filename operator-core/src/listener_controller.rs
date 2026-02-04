//! WazuhListener controller implementation

use kube::runtime::controller::Action;
use kube::ResourceExt;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{info, error};
use operator_crds::WazuhListener;
use crate::error::{Error, Result};

pub struct ListenerContext {
    pub client: kube::Client,
}

impl ListenerContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhListener
pub async fn reconcile(listener: Arc<WazuhListener>, ctx: Arc<ListenerContext>) -> Result<Action> {
    let ns = listener.namespace().ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let name = listener.name_any();
    
    info!("Reconciling WazuhListener: {}/{}", ns, name);

    // TODO: Implement actual reconciliation logic:
    // 1. Create Service for the listener
    // 2. Update manager configuration
    // 3. Update status

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Error policy for WazuhListener reconciliation
pub fn error_policy(_listener: Arc<WazuhListener>, error: &Error, _ctx: Arc<ListenerContext>) -> Action {
    error!("Reconciliation failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}
