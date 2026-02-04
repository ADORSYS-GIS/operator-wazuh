//! WazuhRule and WazuhDecoder controllers implementation

use crate::error::{Error, Result};
use kube::ResourceExt;
use kube::runtime::controller::Action;
use operator_crds::{WazuhDecoder, WazuhRule};
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};

pub struct RuleContext {
    pub client: kube::Client,
}

impl RuleContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhRule
pub async fn reconcile_rule(rule: Arc<WazuhRule>, ctx: Arc<RuleContext>) -> Result<Action> {
    let ns = rule
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let name = rule.name_any();

    info!("Reconciling WazuhRule: {}/{}", ns, name);

    // TODO: Implement actual reconciliation logic:
    // 1. Trigger ConfigMap aggregation
    // 2. Update status

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Error policy for WazuhRule reconciliation
pub fn rule_error_policy(_rule: Arc<WazuhRule>, error: &Error, _ctx: Arc<RuleContext>) -> Action {
    error!("Rule reconciliation failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

pub struct DecoderContext {
    pub client: kube::Client,
}

impl DecoderContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhDecoder
pub async fn reconcile_decoder(
    decoder: Arc<WazuhDecoder>,
    ctx: Arc<DecoderContext>,
) -> Result<Action> {
    let ns = decoder
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let name = decoder.name_any();

    info!("Reconciling WazuhDecoder: {}/{}", ns, name);

    // TODO: Implement actual reconciliation logic:
    // 1. Trigger ConfigMap aggregation
    // 2. Update status

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Error policy for WazuhDecoder reconciliation
pub fn decoder_error_policy(
    _decoder: Arc<WazuhDecoder>,
    error: &Error,
    _ctx: Arc<DecoderContext>,
) -> Action {
    error!("Decoder reconciliation failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}
