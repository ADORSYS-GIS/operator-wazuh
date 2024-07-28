use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use crate::errors::*;
use crate::crds::wazuh_cluster::WazuhCluster;
use crate::models::data::Data;

pub fn error_policy(wazuh: Arc<WazuhCluster>, error: &Error, _ctx: Arc<Data>) -> Action {
    eprintln!("Reconciliation error:\n{:?}.\n{:?}", error, wazuh);
    Action::requeue(Duration::from_secs(60))
}