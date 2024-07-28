use kube::Resource;

use crate::crds::wazuh_cluster::WazuhCluster;
use crate::models::crd_action::WazuhClusterAction;

pub fn determine_action(cluster: &WazuhCluster) -> WazuhClusterAction {
    if cluster.meta().deletion_timestamp.is_some() {
        WazuhClusterAction::Delete
    } else if cluster
        .meta()
        .finalizers
        .as_ref()
        .map_or(true, |finalizers| finalizers.is_empty()) {
        WazuhClusterAction::Create
    } else {
        WazuhClusterAction::Update
    }
}