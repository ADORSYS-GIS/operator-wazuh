use std::sync::Arc;

use futures::StreamExt;
use kube::{Api, Client};
use kube::runtime::Controller;
use kube::runtime::watcher::Config;

use crate::controller::error_handler::error_policy;
use crate::controller::reconcile_wazuh::reconcile_wazuh;
use crate::crds::wazuh_cluster::WazuhCluster;
use crate::models::cluster_ref::WazuhClusterRef;
use crate::models::data::Data;

pub async fn watch_wazuh_cluster(client: Client) {
    // Create an API for the WazuhCluster CRD
    let crd_api: Api<WazuhCluster> = Api::all(client.clone());

    // Create a controller for the WazuhCluster CRD
    Controller::new(crd_api, Config::default())
        .run(reconcile_wazuh, error_policy, Arc::from(Data::new(client.clone())))
        .for_each(|res| async move {
            match res {
                Ok((WazuhClusterRef { name, namespace, .. }, _)) => debug!("Reconciled {:?} in {:?}", name, namespace.unwrap_or_else(|| "default".to_string())),
                Err(e) => error!("Reconcile failed: {:?}", e),
            }
        })
        .await;
}