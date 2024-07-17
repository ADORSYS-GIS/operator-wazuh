use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::{Api, Client};
use kube::runtime::Controller;
use kube::runtime::controller::Action;
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher::Config;

use crate::crds::wazuh_cluster::WazuhCluster;
use crate::models::data::Data;

type WazuhClusterRef = ObjectRef<WazuhCluster>;

pub async fn watch_wazuh_cluster(client: Client) {
    // Create an API for the WazuhCluster CRD
    let crd_api: Api<WazuhCluster> = Api::all(client.clone());

    // Define the reconciliation function
    async fn reconcile(_wazuh: Arc<WazuhCluster>, _ctx: Arc<Data>) -> Result<Action, kube::Error> {
        info!("Reconciling WazuhCluster");

        let patch = json!({"spec": {
            "activeDeadlineSeconds": 5
        }});

        // Implement your reconciliation logic here
        Ok(Action::requeue(Duration::from_secs(300)))
    }

    // Define the error policy
    fn error_policy(_wazuh: Arc<WazuhCluster>, _error: &kube::Error, _ctx: Arc<Data>) -> Action {
        error!("Reconciliation failed");
        Action::requeue(Duration::from_secs(60))
    }

    // Create a controller for the WazuhCluster CRD
    Controller::new(crd_api, Config::default())
        .run(reconcile, error_policy, Arc::from(Data::new(client.clone())))
        .for_each(|res| async move {
            match res {
                Ok((WazuhClusterRef { name, .. }, _)) => info!("Reconciled {:?}", name),
                Err(e) => error!("Reconcile failed: {:?}", e),
            }
        })
        .await;
}