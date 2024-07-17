use std::sync::Arc;

use futures::StreamExt;
use kube::{Api, Client};
use kube::runtime::Controller;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config;
use tokio::time::Duration;

use crate::crds::wazuh_cluster::WazuhCluster;
use crate::models::data::Data;

mod crds;
mod models;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a Kubernetes client
    let client = Client::try_default().await?;

    // Create an API for the WazuhCluster CRD
    let crd_api: Api<WazuhCluster> = Api::all(client.clone());

    // Define the reconciliation function
    async fn reconcile(wazuh: Arc<WazuhCluster>, _ctx: Arc<Data>) -> Result<Action, kube::Error> {
        println!("Reconciling WazuhCluster: {:?}", wazuh);

        // Implement your reconciliation logic here
        Ok(Action::requeue(Duration::from_secs(300)))
    }

    // Define the error policy
    fn error_policy(_wazuh: Arc<WazuhCluster>, _error: &kube::Error, _ctx: Arc<Data>) -> Action {
        Action::requeue(Duration::from_secs(60))
    }

    // Create a controller for the WazuhCluster CRD
    Controller::new(crd_api, Config::default())
        .run(reconcile, error_policy, Arc::from(Data::new()))
        .for_each(|res| async move {
            match res {
                Ok(o) => println!("Reconciled {:?}", o),
                Err(e) => eprintln!("Reconcile failed: {:?}", e),
            }
        })
        .await;

    Ok(())
}

