#[macro_use]
extern crate log;

use anyhow::*;
use kube::Client;

use crate::controller::handler::{watch_wazuh_cluster};

mod crds;
mod models;
mod controller;
mod errors;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    info!("starting up");

    // Create a Kubernetes client
    let client = Client::try_default().await?;

    info!("connected to the Kubernetes API");

    // Watch the WazuhCluster CRD
    watch_wazuh_cluster(client.clone()).await;

    info!("controller terminated");
    Ok(())
}

