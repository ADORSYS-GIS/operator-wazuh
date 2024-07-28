use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::runtime::reflector::Lookup;

use crate::controller::finalizer::{add_finalizer, delete_finalizer};
use crate::crds::wazuh_cluster::WazuhCluster;
use crate::models::crd_action::WazuhClusterAction;
use crate::models::data::Data;
use crate::services::determine_action::determine_action;
use crate::services::nginx_deployment::{update_deployment, delete_deployment, update_status};
use crate::errors::*;

pub async fn reconcile_wazuh(wazuh: Arc<WazuhCluster>, ctx: Arc<Data>) -> Result<Action, Error> {
    info!("Reconciling WazuhCluster");

    let namespace = &wazuh.namespace().unwrap();
    let name = &wazuh.name().unwrap();

    match determine_action(&wazuh) {
        WazuhClusterAction::Create => {
            debug!("Creating WazuhCluster {:?}", name);
            // Add the finalizer and create the deployment
            add_finalizer(ctx.client.clone(), name, namespace).await?;
            update_deployment(ctx.client.clone(), &wazuh, name, namespace).await?;
            update_status(ctx.client.clone(), &wazuh, name, namespace).await?;
            debug!("Created WazuhCluster {:?}", name);
            Ok(Action::requeue(Duration::from_secs(20)))
        }
        WazuhClusterAction::Delete => {
            debug!("Deleting WazuhCluster {:?}", name);
            // Delete the deployment and remove the finalizer
            delete_deployment(ctx.client.clone(), &wazuh, name, namespace).await?;
            delete_finalizer(ctx.client.clone(), name, namespace).await?;
            debug!("Deleted WazuhCluster {:?}", name);
            Ok(Action::await_change())
        }
        WazuhClusterAction::Update => {
            debug!("Updating WazuhCluster {:?}", name);
            update_deployment(ctx.client.clone(), &wazuh, name, namespace).await?;
            update_status(ctx.client.clone(), &wazuh, name, namespace).await?;
            debug!("Updated WazuhCluster {:?}", name);
            Ok(Action::requeue(Duration::from_secs(10)))
        }
    }
}