//! Controller implementation for the Wazuh operator

use crate::error::Result;
use futures::StreamExt;
use kube::api::{Api, Resource};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};

#[derive(Clone)]
pub struct ControllerContext {
    pub client: kube::Client,
}

impl ControllerContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Generic controller for managing custom resources
pub struct WazuhController<T>
where
    T: Resource<DynamicType = ()>
        + Clone
        + serde::de::DeserializeOwned
        + serde::Serialize
        + Send
        + 'static,
    T::DynamicType: Default,
{
    context: Arc<ControllerContext>,
    phantom: std::marker::PhantomData<T>,
}

impl<T> WazuhController<T>
where
    T: Resource<DynamicType = ()>
        + Clone
        + serde::de::DeserializeOwned
        + serde::Serialize
        + Send
        + Sync
        + 'static,
    T::DynamicType: Default + std::fmt::Debug + Clone + PartialEq + Eq + Hash,
{
    pub fn new(context: ControllerContext) -> Self {
        Self {
            context: Arc::new(context),
            phantom: std::marker::PhantomData,
        }
    }
}

use std::hash::Hash;

impl WazuhController<operator_crds::WazuhIndexerCluster> {
    pub async fn run(&self, namespace: Option<&str>) -> Result<()> {
        info!("Starting WazuhIndexerCluster controller");

        let client = self.context.client.clone();
        let api: Api<operator_crds::WazuhIndexerCluster> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };

        let ctx = Arc::new(crate::indexer_controller::IndexerContext::new(client.clone()));

        Controller::new(api, Config::default())
            .shutdown_on_signal()
            .run(
                crate::indexer_controller::reconcile,
                crate::indexer_controller::error_policy,
                ctx,
            )
            .for_each(|res| async move {
                match res {
                    Ok(o) => info!("Reconciled {:?}", o),
                    Err(e) => error!("Reconcile failed: {:?}", e),
                }
            })
            .await;

        Ok(())
    }
}

// Temporary placeholders for other controllers to keep main.rs working
impl WazuhController<operator_crds::WazuhManagerCluster> {
    pub async fn run(&self, _namespace: Option<&str>) -> Result<()> {
        loop { tokio::time::sleep(Duration::from_secs(3600)).await; }
    }
}
impl WazuhController<operator_crds::WazuhDashboard> {
    pub async fn run(&self, _namespace: Option<&str>) -> Result<()> {
        loop { tokio::time::sleep(Duration::from_secs(3600)).await; }
    }
}
impl WazuhController<operator_crds::WazuhConfig> {
    pub async fn run(&self, _namespace: Option<&str>) -> Result<()> {
        loop { tokio::time::sleep(Duration::from_secs(3600)).await; }
    }
}
impl WazuhController<operator_crds::WazuhRule> {
    pub async fn run(&self, _namespace: Option<&str>) -> Result<()> {
        loop { tokio::time::sleep(Duration::from_secs(3600)).await; }
    }
}
impl WazuhController<operator_crds::WazuhListener> {
    pub async fn run(&self, _namespace: Option<&str>) -> Result<()> {
        loop { tokio::time::sleep(Duration::from_secs(3600)).await; }
    }
}
impl WazuhController<operator_crds::WazuhIndexerSecurity> {
    pub async fn run(&self, _namespace: Option<&str>) -> Result<()> {
        loop { tokio::time::sleep(Duration::from_secs(3600)).await; }
    }
}
