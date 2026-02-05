//! Controller implementation for the Wazuh operator

use crate::error::Result;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::api::batch::v1::CronJob;
use k8s_openapi::api::core::v1::{ConfigMap, Secret, Service};
use kube::api::{Api, Resource};
use kube::runtime::controller::Controller;
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
        let sts_api: Api<StatefulSet> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let svc_api: Api<Service> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let cm_api: Api<ConfigMap> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let secret_api: Api<Secret> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };

        let ctx = Arc::new(crate::indexer_controller::IndexerContext::new(
            client.clone(),
        ));

        Controller::new(api, Config::default())
            .owns(sts_api, Config::default())
            .owns(svc_api, Config::default())
            .owns(cm_api, Config::default())
            .owns(secret_api, Config::default())
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

impl WazuhController<operator_crds::WazuhManagerCluster> {
    pub async fn run(&self, namespace: Option<&str>) -> Result<()> {
        info!("Starting WazuhManagerCluster controller");

        let client = self.context.client.clone();
        let api: Api<operator_crds::WazuhManagerCluster> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let sts_api: Api<StatefulSet> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let svc_api: Api<Service> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let cm_api: Api<ConfigMap> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let secret_api: Api<Secret> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };

        let ctx = Arc::new(crate::manager_controller::ManagerContext::new(
            client.clone(),
        ));

        Controller::new(api, Config::default())
            .owns(sts_api, Config::default())
            .owns(svc_api, Config::default())
            .owns(cm_api, Config::default())
            .owns(secret_api, Config::default())
            .shutdown_on_signal()
            .run(
                crate::manager_controller::reconcile,
                crate::manager_controller::error_policy,
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

impl WazuhController<operator_crds::WazuhDashboard> {
    pub async fn run(&self, namespace: Option<&str>) -> Result<()> {
        info!("Starting WazuhDashboard controller");

        let client = self.context.client.clone();
        let api: Api<operator_crds::WazuhDashboard> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let deploy_api: Api<Deployment> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let svc_api: Api<Service> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let cm_api: Api<ConfigMap> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let secret_api: Api<Secret> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };

        let ctx = Arc::new(crate::dashboard_controller::DashboardContext::new(
            client.clone(),
        ));

        Controller::new(api, Config::default())
            .owns(deploy_api, Config::default())
            .owns(svc_api, Config::default())
            .owns(cm_api, Config::default())
            .owns(secret_api, Config::default())
            .shutdown_on_signal()
            .run(
                crate::dashboard_controller::reconcile,
                crate::dashboard_controller::error_policy,
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
impl WazuhController<operator_crds::WazuhConfig> {
    pub async fn run(&self, _namespace: Option<&str>) -> Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }
}
impl WazuhController<operator_crds::WazuhRule> {
    pub async fn run(&self, _namespace: Option<&str>) -> Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }
}
impl WazuhController<operator_crds::WazuhListener> {
    pub async fn run(&self, _namespace: Option<&str>) -> Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }
}
impl WazuhController<operator_crds::WazuhIndexerSecurity> {
    pub async fn run(&self, _namespace: Option<&str>) -> Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }
}

impl WazuhController<operator_crds::WazuhIndexerConfig> {
    pub async fn run(&self, namespace: Option<&str>) -> Result<()> {
        info!("Starting WazuhIndexerConfig controller");

        let client = self.context.client.clone();
        let api: Api<operator_crds::WazuhIndexerConfig> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let cronjob_api: Api<CronJob> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let cm_api: Api<ConfigMap> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };

        let ctx = Arc::new(crate::indexer_config_controller::IndexerConfigContext::new(
            client.clone(),
        ));

        Controller::new(api, Config::default())
            .owns(cronjob_api, Config::default())
            .owns(cm_api, Config::default())
            .shutdown_on_signal()
            .run(
                crate::indexer_config_controller::reconcile,
                crate::indexer_config_controller::error_policy,
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

impl WazuhController<operator_crds::WazuhIndexerBackup> {
    pub async fn run(&self, namespace: Option<&str>) -> Result<()> {
        info!("Starting WazuhIndexerBackup controller");

        let client = self.context.client.clone();
        let api: Api<operator_crds::WazuhIndexerBackup> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let cronjob_api: Api<CronJob> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };

        let ctx = Arc::new(crate::indexer_backup_controller::IndexerBackupContext::new(
            client.clone(),
        ));

        Controller::new(api, Config::default())
            .owns(cronjob_api, Config::default())
            .shutdown_on_signal()
            .run(
                crate::indexer_backup_controller::reconcile,
                crate::indexer_backup_controller::error_policy,
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

impl WazuhController<operator_crds::WazuhManagerBackup> {
    pub async fn run(&self, namespace: Option<&str>) -> Result<()> {
        info!("Starting WazuhManagerBackup controller");

        let client = self.context.client.clone();
        let api: Api<operator_crds::WazuhManagerBackup> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };
        let cronjob_api: Api<CronJob> = if let Some(ns) = namespace {
            Api::namespaced(client.clone(), ns)
        } else {
            Api::all(client.clone())
        };

        let ctx = Arc::new(crate::manager_backup_controller::ManagerBackupContext::new(
            client.clone(),
        ));

        Controller::new(api, Config::default())
            .owns(cronjob_api, Config::default())
            .shutdown_on_signal()
            .run(
                crate::manager_backup_controller::reconcile,
                crate::manager_backup_controller::error_policy,
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
