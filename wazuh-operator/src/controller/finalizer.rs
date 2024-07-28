use kube::{Api, Client};
use anyhow::*;
use kube::api::{Patch, PatchParams};
use serde_json::Value;
use crate::crds::wazuh_cluster::WazuhCluster;

pub async fn add_finalizer(client: Client, name: &str, namespace: &str) -> Result<()> {
    let api: Api<WazuhCluster> = Api::namespaced(client, namespace);
    let finalizer = json!({
        "metadata": {
            "finalizers": ["wazuh.adorsys.team/finalizer"]
        }
    });

    let patch: Patch<&Value> = Patch::Merge(&finalizer);
    api.patch(name, &PatchParams::default(), &patch).await?;

    Ok(())
}

/// Removes all finalizers from an `Echo` resource. If there are no finalizers already, this
/// action has no effect.
///
/// # Arguments:
/// - `client` - Kubernetes client to modify the `Echo` resource with.
/// - `name` - Name of the `Echo` resource to modify. Existence is not verified
/// - `namespace` - Namespace where the `Echo` resource with given `name` resides.
///
/// Note: Does not check for resource's existence for simplicity.
pub async fn delete_finalizer(client: Client, name: &str, namespace: &str) -> Result<()> {
    let api: Api<WazuhCluster> = Api::namespaced(client, namespace);
    let finalizer: Value = json!({
        "metadata": {
            "finalizers": null
        }
    });

    let patch: Patch<&Value> = Patch::Merge(&finalizer);
    api.patch(name, &PatchParams::default(), &patch).await?;

    Ok(())
}