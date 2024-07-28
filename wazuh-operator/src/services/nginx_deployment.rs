use anyhow::*;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentStatus};
use k8s_openapi::api::core::v1::{Container, ContainerPort, PodSpec, PodTemplateSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::*;
use kube::{Api, Client, ResourceExt};
use kube::api::{DeleteParams, Patch, PatchParams, PostParams};

use crate::crds::wazuh_cluster::{WazuhCluster, WazuhClusterStatus};

fn get_deployment_name(name: &str) -> String {
    let s = format!("{name}-nginx");
    s.to_owned()
}

pub async fn update_deployment(client: Client, app: &WazuhCluster, name: &str, namespace: &str) -> Result<()> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);

    let mut labels = app.metadata.labels.clone().unwrap_or_default();
    labels.insert("app".to_owned(), app.name_any().to_owned());
    let app_name = get_deployment_name(name);

    match deployments.get_opt(&app_name).await? {
        Some(_) => {
            let fs = json!({
                "spec": {
                    "replicas": app.spec.replicas,
                }
            });
            let patch = Patch::Merge(fs);
            deployments.patch(&app_name, &PatchParams::default(), &patch).await?;
        }
        None => {
            let dp = Deployment {
                metadata: ObjectMeta {
                    name: Some(app_name.to_owned()),
                    namespace: Some(namespace.to_owned()),
                    labels: Some(labels.clone()),
                    ..ObjectMeta::default()
                },
                spec: Some(k8s_openapi::api::apps::v1::DeploymentSpec {
                    replicas: Some(app.spec.replicas),
                    selector: LabelSelector {
                        match_labels: Some(labels.clone()),
                        ..Default::default()
                    },
                    template: PodTemplateSpec {
                        metadata: Some(ObjectMeta {
                            labels: Some(labels.clone()),
                            ..Default::default()
                        }),
                        spec: Some(PodSpec {
                            containers: vec![Container {
                                name: app_name.to_owned(),
                                image: Some("nginx".to_string()),
                                ports: Some(vec![ContainerPort {
                                    container_port: 80,
                                    ..ContainerPort::default()
                                }]),
                                ..Default::default()
                            }],
                            ..Default::default()
                        }),
                    },
                    ..Default::default()
                }),
                ..Default::default()
            };
            deployments.create(&PostParams::default(), &dp).await?;
        }
    }

    Ok(())
}

pub async fn update_status(client: Client, _app: &WazuhCluster, name: &str, namespace: &str) -> Result<()> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let api: Api<WazuhCluster> = Api::namespaced(client.clone(), namespace);

    let app_name = get_deployment_name(name);
    let dp = deployments.get(&app_name).await?;
    let available_replicas = match dp.status {
        None => 0,
        Some(DeploymentStatus { available_replicas, .. }) => available_replicas.unwrap_or_else(|| 0)
    };
    let fs = json!({
        "status": WazuhClusterStatus { available_replicas }
    });
    let patch = Patch::Merge(fs);

    api
        .patch(name, &PatchParams::default(), &patch)
        .await?;
    Ok(())
}

pub async fn delete_deployment(client: Client, _app: &WazuhCluster, name: &str, namespace: &str) -> Result<()> {
    let api: Api<Deployment> = Api::namespaced(client, namespace);
    let app_name = get_deployment_name(name);
    api.delete(&app_name, &DeleteParams::default()).await?;
    Ok(())
}