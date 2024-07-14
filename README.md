# Wazuh Kubernetes Operator

## Overview

This project aims to develop a Kubernetes operator for managing the deployment of Wazuh components using existing Helm charts. The operator will handle the creation and management of Wazuh master, workers, indexer, dashboard, and Snort components. It will also manage Persistent Volume Claims (PVCs), ConfigMaps, and ensure proper dependencies and cleanup using finalizers.

## Table of Contents

- [Overview](#overview)
- [Project Scope and Team Roles](#project-scope-and-team-roles)
- [Development Environment Setup](#development-environment-setup)
- [Custom Resource Definitions (CRDs)](#custom-resource-definitions-crds)
- [Operator Logic and Helm Integration](#operator-logic-and-helm-integration)
- [Volume and ConfigMap Management](#volume-and-configmap-management)
- [Testing and Validation](#testing-and-validation)
- [Documentation](#documentation)
- [Final Review and Deployment](#final-review-and-deployment)
- [Additional Considerations](#additional-considerations)

## Project Scope and Team Roles

### Team Roles

- **Team Lead**: Oversees the project, ensures deadlines are met, and coordinates tasks.
- **DevOps**: Focuses on CRD and API development.
- **Developer**: Handles operator logic and Helm integration.
- **DevOps**: Manages volume and ConfigMap creation.
- **Tester**: Develops testing strategies and documentation.

## Development Environment Setup

### Tools and Dependencies

Ensure all team members have the following tools installed:

- Kubernetes Cluster (Minikube, Kind, or a cloud-based cluster)
- [Operator SDK](https://sdk.operatorframework.io/docs/installation/)
- [Helm](https://helm.sh/docs/intro/install/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
- Git
- CI/CD tools (GitHub Actions, Jenkins, etc.)

### Repository Setup

1. Create a Git repository for the project.
2. Set up a CI/CD pipeline to automate testing and deployment.

## Custom Resource Definitions (CRDs)

### CRD Definitions

Define CRDs for Wazuh components:

1. **WazuhCluster CRD**: Encompasses the entire Wazuh setup.
2. **Snort CRD**: Manages Snort deployment.
3. **WazuhDashboard CRD**: Manages the Wazuh dashboard deployment.

### Example CRD Schema

```yaml
apiVersion: wazuh.io/v1
kind: WazuhCluster
metadata:
  name: example-wazuh-cluster
spec:
  master:
    replicas: 1
    storageSize: 10Gi
  worker:
    replicas: 2
    storageSize: 10Gi
  indexer:
    replicas: 1
    storageSize: 10Gi
  dashboard:
    enabled: true
  snort:
    enabled: false
```

### Validation

Implement OpenAPI validation schemas for the CRDs to ensure the correct configuration.

## Operator Logic and Helm Integration

### Initialize Operator SDK Project

1. Scaffold a new operator project using the Operator SDK.
2. Integrate Helm using the Helm operator plugin to manage Helm charts.

### Reconciliation Logic

Implement the reconciliation loop to:

1. Watch for changes in the CRDs.
2. Deploy/update Helm releases based on the CRD specifications.

## Volume and ConfigMap Management

### PVC and ConfigMap Creation

1. Define and create PVCs with custom annotations.
2. Manage ConfigMaps for each component.
3. Ensure PVCs are created and mounted correctly, handling custom annotations for mounting paths.

### Integration with Operator

Integrate PVC and ConfigMap management into the operator's reconciliation logic to ensure proper creation and mounting.

## Testing and Validation

### Unit and Integration Tests

1. Develop unit tests for the operator logic.
2. Create integration tests to ensure the full deployment using the CRDs works as expected.

### Deployment Testing

Deploy the operator in a development cluster and test the CRD deployment to ensure all components are created and managed correctly.

## Documentation

### User Guide

Provide a user guide that includes:

1. Instructions on deploying the operator.
2. Examples of using the CRDs.
3. Configuration options and explanations.

### Developer Guide

Include a developer guide with:

1. Instructions on contributing to the project.
2. Code structure and explanation.
3. How to run and debug the operator.

## Final Review and Deployment

### Code Review

Conduct a thorough code review and make final adjustments based on feedback.

### Production Deployment

Prepare the operator for production deployment:

1. Ensure all tests pass.
2. Validate in a staging environment.
3. Deploy to production.

## Additional Considerations

### Monitoring and Logging

Integrate monitoring and logging for the operator and Wazuh components using tools like Prometheus and Grafana.

### Security

Implement RBAC policies and security measures to ensure the operator has the necessary permissions and follows best security practices.

### Backup and Recovery

Plan and implement backup and recovery strategies for Wazuh data to ensure data integrity and availability.

## Full example
CRD for Custom PVC
```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: custompvcs.yourdomain.com
spec:
  group: yourdomain.com
  names:
    kind: CustomPVC
    listKind: CustomPVCList
    plural: custompvcs
    singular: custompvc
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                accessModes:
                  type: array
                  items:
                    type: string
                resources:
                  type: object
                  properties:
                    requests:
                      type: object
                      properties:
                        storage:
                          type: string
```

CRD for Custom Config
```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: customconfigs.yourdomain.com
spec:
  group: yourdomain.com
  names:
    kind: CustomConfig
    listKind: CustomConfigList
    plural: customconfigs
    singular: customconfig
  scope: Namespaced
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                configData:
                  type: string
```

Operator Logic in Rust
```toml
[dependencies]
kube = { version = "0.58.0", features = ["runtime"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1", features = ["full"] }
```

Main
```rust
use kube::api::{Api, PostParams};
use kube::Client;
use kube::CustomResource;
use kube_runtime::controller::{Context, Controller, ReconcilerAction};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Duration;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug)]
#[kube(group = "yourdomain.com", version = "v1", kind = "CustomPVC", namespaced)]
struct CustomPVCSpec {
    access_modes: Vec<String>,
    resources: ResourceRequirements,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct ResourceRequirements {
    requests: StorageRequests,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct StorageRequests {
    storage: String,
}

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug)]
#[kube(group = "yourdomain.com", version = "v1", kind = "CustomConfig", namespaced)]
struct CustomConfigSpec {
    config_data: String,
}

async fn reconcile_pvc(pvc: Arc<CustomPVC>, ctx: Context<Data>) -> Result<ReconcilerAction, kube::Error> {
    // Here you can add the logic to handle PVC creation, update, or deletion
    // Example: Create a PersistentVolumeClaim based on the CustomPVC
    Ok(ReconcilerAction {
        requeue_after: Some(Duration::from_secs(300)),
    })
}

async fn reconcile_config(config: Arc<CustomConfig>, ctx: Context<Data>) -> Result<ReconcilerAction, kube::Error> {
    // Here you can add the logic to handle Config creation, update, or deletion
    // Example: Create a ConfigMap based on the CustomConfig
    Ok(ReconcilerAction {
        requeue_after: Some(Duration::from_secs(300)),
    })
}

struct Data {
    client: Client,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::try_default().await?;
    let pvcs = Api::<CustomPVC>::all(client.clone());
    let configs = Api::<CustomConfig>::all(client.clone());

    let context = Context::new(Data { client: client.clone() });

    Controller::new(pvcs, Default::default())
        .run(reconcile_pvc, error_policy, context.clone())
        .for_each(|res| async move {
            match res {
                Ok(o) => println!("reconciled {:?}", o),
                Err(e) => eprintln!("reconcile failed: {:?}", e),
            }
        })
        .await;

    Controller::new(configs, Default::default())
        .run(reconcile_config, error_policy, context)
        .for_each(|res| async move {
            match res {
                Ok(o) => println!("reconciled {:?}", o),
                Err(e) => eprintln!("reconcile failed: {:?}", e),
            }
        })
        .await;

    Ok(())
}

fn error_policy(_object: Arc<CustomPVC>, _error: &kube::Error, _ctx: Context<Data>) -> ReconcilerAction {
    ReconcilerAction {
        requeue_after: Some(Duration::from_secs(60)),
    }
}

fn error_policy(_object: Arc<CustomConfig>, _error: &kube::Error, _ctx: Context<Data>) -> ReconcilerAction {
    ReconcilerAction {
        requeue_after: Some(Duration::from_secs(60)),
    }
}
```

## Conclusion

By following this comprehensive plan, your team can successfully develop a robust Kubernetes operator for managing Wazuh deployments. This project will leverage existing Helm charts, ensuring efficient and reliable management of Wazuh components within a Kubernetes environment. If you have any questions or need further guidance, please refer to the documentation or contact the project team.
