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
- **Developer 1**: Focuses on CRD and API development.
- **Developer 2**: Handles operator logic and Helm integration.
- **Developer 3**: Manages volume and ConfigMap creation.
- **Developer 4**: Develops testing strategies and documentation.

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

### Example Reconciliation Code

```go
package controllers

import (
    "context"
    helmv2 "github.com/operator-framework/helm-operator-plugins/pkg/helm/v2"
    wazuhv1 "your-operator/api/v1"
    "sigs.k8s.io/controller-runtime/pkg/client"
)

type WazuhClusterReconciler struct {
    client.Client
    HelmChart helmv2.HelmChart
}

func (r *WazuhClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    var wazuhCluster wazuhv1.WazuhCluster
    if err := r.Get(ctx, req.NamespacedName, &wazuhCluster); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    // Reconcile Helm release for Wazuh master
    _, err := r.HelmChart.ReconcileRelease(ctx, req.NamespacedName, wazuhCluster.Spec.Master)
    if err != nil {
        return ctrl.Result{}, err
    }

    // Similar logic for other components

    return ctrl.Result{}, nil
}

func (r *WazuhClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
    return ctrl.NewControllerManagedBy(mgr).
        For(&wazuhv1.WazuhCluster{}).
        Complete(r)
}
```

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

## Conclusion

By following this comprehensive plan, your team can successfully develop a robust Kubernetes operator for managing Wazuh deployments. This project will leverage existing Helm charts, ensuring efficient and reliable management of Wazuh components within a Kubernetes environment. If you have any questions or need further guidance, please refer to the documentation or contact the project team.
