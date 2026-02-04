//! OpenSearch security controllers implementation

use crate::error::{Error, Result};
use kube::api::{Api, Patch, PatchParams};
use kube::ResourceExt;
use kube::runtime::controller::Action;
use operator_api::client::ApiClient;
use operator_crds::{WazuhIndexerIndexTemplate, WazuhIndexerSecurity, WazuhIndexerUser};
use serde_json::json;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info};

pub struct SecurityContext {
    pub client: kube::Client,
}

impl SecurityContext {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

/// Reconcile function for WazuhIndexerSecurity
pub async fn reconcile_security(
    security: Arc<WazuhIndexerSecurity>,
    ctx: Arc<SecurityContext>,
) -> Result<Action> {
    let ns = security
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let name = security.name_any();

    info!("Reconciling WazuhIndexerSecurity: {}/{}", ns, name);

    // In a real scenario, we would discover the indexer service endpoint.
    // For now, we assume a standard naming convention or look it up.
    let base_url = format!("http://wazuh-indexer.{}.svc.cluster.local:9200", ns);
    let api_client = ApiClient::new(base_url);

    // Reconcile Roles
    for role in &security.spec.roles {
        let role_name = &role.name;
        let body = json!({
            "cluster_permissions": role.cluster_permissions,
            "index_permissions": role.index_permissions.iter().map(|p| {
                json!({
                    "index_patterns": p.index_patterns,
                    "allowed_actions": p.allowed_actions
                })
            }).collect::<Vec<_>>()
        });

        api_client
            .put::<serde_json::Value, _>(&format!("/_plugins/_security/api/roles/{}", role_name), &body)
            .await?;
        info!("Applied role: {}", role_name);
    }

    // Reconcile Tenants
    for tenant in &security.spec.tenants {
        let tenant_name = &tenant.name;
        let body = json!({
            "description": tenant.description
        });

        api_client
            .put::<serde_json::Value, _>(&format!("/_plugins/_security/api/tenants/{}", tenant_name), &body)
            .await?;
        info!("Applied tenant: {}", tenant_name);
    }

    // Update Status
    let security_api: Api<WazuhIndexerSecurity> = Api::namespaced(ctx.client.clone(), &ns);
    let status = json!({
        "status": {
            "applied": true,
            "error": null
        }
    });
    security_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&status))
        .await?;

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Reconcile function for WazuhIndexerUser
pub async fn reconcile_user(
    user: Arc<WazuhIndexerUser>,
    ctx: Arc<SecurityContext>,
) -> Result<Action> {
    let ns = user
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let name = user.name_any();

    info!("Reconciling WazuhIndexerUser: {}/{}", ns, name);

    let base_url = format!("http://wazuh-indexer.{}.svc.cluster.local:9200", ns);
    let api_client = ApiClient::new(base_url);

    // In a real implementation, we would fetch the password from the secret.
    // For this phase, we'll assume a placeholder or that it's managed elsewhere.
    let body = json!({
        "password": "vErySecUrEPasSw0rd123!", // Placeholder
        "opendistro_security_roles": user.spec.roles
    });

    api_client
        .put::<serde_json::Value, _>(&format!("/_plugins/_security/api/internalusers/{}", user.spec.username), &body)
        .await?;

    // Update Status
    let user_api: Api<WazuhIndexerUser> = Api::namespaced(ctx.client.clone(), &ns);
    let status = json!({
        "status": {
            "created": true,
            "error": null
        }
    });
    user_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&status))
        .await?;

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Reconcile function for WazuhIndexerIndexTemplate
pub async fn reconcile_template(
    template: Arc<WazuhIndexerIndexTemplate>,
    ctx: Arc<SecurityContext>,
) -> Result<Action> {
    let ns = template
        .namespace()
        .ok_or_else(|| Error::ValidationError("Namespace is required".to_string()))?;
    let name = template.name_any();

    info!("Reconciling WazuhIndexerIndexTemplate: {}/{}", ns, name);

    let base_url = format!("http://wazuh-indexer.{}.svc.cluster.local:9200", ns);
    let api_client = ApiClient::new(base_url);

    let settings: serde_json::Value = serde_json::from_str(&template.spec.settings)?;
    let body = json!({
        "index_patterns": template.spec.index_patterns,
        "template": settings
    });

    api_client
        .put::<serde_json::Value, _>(&format!("/_index_template/{}", template.spec.name), &body)
        .await?;

    // Update Status
    let template_api: Api<WazuhIndexerIndexTemplate> = Api::namespaced(ctx.client.clone(), &ns);
    let status = json!({
        "status": {
            "applied": true,
            "error": null
        }
    });
    template_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&status))
        .await?;

    Ok(Action::requeue(Duration::from_secs(300)))
}
