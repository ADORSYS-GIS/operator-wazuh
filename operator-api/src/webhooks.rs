//! Validation webhooks for Wazuh configuration CRDs

use axum::{extract::Json, http::StatusCode, response::IntoResponse};
use serde_json::{Value, json};
use tracing::{error, info};

/// Validating admission webhook for WazuhRule and WazuhDecoder
pub async fn validate_config(Json(admission_review): Json<Value>) -> impl IntoResponse {
    info!("Received admission review request");

    // TODO: Implement actual XML validation logic
    // For now, we just accept everything

    let uid = admission_review["request"]["uid"]
        .as_str()
        .unwrap_or_default();

    let response = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": true
        }
    });

    (StatusCode::OK, Json(response))
}
