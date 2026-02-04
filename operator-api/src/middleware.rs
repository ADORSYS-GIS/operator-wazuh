//! HTTP middleware for the operator API

use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use tracing::{info, warn};

/// Request logging middleware
pub async fn request_logging_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let uri = request.uri().clone();

    info!("Incoming request: {} {}", method, uri);

    let response = next.run(request).await;

    let status = response.status();
    info!("Response: {} {} -> {}", method, uri, status);

    Ok(response)
}

/// CORS middleware
pub async fn cors_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();
    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    headers.insert(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE".parse().unwrap(),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization".parse().unwrap(),
    );

    Ok(response)
}
