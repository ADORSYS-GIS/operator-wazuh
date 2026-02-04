//! HTTP server implementation for the operator API

use axum::{Router, routing::get};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;

pub struct Server {
    addr: SocketAddr,
}

impl Server {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// Create the application router
    pub fn router() -> Router {
        Router::new()
            .route("/healthz", get(health_handler))
            .route("/readyz", get(ready_handler))
            .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()))
    }

    /// Start the server
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app = Self::router();
        
        info!("Starting server on {}", self.addr);
        
        let listener = tokio::net::TcpListener::bind(self.addr).await?;
        axum::serve(listener, app).await?;
        
        Ok(())
    }
}

async fn health_handler() -> &'static str {
    "OK"
}

async fn ready_handler() -> &'static str {
    "OK"
}