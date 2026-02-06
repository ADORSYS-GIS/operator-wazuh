//! HTTP API server for the Wazuh operator
//!
//! This module provides REST API endpoints for:
//! - Health checks
//! - Metrics
//! - Status information
//! - Cluster management

pub mod admission;
pub mod client;
pub mod handlers;
pub mod middleware;
pub mod server;
pub mod webhooks;

pub use server::Server;
