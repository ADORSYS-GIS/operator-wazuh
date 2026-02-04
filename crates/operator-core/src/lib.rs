//! Core logic and utilities for the Wazuh operator
//!
//! This module provides shared functionality including:
//! - Error handling
//! - Controller utilities
//! - Reconciliation logic
//! - Kubernetes client management

pub mod client;
pub mod config_aggregator;
pub mod config_controller;
pub mod controller;
pub mod dashboard_controller;
pub mod error;
pub mod indexer_controller;
pub mod listener_controller;
pub mod manager_controller;
pub mod rule_controller;
pub mod security_controller;
pub mod tls;

pub use client::ClientManager;
pub use controller::WazuhController;
pub use error::{Error, Result};
