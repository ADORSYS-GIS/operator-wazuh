//! Core logic and utilities for the Wazuh operator
//! 
//! This module provides shared functionality including:
//! - Error handling
//! - Controller utilities
//! - Reconciliation logic
//! - Kubernetes client management

pub mod error;
pub mod controller;
pub mod client;
pub mod indexer_controller;
pub mod manager_controller;
pub mod dashboard_controller;
pub mod config_aggregator;
pub mod config_controller;
pub mod rule_controller;
pub mod listener_controller;
pub mod tls;

pub use error::{Error, Result};
pub use controller::WazuhController;
pub use client::ClientManager;