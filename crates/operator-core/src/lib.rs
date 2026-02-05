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
pub mod indexer_backup_controller;
pub mod indexer_config_controller;
pub mod indexer_controller;
pub mod listener_controller;
pub mod manager_backup_controller;
pub mod manager_controller;
pub mod rule_controller;
pub mod security_controller;
pub mod tls;
pub mod wazuh_ca_controller;
pub mod wazuh_manager_controller;
pub mod pod_template;

pub use client::ClientManager;
pub use controller::WazuhController;
pub use error::{Error, Result};
pub mod ca;
pub mod cert_manager;
