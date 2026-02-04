//! CRD definitions for the Wazuh operator
//! 
//! This module contains the Custom Resource Definitions for:
//! - WazuhIndexerCluster
//! - WazuhManagerCluster  
//! - WazuhDashboard

pub mod wazuh_indexer_cluster;
pub mod wazuh_manager_cluster;
pub mod wazuh_dashboard;

pub use wazuh_indexer_cluster::WazuhIndexerCluster;
pub use wazuh_manager_cluster::WazuhManagerCluster;
pub use wazuh_dashboard::WazuhDashboard;