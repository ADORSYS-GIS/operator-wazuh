//! CRD definitions for the Wazuh operator
//!
//! This module contains the Custom Resource Definitions for:
//! - WazuhIndexerCluster
//! - WazuhManagerCluster  
//! - WazuhDashboard

pub mod wazuh_agent_group;
pub mod wazuh_ca;
pub mod wazuh_config;
pub mod wazuh_dashboard;
pub mod wazuh_decoder;
pub mod wazuh_indexer_backup;
pub mod wazuh_indexer_cluster;
pub mod wazuh_indexer_config;
pub mod wazuh_indexer_index_template;
pub mod wazuh_indexer_security;
pub mod wazuh_indexer_user;
pub mod wazuh_listener;
pub mod wazuh_manager_backup;
pub mod wazuh_manager;
pub mod wazuh_manager_cluster;
pub mod pod_template;
pub mod wazuh_rule;

pub use wazuh_agent_group::WazuhAgentGroup;
pub use wazuh_ca::{IssuerRef, WazuhCA, WazuhCAProvider, WazuhCARef, WazuhCAStatus};
pub use wazuh_config::WazuhConfig;
pub use wazuh_dashboard::{ImageConfig as DashboardImageConfig, WazuhDashboard};
pub use wazuh_decoder::WazuhDecoder;
pub use wazuh_indexer_backup::WazuhIndexerBackup;
pub use wazuh_indexer_cluster::WazuhIndexerCluster;
pub use wazuh_indexer_config::{
    IndexerClusterRef, SecretKeyRef, WazuhIndexerConfig, WazuhIndexerConfigStatus,
};
pub use wazuh_indexer_index_template::WazuhIndexerIndexTemplate;
pub use wazuh_indexer_security::WazuhIndexerSecurity;
pub use wazuh_indexer_user::WazuhIndexerUser;
pub use wazuh_listener::WazuhListener;
pub use wazuh_manager_backup::WazuhManagerBackup;
pub use wazuh_manager::{
    ImageConfig as ManagerImageConfig, WazuhManager, WazuhManagerClusterRef, WazuhManagerRole,
};
pub use wazuh_manager_cluster::WazuhManagerCluster;
pub use pod_template::{PodMetadataPatch, PodSpecPatch, PodTemplateSpecPatch};
pub use wazuh_rule::WazuhRule;
