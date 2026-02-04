//! UI components for the web interface
//! 
//! This module provides reusable components for the web dashboard.

pub struct Components;

impl Components {
    /// Create a cluster status component
    pub fn cluster_status() -> &'static str {
        r##"<div class="cluster-status">
    <h2>Cluster Status</h2>
    <div class="status-indicator">
        <span class="status-dot"></span>
        <span class="status-text">Loading...</span>
    </div>
</div>"##
    }

    /// Create a navigation component
    pub fn navigation() -> &'static str {
        r##"<nav class="main-nav">
    <ul>
        <li><a href="#clusters">Clusters</a></li>
        <li><a href="#nodes">Nodes</a></li>
        <li><a href="#settings">Settings</a></li>
    </ul>
</nav>"##
    }
}