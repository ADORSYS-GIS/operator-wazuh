//! Workload configuration definitions

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub struct WorkloadConfig {
    /// Override workload name (used for StatefulSet/Deployment name and pod name prefix)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}
