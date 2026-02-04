//! ConfigMap aggregation logic for Wazuh rules and decoders

use sha2::{Sha256, Digest};
use kube::api::{Api, ListParams};
use operator_crds::{WazuhRule, WazuhDecoder};
use crate::error::Result;
use std::collections::BTreeMap;

pub struct ConfigAggregator;

impl ConfigAggregator {
    /// Aggregate all WazuhRules in a namespace into a map of filename -> content
    pub async fn aggregate_rules(client: kube::Client, namespace: &str) -> Result<BTreeMap<String, String>> {
        let api: Api<WazuhRule> = Api::namespaced(client, namespace);
        let rules = api.list(&ListParams::default()).await?;
        
        let mut aggregated = BTreeMap::new();
        
        // Group by filename and sort by priority
        let mut grouped: BTreeMap<String, Vec<&WazuhRule>> = BTreeMap::new();
        for rule in &rules {
            grouped.entry(rule.spec.filename.clone()).or_default().push(rule);
        }
        
        for (filename, mut file_rules) in grouped {
            file_rules.sort_by_key(|r| r.spec.priority.unwrap_or(100));
            let content = file_rules.iter()
                .map(|r| r.spec.content.as_str())
                .collect::<Vec<_>>()
                .join("\n\n");
            aggregated.insert(filename, content);
        }
        
        Ok(aggregated)
    }

    /// Aggregate all WazuhDecoders in a namespace into a map of filename -> content
    pub async fn aggregate_decoders(client: kube::Client, namespace: &str) -> Result<BTreeMap<String, String>> {
        let api: Api<WazuhDecoder> = Api::namespaced(client, namespace);
        let decoders = api.list(&ListParams::default()).await?;
        
        let mut aggregated = BTreeMap::new();
        
        // Group by filename and sort by priority
        let mut grouped: BTreeMap<String, Vec<&WazuhDecoder>> = BTreeMap::new();
        for decoder in &decoders {
            grouped.entry(decoder.spec.filename.clone()).or_default().push(decoder);
        }
        
        for (filename, mut file_decoders) in grouped {
            file_decoders.sort_by_key(|d| d.spec.priority.unwrap_or(100));
            let content = file_decoders.iter()
                .map(|d| d.spec.content.as_str())
                .collect::<Vec<_>>()
                .join("\n\n");
            aggregated.insert(filename, content);
        }
        
        Ok(aggregated)
    }

    /// Calculate SHA256 hash of a string
    pub fn calculate_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}
