//! ConfigMap aggregation logic for Wazuh rules and decoders

use crate::error::Result;
use kube::api::{Api, ListParams};
use operator_crds::{WazuhConfig, WazuhDecoder, WazuhRule};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub struct ConfigAggregator;

impl ConfigAggregator {
    /// Aggregate all WazuhConfigs and WazuhListeners in a namespace into a single ossec.conf content
    pub async fn aggregate_configs(
        client: kube::Client,
        namespace: &str,
        labels: Option<&BTreeMap<String, String>>,
    ) -> Result<String> {
        let config_api: Api<WazuhConfig> = Api::namespaced(client.clone(), namespace);
        let configs = config_api.list(&ListParams::default()).await?;

        let mut content = configs
            .iter()
            .filter(|c| {
                if let Some(selector) = &c.spec.node_selector {
                    for (k, v) in selector {
                        if labels.and_then(|l| l.get(k)) != Some(v) {
                            return false;
                        }
                    }
                }
                true
            })
            .map(|c| c.spec.content.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");

        // Aggregate listeners
        let listener_api: Api<operator_crds::WazuhListener> = Api::namespaced(client, namespace);
        let listeners = listener_api.list(&ListParams::default()).await?;

        if !listeners.items.is_empty() {
            content.push_str("\n\n<!-- Dynamic Listeners -->\n");
            for listener in listeners.items {
                let remote = format!(
                    r#"<remote>
  <connection>{}</connection>
  <port>{}</port>
  <protocol>{}</protocol>
</remote>"#,
                    if listener.spec.protocol.to_uppercase() == "UDP" {
                        "syslog"
                    } else {
                        "secure"
                    },
                    listener.spec.port,
                    listener.spec.protocol.to_lowercase()
                );
                content.push_str(&remote);
                content.push('\n');
            }
        }

        Ok(content)
    }

    /// Aggregate all WazuhRules in a namespace into a map of filename -> content
    pub async fn aggregate_rules(
        client: kube::Client,
        namespace: &str,
        labels: Option<&BTreeMap<String, String>>,
    ) -> Result<BTreeMap<String, String>> {
        let api: Api<WazuhRule> = Api::namespaced(client, namespace);
        let rules = api.list(&ListParams::default()).await?;

        let mut aggregated = BTreeMap::new();

        // Group by filename and sort by priority
        let mut grouped: BTreeMap<String, Vec<&WazuhRule>> = BTreeMap::new();
        for rule in &rules {
            if let Some(selector) = &rule.spec.node_selector {
                let mut matches = true;
                for (k, v) in selector {
                    if labels.and_then(|l| l.get(k)) != Some(v) {
                        matches = false;
                        break;
                    }
                }
                if !matches {
                    continue;
                }
            }
            grouped
                .entry(rule.spec.filename.clone())
                .or_default()
                .push(rule);
        }

        for (filename, mut file_rules) in grouped {
            file_rules.sort_by_key(|r| r.spec.priority.unwrap_or(100));
            let content = file_rules
                .iter()
                .map(|r| r.spec.content.as_str())
                .collect::<Vec<_>>()
                .join("\n\n");
            aggregated.insert(filename, content);
        }

        Ok(aggregated)
    }

    /// Aggregate all WazuhDecoders in a namespace into a map of filename -> content
    pub async fn aggregate_decoders(
        client: kube::Client,
        namespace: &str,
        labels: Option<&BTreeMap<String, String>>,
    ) -> Result<BTreeMap<String, String>> {
        let api: Api<WazuhDecoder> = Api::namespaced(client, namespace);
        let decoders = api.list(&ListParams::default()).await?;

        let mut aggregated = BTreeMap::new();

        // Group by filename and sort by priority
        let mut grouped: BTreeMap<String, Vec<&WazuhDecoder>> = BTreeMap::new();
        for decoder in &decoders {
            if let Some(selector) = &decoder.spec.node_selector {
                let mut matches = true;
                for (k, v) in selector {
                    if labels.and_then(|l| l.get(k)) != Some(v) {
                        matches = false;
                        break;
                    }
                }
                if !matches {
                    continue;
                }
            }
            grouped
                .entry(decoder.spec.filename.clone())
                .or_default()
                .push(decoder);
        }

        for (filename, mut file_decoders) in grouped {
            file_decoders.sort_by_key(|d| d.spec.priority.unwrap_or(100));
            let content = file_decoders
                .iter()
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
