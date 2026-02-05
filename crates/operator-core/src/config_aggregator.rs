//! ConfigMap aggregation logic for Wazuh rules and decoders

use crate::error::Result;
use kube::api::{Api, ListParams};
use operator_crds::{WazuhConfig, WazuhDecoder, WazuhListener, WazuhRule};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub struct ConfigAggregator;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenerPort {
    pub port: i32,
    pub protocol: String,
}

impl ConfigAggregator {
    fn selector_map_matches(
        labels: Option<&BTreeMap<String, String>>,
        selector: &BTreeMap<String, String>,
    ) -> bool {
        if selector.is_empty() {
            return true;
        }
        let labels = match labels {
            Some(l) => l,
            None => return false,
        };
        selector
            .iter()
            .all(|(k, v)| labels.get(k).map(|lv| lv == v).unwrap_or(false))
    }

    fn selectors_match(
        labels: Option<&BTreeMap<String, String>>,
        node_selector: Option<&BTreeMap<String, String>>,
        selectors: Option<&Vec<BTreeMap<String, String>>>,
    ) -> bool {
        let mut all_selectors: Vec<&BTreeMap<String, String>> = Vec::new();
        if let Some(sel) = node_selector {
            all_selectors.push(sel);
        }
        if let Some(multi) = selectors {
            for sel in multi {
                all_selectors.push(sel);
            }
        }
        if all_selectors.is_empty() {
            return true;
        }
        all_selectors
            .into_iter()
            .any(|sel| Self::selector_map_matches(labels, sel))
    }

    fn listener_matches(
        listener: &WazuhListener,
        labels: Option<&BTreeMap<String, String>>,
        namespace: &str,
    ) -> bool {
        if !Self::selectors_match(
            labels,
            listener.spec.node_selector.as_ref(),
            listener.spec.selectors.as_ref(),
        ) {
            return false;
        }
        if let Some(cluster_ref) = listener.spec.manager_cluster.as_ref() {
            let labels = match labels {
                Some(l) => l,
                None => return false,
            };
            if labels.get("cluster") != Some(&cluster_ref.name) {
                return false;
            }
            let expected_ns = cluster_ref
                .namespace
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or(namespace);
            if labels.get("namespace").map(|s| s.as_str()) != Some(expected_ns) {
                return false;
            }
        }
        true
    }

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
                Self::selectors_match(
                    labels,
                    c.spec.node_selector.as_ref(),
                    None,
                )
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
                if !Self::listener_matches(&listener, labels, namespace) {
                    continue;
                }
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
            if !Self::selectors_match(
                labels,
                rule.spec.node_selector.as_ref(),
                rule.spec.selectors.as_ref(),
            ) {
                continue;
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
            if !Self::selectors_match(
                labels,
                decoder.spec.node_selector.as_ref(),
                decoder.spec.selectors.as_ref(),
            ) {
                continue;
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

    /// Collect listener ports that match the given labels
    pub async fn collect_listener_ports(
        client: kube::Client,
        namespace: &str,
        labels: Option<&BTreeMap<String, String>>,
    ) -> Result<Vec<ListenerPort>> {
        let api: Api<WazuhListener> = Api::namespaced(client, namespace);
        let listeners = api.list(&ListParams::default()).await?;
        let mut ports = Vec::new();

        for listener in listeners.items {
            if !Self::listener_matches(&listener, labels, namespace) {
                continue;
            }
            ports.push(ListenerPort {
                port: listener.spec.port,
                protocol: listener.spec.protocol.to_lowercase(),
            });
        }

        ports.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.protocol.cmp(&b.protocol)));
        ports.dedup_by(|a, b| a.port == b.port && a.protocol == b.protocol);

        Ok(ports)
    }
}
