//! Volume claim template helpers

use crate::error::{Error, Result};
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, PersistentVolumeClaimSpec};
use operator_crds::VolumeClaimTemplate;

pub fn pvc_from_template(tmpl: &VolumeClaimTemplate) -> Result<PersistentVolumeClaim> {
    let spec: PersistentVolumeClaimSpec = serde_json::from_value(tmpl.spec.clone()).map_err(|e| {
        Error::ValidationError(format!(
            "Invalid volume claim spec for {}: {}",
            tmpl.metadata.name, e
        ))
    })?;

    Ok(PersistentVolumeClaim {
        metadata: kube::api::ObjectMeta {
            name: Some(tmpl.metadata.name.clone()),
            labels: tmpl.metadata.labels.clone(),
            annotations: tmpl.metadata.annotations.clone(),
            ..Default::default()
        },
        spec: Some(spec),
        ..Default::default()
    })
}

pub fn merge_volume_claims(
    defaults: Vec<PersistentVolumeClaim>,
    overrides: Vec<PersistentVolumeClaim>,
) -> Vec<PersistentVolumeClaim> {
    let mut merged = defaults;

    for override_pvc in overrides {
        let name = override_pvc
            .metadata
            .name
            .clone()
            .unwrap_or_default();
        if let Some(existing) = merged.iter_mut().find(|p| p.metadata.name == Some(name.clone())) {
            if let Some(labels) = override_pvc.metadata.labels {
                let dst = existing.metadata.labels.get_or_insert_with(Default::default);
                for (k, v) in labels {
                    dst.insert(k, v);
                }
            }
            if let Some(annotations) = override_pvc.metadata.annotations {
                let dst = existing
                    .metadata
                    .annotations
                    .get_or_insert_with(Default::default);
                for (k, v) in annotations {
                    dst.insert(k, v);
                }
            }
            if override_pvc.spec.is_some() {
                existing.spec = override_pvc.spec;
            }
        } else {
            merged.push(override_pvc);
        }
    }

    merged
}
