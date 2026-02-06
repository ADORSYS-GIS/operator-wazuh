//! Pod template patch helper

use crate::error::Result;
use k8s_openapi::api::core::v1::PodTemplateSpec;
use operator_crds::PodTemplateSpecPatch;
use serde_json::Value;

pub fn apply_pod_template_patch(
    template: &mut PodTemplateSpec,
    patch: &PodTemplateSpecPatch,
) -> Result<()> {
    if let Some(meta_patch) = &patch.metadata {
        let meta = template.metadata.get_or_insert_with(Default::default);
        if let Some(labels) = &meta_patch.labels {
            let dst = meta.labels.get_or_insert_with(Default::default);
            for (k, v) in labels {
                dst.insert(k.clone(), v.clone());
            }
        }
        if let Some(annotations) = &meta_patch.annotations {
            let dst = meta.annotations.get_or_insert_with(Default::default);
            for (k, v) in annotations {
                dst.insert(k.clone(), v.clone());
            }
        }
    }

    if let Some(spec_patch) = &patch.spec {
        let mut base = serde_json::to_value(template.spec.clone()).unwrap_or(Value::Null);
        let patch_value = serde_json::to_value(spec_patch).unwrap_or(Value::Null);
        merge_value(&mut base, patch_value);
        template.spec = serde_json::from_value(base).ok();
    }

    Ok(())
}

fn merge_value(base: &mut Value, patch: Value) {
    match (base, patch) {
        (Value::Object(base_map), Value::Object(patch_map)) => {
            for (k, v) in patch_map {
                match base_map.get_mut(&k) {
                    Some(base_val) => merge_value(base_val, v),
                    None => {
                        base_map.insert(k, v);
                    }
                }
            }
        }
        (base_val, patch_val) => {
            *base_val = patch_val;
        }
    }
}
