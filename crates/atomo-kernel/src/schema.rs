//! Schema is a clonable wrapper around a compiled [`jsonschema::Validator`], held in
//! an [`Arc`].
//!
//! Compiling a schema is the costly step, and the Arc lets the registry store one
//! compiled copy and hand out cheap clones.

use std::sync::Arc;

use serde_json::Value;

#[derive(Clone)]
pub struct Schema(Arc<jsonschema::Validator>);

impl std::fmt::Debug for Schema {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Schema")
    }
}

impl Schema {
    pub fn compile(schema: &Value) -> Result<Schema, String> {
        jsonschema::validator_for(schema)
            .map(|v| Schema(Arc::new(v)))
            .map_err(|e| e.to_string())
    }

    /// The first few errors, joined, with their instance paths.
    pub fn validate(&self, instance: &Value) -> Result<(), String> {
        let errors: Vec<String> = self
            .0
            .iter_errors(instance)
            .take(3)
            .map(|e| {
                let path = e.instance_path().to_string();
                if path.is_empty() {
                    e.to_string()
                } else {
                    format!("{path}: {e}")
                }
            })
            .collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}
