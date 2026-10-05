//! Windows Registry Collector — Stub Implementation

use async_trait::async_trait;
use crate::trait_def::{Collector, CollectorOutput, ExecutionContext, CollectorError};
use serde_json::Value;

/// Windows Registry Collector
pub struct RegistryWindowsCollector;

#[async_trait]
impl Collector for RegistryWindowsCollector {
    fn name(&self) -> &'static str {
        "registry_windows"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn supported_actions(&self) -> Vec<&'static str> {
        vec!["get_key", "get_value", "enumerate", "persistence", "sam"]
    }

    fn supported_os(&self) -> Vec<&'static str> {
        vec!["windows"]
    }

    async fn execute(
        &self,
        action: &str,
        _params: Value,
        _context: &ExecutionContext,
    ) -> Result<CollectorOutput, CollectorError> {
        match action {
            _ => Err(CollectorError::UnsupportedAction(format!("registry_windows action {} not implemented", action)))
        }
    }
}