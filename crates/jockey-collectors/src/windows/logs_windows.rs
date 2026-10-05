//! Windows Logs Collector — Stub Implementation

use async_trait::async_trait;
use crate::trait_def::{Collector, CollectorOutput, ExecutionContext, CollectorError};
use serde_json::Value;

/// Windows Event Logs Collector
pub struct LogsWindowsCollector;

#[async_trait]
impl Collector for LogsWindowsCollector {
    fn name(&self) -> &'static str {
        "logs_windows"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn supported_actions(&self) -> Vec<&'static str> {
        vec!["security", "system", "application", "evtx_dump"]
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
            _ => Err(CollectorError::UnsupportedAction(format!("logs_windows action {} not implemented", action)))
        }
    }
}