//! Linux Logs Collector — Stub Implementation

use async_trait::async_trait;
use crate::trait_def::{Collector, CollectorOutput, ExecutionContext, CollectorError};
use serde_json::Value;

/// Linux System Logs Collector
pub struct LogsLinuxCollector;

#[async_trait]
impl Collector for LogsLinuxCollector {
    fn name(&self) -> &'static str {
        "logs_linux"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn supported_actions(&self) -> Vec<&'static str> {
        vec!["syslog", "auth", "journalctl", "dmesg"]
    }

    fn supported_os(&self) -> Vec<&'static str> {
        vec!["linux"]
    }

    async fn execute(
        &self,
        action: &str,
        _params: Value,
        _context: &ExecutionContext,
    ) -> Result<CollectorOutput, CollectorError> {
        match action {
            _ => Err(CollectorError::UnsupportedAction(format!("logs_linux action {} not implemented", action)))
        }
    }
}