//! Windows File Collector — Stub Implementation

use async_trait::async_trait;
use crate::trait_def::{Collector, CollectorOutput, ExecutionContext, CollectorError};
use serde_json::Value;

/// Windows File Collector
pub struct FileWindowsCollector;

#[async_trait]
impl Collector for FileWindowsCollector {
    fn name(&self) -> &'static str {
        "file_windows"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn supported_actions(&self) -> Vec<&'static str> {
        vec!["enumerate", "hash", "collect", "mft", "usn", "vss"]
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
            _ => Err(CollectorError::UnsupportedAction(format!("file_windows action {} not implemented", action)))
        }
    }
}