//! Windows Network Collector — Stub Implementation

use async_trait::async_trait;
use crate::trait_def::{Collector, CollectorOutput, ExecutionContext, CollectorError};
use serde_json::Value;

/// Windows Network Connections and Interfaces Collector
pub struct NetWindowsCollector;

#[async_trait]
impl Collector for NetWindowsCollector {
    fn name(&self) -> &'static str {
        "net_windows"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn supported_actions(&self) -> Vec<&'static str> {
        vec!["connections", "interfaces", "routes", "dns_cache", "arp"]
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
            _ => Err(CollectorError::UnsupportedAction(format!("net_windows action {} not implemented", action)))
        }
    }
}