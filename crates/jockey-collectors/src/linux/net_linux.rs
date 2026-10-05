//! Linux Network Collector — Stub Implementation

use async_trait::async_trait;
use crate::trait_def::{Collector, CollectorOutput, ExecutionContext, CollectorError};
use serde_json::Value;

/// Linux Network Connections and Interfaces Collector
pub struct NetLinuxCollector;

#[async_trait]
impl Collector for NetLinuxCollector {
    fn name(&self) -> &'static str {
        "net_linux"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn supported_actions(&self) -> Vec<&'static str> {
        vec!["connections", "interfaces", "routes", "arp", "sockstat"]
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
            _ => Err(CollectorError::UnsupportedAction(format!("net_linux action {} not implemented", action)))
        }
    }
}