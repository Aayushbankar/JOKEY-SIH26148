//! JOCKY Runtime — Collector Registry

use jockey_collectors::{Collector, CollectorManifest, ActionManifest};
use std::collections::HashMap;
use std::sync::Arc;

/// Collector Registry
#[derive(Clone)]
pub struct CollectorRegistry {
    collectors: HashMap<String, Arc<dyn Collector>>,
    manifests: HashMap<String, CollectorManifest>,
}

impl CollectorRegistry {
    /// Create a new empty CollectorRegistry
    pub fn new() -> Self {
        Self {
            collectors: HashMap::new(),
            manifests: HashMap::new(),
        }
    }

    /// Register a collector in the registry
    pub fn register(&mut self, collector: Arc<dyn Collector>) -> Result<(), RegistryError> {
        let name = collector.name().to_string();
        
        if self.collectors.contains_key(&name) {
            return Err(RegistryError::AlreadyRegistered(name));
        }

        // Create manifest from collector
        let manifest = CollectorManifest {
            name: name.clone(),
            version: collector.version().to_string(),
            supported_os: collector.supported_os().iter().map(|s| s.to_string()).collect(),
            capabilities: collector.supported_actions().iter()
                .flat_map(|action| self.infer_capabilities(action))
                .collect(),
            actions: collector.supported_actions().iter()
                .map(|action| (action.to_string(), ActionManifest {
                    capabilities: self.infer_capabilities(action),
                    params_schema: serde_json::json!({}),
                    description: format!("Action {}", action),
                }))
                .collect(),
            public_key: String::new(), // Would be populated from keypair
        };

        self.manifests.insert(name.clone(), manifest);
        self.collectors.insert(name, collector);
        
        Ok(())
    }

    fn infer_capabilities(&self, action: &str) -> Vec<String> {
        match action {
            "list" | "enumerate" => vec!["ProcessEnumerate".to_string(), "FileEnumerate".to_string()],
            "get" => vec!["ProcessGet".to_string()],
            "tree" => vec!["ProcessTree".to_string()],
            "query" => vec!["LogQuery".to_string()],
            "export" => vec!["LogExport".to_string()],
            "tail" => vec!["LogTail".to_string()],
            "connections" => vec!["NetworkConnections".to_string()],
            "listen" => vec!["NetworkListen".to_string()],
            "capture" => vec!["NetworkCapture".to_string()],
            "resolve" => vec!["NetworkResolve".to_string()],
            _ => vec![],
        }
    }

    /// Look up a collector by name
    pub fn get(&self, name: &str) -> Option<Arc<dyn Collector>> {
        self.collectors.get(name).cloned()
    }

    /// Look up collector manifest by name
    pub fn get_manifest(&self, name: &str) -> Option<&CollectorManifest> {
        self.manifests.get(name)
    }

    /// Retrieve all collectors supporting the given operating system
    pub fn get_for_os(&self, os: &str) -> Vec<&dyn Collector> {
        self.collectors.values()
            .filter(|c| c.supported_os().iter().any(|s| *s == os))
            .map(|c| c.as_ref())
            .collect()
    }

    /// Retrieve all registered collectors
    pub fn get_all(&self) -> Vec<&dyn Collector> {
        self.collectors.values().map(|c| c.as_ref()).collect()
    }
}

impl Default for CollectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Registry error types
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// Collector with the same name already registered
    #[error("Collector already registered: {0}")]
    AlreadyRegistered(String),
    /// Collector not found
    #[error("Collector not found: {0}")]
    NotFound(String),
    /// Invalid collector manifest
    #[error("Invalid manifest: {0}")]
    InvalidManifest(String),
}