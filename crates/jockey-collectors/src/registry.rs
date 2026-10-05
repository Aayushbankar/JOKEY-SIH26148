//! Collector Registry module
//!
//! Manages registration, discovery, and lookup of artifact collectors.

use std::collections::HashMap;
use crate::trait_def::*;

/// Collector Manifest describing collector capabilities
#[derive(Debug, Clone)]
pub struct CollectorManifest {
    /// Collector name
    pub name: String,
    /// Semantic version
    pub version: String,
    /// Supported operating systems
    pub supported_os: Vec<String>,
    /// Security capabilities required
    pub capabilities: Vec<String>,
    /// Actions exposed by this collector
    pub actions: HashMap<String, ActionManifest>,
    /// Ed25519 public key hex for receipt verification
    pub public_key: String,
}

/// Action Manifest describing an action's schema and capabilities
#[derive(Debug, Clone)]
pub struct ActionManifest {
    /// Capabilities required to invoke this action
    pub capabilities: Vec<String>,
    /// JSON schema for parameters
    pub params_schema: serde_json::Value,
    /// Description of action
    pub description: String,
}

/// Collector Registry for managing active collectors
pub struct CollectorRegistry {
    collectors: HashMap<String, Box<dyn Collector>>,
    manifests: HashMap<String, CollectorManifest>,
}

impl CollectorRegistry {
    /// Create a new empty collector registry
    pub fn new() -> Self {
        Self {
            collectors: HashMap::new(),
            manifests: HashMap::new(),
        }
    }

    /// Register a collector instance
    pub fn register(&mut self, collector: Box<dyn Collector>) -> Result<(), RegistryError> {
        let name = collector.name().to_string();
        if self.collectors.contains_key(&name) {
            return Err(RegistryError::AlreadyRegistered(name));
        }
        self.collectors.insert(name, collector);
        Ok(())
    }

    /// Register a collector manifest
    pub fn register_manifest(&mut self, manifest: CollectorManifest) -> Result<(), RegistryError> {
        self.manifests.insert(manifest.name.clone(), manifest);
        Ok(())
    }

    /// Lookup a collector by name
    pub fn get(&self, name: &str) -> Option<&dyn Collector> {
        self.collectors.get(name).map(|c| c.as_ref())
    }

    /// Lookup all collectors supporting a specific operating system
    pub fn get_for_os(&self, os: &str) -> Vec<&dyn Collector> {
        self.collectors
            .values()
            .filter(|c| c.supported_os().contains(&os))
            .map(|c| c.as_ref())
            .collect()
    }

    /// Lookup a collector manifest by name
    pub fn get_manifest(&self, name: &str) -> Option<&CollectorManifest> {
        self.manifests.get(name)
    }
}

impl Default for CollectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors returned by collector registry operations
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// Collector with the same name is already registered
    #[error("collector already registered: {0}")]
    AlreadyRegistered(String),
    /// Collector was not found
    #[error("collector not found: {0}")]
    NotFound(String),
    /// Manifest validation failed
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
}
