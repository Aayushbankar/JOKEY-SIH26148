//! JOCKY Core — Policy Engine Module

use crate::contract::{ExecPolicy, ContractError};
use crate::collector::CollectorManifest;
use crate::TargetSpec;
use std::collections::HashMap;

/// Policy Engine
pub struct PolicyEngine {
    collector_manifests: HashMap<String, CollectorManifest>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            collector_manifests: HashMap::new(),
        }
    }
    
    pub fn register_collector(&mut self, manifest: CollectorManifest) {
        self.collector_manifests.insert(manifest.name.clone(), manifest);
    }
    
    pub fn validate_contract(
        &self,
        contract: &crate::contract::ExecutionContract,
    ) -> Result<(), ContractError> {
        // Validate each step
        for step in &contract.steps {
            self.validate_step(step, &contract.target)?;
        }
        
        // Validate policy bounds
        if contract.policy.parallelism < 1 || contract.policy.parallelism > 16 {
            return Err(ContractError::InvalidTimeout(
                "Parallelism must be 1-16".to_string()
            ));
        }
        
        if contract.policy.hash_algorithm != "blake3" && contract.policy.hash_algorithm != "sha256" {
            return Err(ContractError::HashAlgoUnsupported(
                contract.policy.hash_algorithm.clone()
            ));
        }
        
        Ok(())
    }
    
    fn validate_step(&self, step: &crate::contract::ExecStep, target: &TargetSpec) -> Result<(), ContractError> {
        // Check collector exists
        let manifest = self.collector_manifests.get(&step.collector)
            .ok_or(crate::contract::ContractError::CollectorNotFound(step.collector.clone()))?;
        
        // Check OS compatibility
        if !manifest.supported_os.contains(&target.os) {
            return Err(crate::contract::ContractError::UnsupportedOS(format!(
                "Collector {} does not support OS: {}", step.collector, target.os
            )));
        }
        
        // Check action supported
        if !manifest.actions.contains_key(&step.action) {
            return Err(crate::contract::ContractError::ActionNotSupported(step.action.clone()));
        }
        
        // Validate parameters against schema
        let action_manifest = &manifest.actions[&step.action];
        // In a real implementation, validate JSON against schema
        
        // Check capabilities
        let required_caps = manifest.actions[&step.action].capabilities.clone();
        let available_caps = manifest.capabilities.clone();
        
        for cap in required_caps {
            if !available_caps.contains(&cap) {
                return Err(crate::contract::ContractError::CapabilityDenied(
                    format!("Missing capability: {}", cap)
                ));
            }
        }
        
        // Check timeout bounds
        if step.timeout_ms < 1000 || step.timeout_ms > 300000 {
            return Err(crate::contract::ContractError::InvalidTimeout(
                "Timeout must be 1000-300000 ms".to_string()
            ));
        }
        
        Ok(())
    }
}