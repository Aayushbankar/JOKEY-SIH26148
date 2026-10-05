//! JOCKY Runtime — Executor

use jockey_core::contract::{ExecutionContract, ExecStep};
use crate::collector_registry::CollectorRegistry;
use jockey_collectors::{ExecutionContext, CollectorError};
use jockey_evidence::model::Evidence;
use jockey_evidence::receipt::{CollectorKeypair, EvidenceReceipt, HostInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use petgraph::graph::DiGraph;
use petgraph::algo::toposort;

/// Executor
pub struct Executor {
    registry: Arc<CollectorRegistry>,
    keypairs: HashMap<String, Arc<CollectorKeypair>>,
}

impl Executor {
    /// Create a new Executor with the given collector registry
    pub fn new(registry: &CollectorRegistry) -> Self {
        let mut keypairs = HashMap::new();
        
        // Generate keypairs for each registered collector
        for collector in registry.get_all() {
            let keypair = Arc::new(CollectorKeypair::generate());
            keypairs.insert(collector.name().to_string(), keypair);
        }
        
        Self {
            registry: Arc::new(registry.clone()),
            keypairs,
        }
    }

    /// Execute a contract
    pub async fn execute(&self, contract: ExecutionContract) -> Result<ExecutionResult, RuntimeError> {
        let start_time = Instant::now();
        let mut evidence_collected = 0;
        let mut receipts_generated = 0;
        let mut errors = Vec::new();
        
        // Create evidence root directory
        std::fs::create_dir_all(&contract.policy.evidence_root)
            .map_err(|e| RuntimeError::StorageError(e.to_string()))?;

        // Plan execution (topological sort)
        let groups = self.build_execution_groups(&contract.steps)?;
        
        // Create execution context
        let context = ExecutionContext {
            run_id: contract.run_id.clone(),
            evidence_root: std::path::PathBuf::from(&contract.policy.evidence_root),
            target: contract.target.clone(),
            temp_dir: std::env::temp_dir().join(&contract.run_id),
            credentials: Some(contract.context.clone()),
        };

        // Create semaphore for parallelism control
        let semaphore = Arc::new(tokio::sync::Semaphore::new(contract.policy.parallelism as usize));
        
        // Execute steps in topological order with parallelism
        for group in groups {
            let mut handles = Vec::new();
            
            for step in group {
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let collector = self.registry.get(&step.collector)
                    .ok_or_else(|| RuntimeError::CollectorNotFound(step.collector.clone()))?;
                
                let keypair = self.keypairs.get(&step.collector).cloned();
                let context = context.clone();
                let step_clone = step.clone();
                
                let handle = tokio::spawn(async move {
                    let _permit = permit; // Hold permit until task completes
                    
                    let collector_clone = collector.clone();
                    let keypair = keypair.clone();
                    
                    let result = collector_clone.execute(
                        &step_clone.action,
                        step_clone.params.clone(),
                        &context,
                    ).await;
                    
                    (step_clone.step_id, result, keypair)
                });
                
                handles.push(handle);
            }
            
            // Wait for all steps in group
            for handle in handles {
                match handle.await {
                    Ok((step_id, result, keypair)) => {
                        match result {
                            Ok(output) => {
                                // Generate receipts for evidence
                                for evidence in &output.evidence {
                                    if let Some(keypair) = &keypair {
                                        // Generate receipt
                                        let _ = self.generate_receipt(evidence, keypair.clone());
                                    }
                                }
                                
                                evidence_collected += output.evidence.len();
                                receipts_generated += output.evidence.len();
                            }
                            Err(e) => {
                                errors.push(format!("Step {} failed: {}", step_id, e));
                            }
                        }
                    }
                    Err(e) => {
                        errors.push(format!("Task join error: {}", e));
                    }
                }
            }
        }
        
        let duration_ms = start_time.elapsed().as_millis() as u64;
        
        let status = if errors.is_empty() {
            ExecutionStatus::Success
        } else if evidence_collected > 0 {
            ExecutionStatus::Partial
        } else {
            ExecutionStatus::Failed
        };
        
        Ok(ExecutionResult {
            run_id: contract.run_id.clone(),
            status,
            evidence_collected,
            receipts_generated,
            provenance_records: 0, // TODO
            findings: 0, // TODO
            duration_ms,
            errors,
        })
    }
    
    fn build_execution_groups(&self, steps: &[ExecStep]) -> Result<Vec<Vec<ExecStep>>, RuntimeError> {
        // Build dependency graph
        let mut graph = DiGraph::new();
        let mut node_map = HashMap::new();
        
        for step in steps {
            let idx = graph.add_node(step.clone());
            node_map.insert(step.step_id.clone(), idx);
        }
        
        for step in steps {
            let from = node_map[&step.step_id];
            for dep_id in &step.depends_on {
                let to = node_map.get(dep_id)
                    .copied()
                    .ok_or_else(|| RuntimeError::ContractValidation(format!("Unknown dependency: {}", dep_id)))?;
                // In petgraph toposort, edge (to -> from) ensures dependency 'to' is ordered before 'from'
                graph.add_edge(to, from, ());
            }
        }
        
        // Topological sort
        let sorted = toposort(&graph, None)
            .map_err(|_| RuntimeError::ContractValidation("Cyclic dependency detected".to_string()))?;
        
        // Group by level (steps that can run in parallel)
        let mut groups: Vec<Vec<ExecStep>> = Vec::new();
        let mut completed = HashSet::new();
        
        for node_idx in sorted {
            let step = &graph[node_idx];
            
            if step.depends_on.iter().all(|d| completed.contains(d)) {
                if let Some(last_group) = groups.last_mut() {
                    if last_group.len() < 16 { // Max parallelism
                        last_group.push(step.clone());
                    } else {
                        groups.push(vec![step.clone()]);
                    }
                } else {
                    groups.push(vec![step.clone()]);
                }
                completed.insert(step.step_id.clone());
            } else {
                // This shouldn't happen with proper topological sort
                groups.push(vec![step.clone()]);
                completed.insert(step.step_id.clone());
            }
        }
        
        Ok(groups)
    }
    
    fn generate_receipt(&self, evidence: &Evidence, keypair: Arc<CollectorKeypair>) -> Result<EvidenceReceipt, RuntimeError> {
        let host_info = HostInfo {
            hostname: "localhost".to_string(), // Simplified - would use hostname crate in real impl
            os: std::env::consts::OS.to_string(),
            kernel: None,
            collector_pid: std::process::id(),
        };
        
        let receipt = EvidenceReceipt::new(
            evidence,
            &evidence.collector,
            "0.1.0",
            &keypair,
            host_info,
        );
        
        Ok(receipt)
    }
}

/// Execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Unique run identifier
    pub run_id: String,
    /// Execution status outcome
    pub status: ExecutionStatus,
    /// Count of evidence items collected
    pub evidence_collected: usize,
    /// Count of receipts generated
    pub receipts_generated: usize,
    /// Count of provenance records created
    pub provenance_records: usize,
    /// Count of findings identified
    pub findings: usize,
    /// Total execution duration in milliseconds
    pub duration_ms: u64,
    /// Errors encountered during execution
    pub errors: Vec<String>,
}

/// Execution status outcome
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    /// All steps completed successfully
    Success,
    /// Some steps failed but partial evidence was collected
    Partial,
    /// Execution failed completely
    Failed,
}

/// Runtime error types
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// Contract validation error
    #[error("Contract validation failed: {0}")]
    ContractValidation(String),
    /// Collector execution error
    #[error("Collector error: {0}")]
    CollectorError(#[from] CollectorError),
    /// Evidence storage error
    #[error("Evidence storage error: {0}")]
    StorageError(String),
    /// Specified collector not found in registry
    #[error("Collector not found: {0}")]
    CollectorNotFound(String),
    /// Execution policy violation
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_step(id: &str, deps: Vec<&str>) -> ExecStep {
        ExecStep {
            step_id: id.to_string(),
            collector: "test_collector".to_string(),
            action: "collect".to_string(),
            params: serde_json::json!({}),
            output_vars: vec![],
            depends_on: deps.into_iter().map(String::from).collect(),
            timeout_ms: 5000,
            retry: jockey_core::contract::RetryPolicy::default(),
        }
    }

    #[test]
    fn test_build_execution_groups_topological_order() {
        let registry = CollectorRegistry::new();
        let executor = Executor::new(&registry);

        let s1 = make_step("step1", vec![]);
        let s2 = make_step("step2", vec!["step1"]);
        let s3 = make_step("step3", vec!["step2"]);

        // Pass out of order
        let steps = vec![s3, s1, s2];
        let groups = executor.build_execution_groups(&steps).expect("toposort should succeed");

        let flat: Vec<String> = groups.into_iter().flatten().map(|s| s.step_id).collect();
        let pos1 = flat.iter().position(|x| x == "step1").unwrap();
        let pos2 = flat.iter().position(|x| x == "step2").unwrap();
        let pos3 = flat.iter().position(|x| x == "step3").unwrap();

        assert!(pos1 < pos2);
        assert!(pos2 < pos3);
    }

    #[test]
    fn test_build_execution_groups_cycle_detection() {
        let registry = CollectorRegistry::new();
        let executor = Executor::new(&registry);

        let s1 = make_step("step1", vec!["step2"]);
        let s2 = make_step("step2", vec!["step1"]);

        let res = executor.build_execution_groups(&[s1, s2]);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Cyclic dependency"));
    }

    #[test]
    fn test_build_execution_groups_missing_dependency() {
        let registry = CollectorRegistry::new();
        let executor = Executor::new(&registry);

        let s1 = make_step("step1", vec!["nonexistent"]);
        let res = executor.build_execution_groups(&[s1]);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Unknown dependency: nonexistent"));
    }
}