//! JOCKY Core — Execution Contract Module

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::TargetSpec;

/// Execution Contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContract {
    pub ir_id: String,
    pub run_id: String,
    pub target: TargetSpec,
    pub steps: Vec<ExecStep>,
    pub policy: ExecPolicy,
    pub context: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Execution Step (resolved from IR)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecStep {
    pub step_id: String,
    pub collector: String,
    pub action: String,
    pub params: serde_json::Value,
    pub output_vars: Vec<String>,
    pub timeout_ms: u64,
    pub retry: RetryPolicy,
}

/// Retry Policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 1,
            backoff_ms: 1000,
        }
    }
}

/// Execution Policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecPolicy {
    pub parallelism: u32,
    pub continue_on_error: bool,
    pub evidence_root: String,
    pub hash_algorithm: String,
}

impl Default for ExecPolicy {
    fn default() -> Self {
        Self {
            parallelism: 2,
            continue_on_error: false,
            evidence_root: "./evidence".to_string(),
            hash_algorithm: "sha256".to_string(),
        }
    }
}

/// Execution Policy builder
impl ExecPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_parallelism(mut self, parallelism: u32) -> Self {
        self.parallelism = parallelism.clamp(1, 16);
        self
    }

    pub fn with_evidence_root(mut self, root: impl Into<String>) -> Self {
        self.evidence_root = root.into();
        self
    }

    pub fn with_hash_algorithm(mut self, algo: impl Into<String>) -> Self {
        let algo = algo.into();
        assert!(algo == "sha256" || algo == "blake3");
        self.hash_algorithm = algo;
        self
    }
}

/// Contract build error
#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("Unsupported OS: {0}")]
    UnsupportedOS(String),

    #[error("Collector not found: {0}")]
    CollectorNotFound(String),

    #[error("Action not supported: {0}")]
    ActionNotSupported(String),

    #[error("Parameter validation failed: {0}")]
    ParamValidationFailed(String),

    #[error("Capability denied: {0}")]
    CapabilityDenied(String),

    #[error("Invalid timeout: {0}")]
    InvalidTimeout(String),

    #[error("Invalid evidence root: {0}")]
    InvalidEvidenceRoot(String),

    #[error("Cyclic dependency: {0}")]
    CyclicDependency(String),

    #[error("Missing dependency: {0}")]
    MissingDependency(String),

    #[error("Hash algorithm unsupported: {0}")]
    HashAlgoUnsupported(String),
}

/// Build execution contract from IR
pub fn build_contract(
    ir: &crate::ir::IrModule,
    target: crate::TargetSpec,
    policy: ExecPolicy,
) -> Result<ExecutionContract, ContractError> {
    // Validate target OS
    validate_target(&target)?;

    // Resolve collectors for each step
    let mut exec_steps = Vec::new();
    for step in &ir.steps {
        let exec_step = resolve_step(step)?;
        exec_steps.push(exec_step);
    }

    // Validate policy bounds
    if policy.parallelism < 1 || policy.parallelism > 16 {
        return Err(ContractError::InvalidTimeout("Parallelism must be 1-16".to_string()));
    }

    if policy.hash_algorithm != "blake3" && policy.hash_algorithm != "sha256" {
        return Err(ContractError::HashAlgoUnsupported(policy.hash_algorithm.clone()));
    }

    // Validate dependencies
    validate_dependencies(&ir.steps)?;

    Ok(ExecutionContract {
        ir_id: ir.id.clone(),
        run_id: ulid::Ulid::new().to_string(),
        target,
        steps: exec_steps,
        policy,
        context: serde_json::json!({}),
        created_at: chrono::Utc::now(),
    })
}

fn validate_target(target: &TargetSpec) -> Result<(), ContractError> {
    // Basic target validation
    if target.identifier.is_empty() {
        return Err(ContractError::InvalidEvidenceRoot("Target identifier cannot be empty".to_string()));
    }
    Ok(())
}

fn resolve_step(step: &crate::ir::IRStep) -> Result<ExecStep, ContractError> {
    // Validate collector exists and supports action
    // In a real implementation, this would check against collector registry
    if step.collector.is_empty() {
        return Err(ContractError::CollectorNotFound(step.collector.clone()));
    }

    Ok(ExecStep {
        step_id: step.id.clone(),
        collector: step.collector.clone(),
        action: step.action.clone(),
        params: step.params.clone(),
        output_vars: step.binds.clone(),
        timeout_ms: 30000,
        retry: Default::default(),
    })
}

fn validate_dependencies(steps: &[crate::ir::IRStep]) -> Result<(), ContractError> {
    let mut step_ids = std::collections::HashSet::new();
    for step in steps {
        if !step_ids.insert(step.id.clone()) {
            return Err(ContractError::CyclicDependency("Duplicate step ID".to_string()));
        }
    }

    // Check all dependencies exist
    let step_ids: std::collections::HashSet<_> = steps.iter().map(|s| s.id.clone()).collect();
    for step in steps {
        for dep in &step.depends_on {
            if !step_ids.contains(dep) {
                return Err(ContractError::MissingDependency(dep.clone()));
            }
        }
    }

    // Check for cycles using simple topological sort
    let mut graph = petgraph::Graph::new();
    let mut node_map = std::collections::HashMap::new();

    for step in steps {
        let idx = graph.add_node(step.id.clone());
        node_map.insert(step.id.clone(), idx);
    }

    for step in steps {
        let from = node_map[&step.id];
        for dep_id in &step.depends_on {
            let to = node_map[dep_id];
            graph.add_edge(to, from, ());
        }
    }

    if petgraph::algo::toposort(&graph, None).is_err() {
        return Err(ContractError::CyclicDependency("Cyclic dependency detected".to_string()));
    }

    Ok(())
}