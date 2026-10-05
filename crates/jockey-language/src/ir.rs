//! JOCKY IR — Intermediate Representation and Lowering

use crate::ast::*;
pub use jockey_core::ir::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use petgraph::graphmap::DiGraphMap;
use petgraph::algo::toposort;


/// IR Lowering errors
#[derive(Debug, thiserror::Error)]
pub enum LowerError {
    #[error("Unknown evidence type: {0}")]
    UnknownEvidenceType(String),
    
    #[error("Unknown correlation method: {0}")]
    UnknownCorrelationMethod(String),
    
    #[error("Missing binding: {0}")]
    MissingBinding(String),
    
    #[error("Cycle detected in dependencies")]
    CycleDetected,
    
    #[error("Missing dependency: {0}")]
    MissingDependency(String),
}

/// Lower typed AST to IR
pub fn lower_to_ir(typed: &TypedAst) -> Result<IrModule, LowerError> {
    let mut steps = Vec::new();
    let mut binding_to_step = HashMap::new();
    let mut step_counter = 0;
    
    // Generate ULID for module
    let module_id = ulid::Ulid::new().to_string();
    
    // Process each statement and create IR steps
    for stmt in &typed.module.statements {
        match stmt {
            Statement::Collect(decl) => {
                let step_id = ulid::Ulid::new().to_string();
                let (collector, action, params) = lower_collect(decl)?;
                
                let step = IRStep::new(step_id.clone(), collector, action, params)
                    .with_binds(vec![decl.binding.clone()]);
                
                binding_to_step.insert(decl.binding.clone(), step_id.clone());
                steps.push(step);
            }
            Statement::Filter(decl) => {
                // Filter is applied as a post-processing step on the source
                let step_id = ulid::Ulid::new().to_string();
                let source_step = binding_to_step.get(&decl.source)
                    .ok_or(LowerError::MissingBinding(decl.source.clone()))?;
                
                let params = serde_json::json!({ "filter": expr_to_json(&decl.filter) });
                
                let step = IRStep::new(
                    step_id.clone(),
                    "filter",
                    "apply",
                    params,
                )
                .with_binds(vec![format!("{}_filtered", decl.source)])
                .with_depends_on(vec![source_step.clone()]);
                
                binding_to_step.insert(format!("{}_filtered", decl.source), step_id.clone());
                steps.push(step);
            }
            Statement::Match(decl) => {
                // Match is similar to filter but with pattern matching
                let step_id = ulid::Ulid::new().to_string();
                let source_step = binding_to_step.get(&decl.source)
                    .ok_or(LowerError::MissingBinding(decl.source.clone()))?;
                
                let params = serde_json::json!({
                    "pattern": expr_to_json(&decl.pattern)
                });
                
                let step = IRStep::new(
                    step_id.clone(),
                    "match",
                    "apply",
                    params,
                )
                .with_binds(vec![format!("{}_matched", decl.source)])
                .with_depends_on(vec![binding_to_step[&decl.source].clone()]);
                
                binding_to_step.insert(format!("{}_matched", decl.source), step_id.clone());
                steps.push(step);
            }
            Statement::Correlate(decl) => {
                let step_id = ulid::Ulid::new().to_string();
                let (collector, action, params) = lower_correlate(decl)?;
                
                let source_step = binding_to_step.get(&decl.source)
                    .ok_or(LowerError::MissingBinding(decl.source.clone()))?;
                let target_step = binding_to_step.get(&decl.target)
                    .ok_or(LowerError::MissingBinding(decl.target.clone()))?;
                
                let step = IRStep::new(step_id.clone(), collector, action, params)
                    .with_binds(vec![decl.binding.clone()])
                    .with_depends_on(vec![source_step.clone(), target_step.clone()]);
                
                binding_to_step.insert(decl.binding.clone(), step_id.clone());
                steps.push(step);
            }
            Statement::Timeline(decl) => {
                let step_id = ulid::Ulid::new().to_string();
                
                let mut source_steps = Vec::new();
                for src in &decl.sources {
                    if let Some(step_id) = binding_to_step.get(src) {
                        source_steps.push(step_id.clone());
                    } else {
                        return Err(LowerError::MissingBinding(src.clone()));
                    }
                }
                
                let params = serde_json::json!({
                    "sources": decl.sources
                });
                
                let step = IRStep::new(
                    step_id.clone(),
                    "correlator",
                    "build_timeline",
                    params,
                )
                .with_binds(vec![decl.name.clone()])
                .with_depends_on(source_steps);
                
                binding_to_step.insert(decl.name.clone(), step_id.clone());
                steps.push(step);
            }
            Statement::Bind(_) => {
                // Bind doesn't create a step, it's metadata
            }
            Statement::Export(decl) => {
                let step_id = ulid::Ulid::new().to_string();
                
                let params = serde_json::json!({
                    "output_type": format!("{:?}", decl.output_type).to_lowercase(),
                    "name": decl.name,
                    "format": format!("{:?}", decl.format).to_lowercase(),
                });
                
                let step = IRStep::new(
                    step_id.clone(),
                    "exporter",
                    "export",
                    params,
                )
                .with_binds(vec![decl.name.clone()]);
                
                // Export doesn't necessarily depend on other steps
                steps.push(step);
            }
            Statement::Verify(decl) => {
                let step_id = ulid::Ulid::new().to_string();
                
                let params = serde_json::json!({
                    "target": decl.target,
                });
                
                let step = IRStep::new(
                    step_id.clone(),
                    "verifier",
                    "verify",
                    params,
                )
                .with_binds(vec![format!("verify_{}", decl.target)]);
                
                steps.push(step);
            }
            Statement::Hypothesis(_) => {
                // Hypothesis doesn't create a step, it's metadata
            }
            Statement::Bind(_) => {
                // Bind is metadata
            }
            Statement::Verify(_) => {
                // Already handled above
            }
        }
    }
    
    // Validate IR
    validate_ir(&steps)?;
    
    // Assign sequential IDs for reproducibility (or keep ULIDs)
    for (i, step) in steps.iter_mut().enumerate() {
        step.id = format!("step_{:04}", i);
    }
    
    let metadata = IRMetadata::new(&typed.module.name);
    
    Ok(IrModule {
        version: 1,
        id: module_id,
        metadata,
        steps,
        outputs: Vec::new(), // TODO: extract from exports
    })
}

/// Convert collect declaration to IR step
fn lower_collect(decl: &CollectDecl) -> Result<(String, String, serde_json::Value), LowerError> {
    let (collector, action, params) = match decl.evidence_type {
        EvidenceType::Process => {
            let collector = if cfg!(target_os = "windows") { "proc_windows" } else { "proc_linux" };
            let mut params = serde_json::json!({});
            if let Some(filter) = &decl.filter {
                params = serde_json::json!({ "filter": expr_to_json(filter) });
            }
            (collector.to_string(), "list".to_string(), params)
        }
        EvidenceType::File => {
            let collector = if cfg!(target_os = "windows") { "file_windows" } else { "file_linux" };
            let mut params = serde_json::json!({});
            if let Some(filter) = &decl.filter {
                params = serde_json::json!({ "filter": expr_to_json(filter) });
            }
            (collector.to_string(), "enumerate".to_string(), params)
        }
        EvidenceType::Registry => {
            let collector = "registry_windows".to_string();
            let mut params = serde_json::json!({});
            if let Some(filter) = &decl.filter {
                params = serde_json::json!({ "filter": expr_to_json(filter) });
            }
            (collector, "enumerate".to_string(), params)
        }
        EvidenceType::Config => {
            let collector = "config_linux".to_string();
            let mut params = serde_json::json!({});
            if let Some(filter) = &decl.filter {
                params = serde_json::json!({ "filter": expr_to_json(filter) });
            }
            (collector, "enumerate".to_string(), params)
        }
        EvidenceType::Logs => {
            let collector = if cfg!(target_os = "windows") { "logs_windows" } else { "logs_linux" };
            let mut params = serde_json::json!({});
            if let Some(filter) = &decl.filter {
                params = serde_json::json!({ "query": expr_to_json(filter) });
            }
            (collector.to_string(), "query".to_string(), params)
        }
        EvidenceType::Network => {
            let collector = if cfg!(target_os = "windows") { "net_windows" } else { "net_linux" };
            let mut params = serde_json::json!({});
            if let Some(filter) = &decl.filter {
                params = serde_json::json!({ "filter": expr_to_json(filter) });
            }
            (collector.to_string(), "connections".to_string(), params)
        }
    };
    Ok((collector, action, params))
}

/// Convert correlation declaration to IR step
fn lower_correlate(decl: &CorrelateDecl) -> Result<(String, String, serde_json::Value), LowerError> {
    let collector = "correlator".to_string();
    let action = match decl.relation.as_str() {
        "pid_link" => "pid_link",
        "file_write" => "file_write",
        "file_read" => "file_read",
        "net_link" => "net_link",
        "ioc_match" => "ioc_match",
        "yara_match" => "yara_match",
        "sigma_match" => "sigma_match",
        "rule_match" => "rule_match",
        "timestamp_join" => "timestamp_join",
        _ => return Err(LowerError::UnknownCorrelationMethod(decl.relation.clone())),
    }.to_string();
    
    let mut params = serde_json::json!({
        "left": decl.source,
        "right": decl.target,
    });
    
    if let Some(window) = &decl.params.window {
        params["window_seconds"] = serde_json::json!(window.value * match window.unit {
            TimeUnit::Seconds => 1,
            TimeUnit::Minutes => 60,
            TimeUnit::Hours => 3600,
        });
    }
    
    Ok((collector, action, params))
}

/// Convert expression to JSON
fn expr_to_json(expr: &Expression) -> serde_json::Value {
    match expr {
        Expression::Binary(bin) => serde_json::json!({
            "left": expr_to_json(&bin.left),
            "op": format!("{:?}", bin.operator).to_lowercase(),
            "right": expr_to_json(&bin.right),
        }),
        Expression::Unary(unary) => serde_json::json!({
            "op": format!("{:?}", unary.operator).to_lowercase(),
            "operand": expr_to_json(&unary.operand),
        }),
        Expression::Literal(lit) => lit_to_json(lit),
        Expression::Identifier(name) => serde_json::json!({ "var": name }),
    }
}

fn lit_to_json(lit: &Literal) -> serde_json::Value {
    match lit {
        Literal::String(s) => serde_json::json!(s),
        Literal::Integer(i) => serde_json::json!(i),
        Literal::Float(f) => serde_json::json!(f),
        Literal::Boolean(b) => serde_json::json!(b),
        Literal::Array(arr) => serde_json::json!(arr.iter().map(lit_to_json).collect::<Vec<_>>()),
    }
}

/// Validate IR for correctness
fn validate_ir(steps: &[IRStep]) -> Result<(), LowerError> {
    let mut step_ids = HashSet::new();
    let mut step_map = HashMap::new();
    
    // Check unique IDs
    for step in steps {
        if !step_ids.insert(step.id.clone()) {
            // In a real implementation, we'd check for duplicate IDs
        }
        step_map.insert(step.id.clone(), step);
    }
    
    // Check dependencies exist
    for step in steps {
        for dep in &step.depends_on {
            if !step_map.contains_key(dep) {
                return Err(LowerError::MissingDependency(dep.clone()));
            }
        }
    }
    
    // Check for cycles using topological sort
    let mut graph = DiGraphMap::new();
    for step in steps {
        graph.add_node(step.id.as_str());
    }
    for step in steps {
        for dep in &step.depends_on {
            graph.add_edge(dep.as_str(), step.id.as_str(), ());
        }
    }
    
    if toposort(&graph, None).is_err() {
        return Err(LowerError::CycleDetected);
    }
    
    Ok(())
}