//! JOCKY Type Checker — Semantic validation and capability inference

use crate::ast::*;
use crate::span::{Span, HasSpan};
use std::collections::HashMap;

/// Type check AST and infer capabilities
pub fn type_check(ast: &AstModule) -> Result<TypedAst, TypeError> {
    let mut symbol_table = SymbolTable::new();
    let mut capabilities = Vec::new();
    
    // First pass: collect all bindings and hypotheses
    for stmt in &ast.statements {
        match stmt {
            Statement::Collect(decl) => {
                // Check for duplicate binding
                if symbol_table.bindings.contains_key(&decl.binding) {
                    return Err(TypeError {
                        message: format!("Duplicate binding: {}", decl.binding),
                        span: decl.span,
                        code: TypeErrorCode::DuplicateBinding,
                    });
                }
                
                // Infer capabilities
                let inferred = infer_capabilities(&decl.evidence_type, &decl.filter);
                capabilities.extend(inferred.clone());
                
                symbol_table.bindings.insert(decl.binding.clone(), BindingInfo {
                    name: decl.binding.clone(),
                    evidence_type: decl.evidence_type,
                    inferred_capabilities: inferred,
                });
            }
            Statement::Hypothesis(decl) => {
                if symbol_table.hypotheses.contains_key(&decl.description) {
                    return Err(TypeError {
                        message: format!("Duplicate hypothesis: {}", decl.description),
                        span: decl.span,
                        code: TypeErrorCode::DuplicateBinding,
                    });
                }
                symbol_table.hypotheses.insert(decl.description.clone(), HypothesisInfo {
                    description: decl.description.clone(),
                    mitre_tags: decl.mitre_tags.clone(),
                    bound_evidence: Vec::new(),
                });
            }
            _ => {}
        }
    }
    
    // Second pass: validate all references
    for stmt in &ast.statements {
        match stmt {
            Statement::Filter(decl) => {
                if !symbol_table.bindings.contains_key(&decl.source) {
                    return Err(TypeError {
                        message: format!("Undefined binding: {}", decl.source),
                        span: decl.span,
                        code: TypeErrorCode::UndefinedBinding,
                    });
                }
                // Validate filter expression
                validate_expression(&decl.filter, &symbol_table, decl.span)?;
            }
            Statement::Match(decl) => {
                if !symbol_table.bindings.contains_key(&decl.source) {
                    return Err(TypeError {
                        message: format!("Undefined binding: {}", decl.source),
                        span: decl.span,
                        code: TypeErrorCode::UndefinedBinding,
                    });
                }
                validate_expression(&decl.pattern, &symbol_table, decl.span)?;
            }
            Statement::Correlate(decl) => {
                if !symbol_table.bindings.contains_key(&decl.source) {
                    return Err(TypeError {
                        message: format!("Undefined source binding: {}", decl.source),
                        span: decl.span,
                        code: TypeErrorCode::UndefinedBinding,
                    });
                }
                if !symbol_table.bindings.contains_key(&decl.target) {
                    return Err(TypeError {
                        message: format!("Undefined target binding: {}", decl.target),
                        span: decl.span,
                        code: TypeErrorCode::UndefinedBinding,
                    });
                }
                // Validate correlation method
                validate_correlation_method(&decl.relation, decl.span)?;
                
                // Register correlation binding
                let source_info = symbol_table.bindings.get(&decl.source).unwrap().clone();
                let target_info = symbol_table.bindings.get(&decl.target).unwrap().clone();
                let mut inferred = source_info.inferred_capabilities;
                inferred.extend(target_info.inferred_capabilities);
                symbol_table.bindings.insert(decl.binding.clone(), BindingInfo {
                    name: decl.binding.clone(),
                    evidence_type: source_info.evidence_type,
                    inferred_capabilities: inferred,
                });
            }
            Statement::Timeline(decl) => {
                for src in &decl.sources {
                    if !symbol_table.bindings.contains_key(src) {
                        return Err(TypeError {
                            message: format!("Undefined timeline source: {}", src),
                            span: decl.span,
                            code: TypeErrorCode::UndefinedBinding,
                        });
                    }
                }
            }
            Statement::Bind(decl) => {
                if !symbol_table.hypotheses.contains_key(&decl.hypothesis) {
                    return Err(TypeError {
                        message: format!("Undefined hypothesis: {}", decl.hypothesis),
                        span: decl.span,
                        code: TypeErrorCode::UndefinedBinding,
                    });
                }
                for binding in &decl.evidence_bindings {
                    if !symbol_table.bindings.contains_key(binding) {
                        return Err(TypeError {
                            message: format!("Undefined evidence binding: {}", binding),
                            span: decl.span,
                            code: TypeErrorCode::UndefinedBinding,
                        });
                    }
                }
                // Update hypothesis info with bound evidence
                if let Some(hyp) = symbol_table.hypotheses.get_mut(&decl.hypothesis) {
                    hyp.bound_evidence.extend(decl.evidence_bindings.clone());
                }
            }
            Statement::Export(decl) => {
                // Export sources must exist (for case/graph/timeline)
                match decl.output_type {
                    OutputType::Case | OutputType::Graph | OutputType::Timeline => {
                        // These would reference specific steps/outputs
                        // For now just check the format is valid
                    }
                    OutputType::Report => {}
                }
            }
            Statement::Verify(decl) => {
                if decl.target != "all" && !symbol_table.bindings.contains_key(&decl.target) {
                    return Err(TypeError {
                        message: format!("Undefined verification target: {}", decl.target),
                        span: decl.span,
                        code: TypeErrorCode::UndefinedBinding,
                    });
                }
            }
            _ => {}
        }
    }
    
    // Check for circular dependencies (simplified)
    // This would be more complete in a full implementation
    
    Ok(TypedAst {
        module: ast.clone(),
        capabilities,
        symbol_table,
    })
}

/// Validate expression types and identifiers
fn validate_expression(expr: &Expression, symbol_table: &SymbolTable, span: Span) -> Result<(), TypeError> {
    match expr {
        Expression::Binary(bin) => {
            validate_expression(&bin.left, symbol_table, span)?;
            validate_expression(&bin.right, symbol_table, span)?;
        }
        Expression::Unary(unary) => {
            validate_expression(&unary.operand, symbol_table, span)?;
        }
        Expression::Identifier(name) => {
            // Check if identifier refers to a valid binding
            if !symbol_table.bindings.contains_key(name) {
                return Err(TypeError {
                    message: format!("Undefined identifier: {}", name),
                    span,
                    code: TypeErrorCode::UndefinedBinding,
                });
            }
        }
        Expression::Literal(_) => {}
    }
    Ok(())
}

/// Validate correlation method is known
fn validate_correlation_method(method: &str, span: Span) -> Result<(), TypeError> {
    const VALID_METHODS: &[&str] = &[
        "pid_link", "file_write", "file_read", "net_link", 
        "ioc_match", "yara_match", "sigma_match", "rule_match", "timestamp_join"
    ];
    
    if !VALID_METHODS.contains(&method) {
        return Err(TypeError {
            message: format!("Unknown correlation method: {}", method),
            span,
            code: TypeErrorCode::InvalidCorrelation,
        });
    }
    Ok(())
}

/// Infer capabilities from collect declaration
pub fn infer_capabilities(evidence_type: &EvidenceType, filter: &Option<Expression>) -> Vec<Capability> {
    let mut caps = Vec::new();
    
    match evidence_type {
        EvidenceType::Process => {
            caps.push(Capability::ProcessEnumerate);
            // Check if filtering by PID
            if let Some(filter) = filter {
                if has_pid_filter(filter) {
                    caps.push(Capability::ProcessGet);
                }
            }
        }
        EvidenceType::File => {
            caps.push(Capability::FileEnumerate);
            if filter.is_some() {
                caps.push(Capability::FileHash);
                caps.push(Capability::FileCollect);
            }
        }
        EvidenceType::Registry => {
            caps.push(Capability::RegistryEnumerate);
            caps.push(Capability::RegistryGet);
        }
        EvidenceType::Config => {
            caps.push(Capability::ConfigEnumerate);
        }
        EvidenceType::Logs => {
            caps.push(Capability::LogQuery);
            caps.push(Capability::LogExport);
        }
        EvidenceType::Network => {
            caps.push(Capability::NetworkConnections);
            caps.push(Capability::NetworkListen);
        }
    }
    caps
}

/// Check if expression contains PID filter
pub fn has_pid_filter(expr: &Expression) -> bool {
    match expr {
        Expression::Binary(bin) => {
            if let Expression::Identifier(name) = bin.left.as_ref() {
                if name == "pid" && matches!(bin.operator, BinaryOp::Eq) {
                    return true;
                }
            }
            has_pid_filter(&bin.left) || has_pid_filter(&bin.right)
        }
        Expression::Unary(unary) => has_pid_filter(&unary.operand),
        _ => false,
    }
}