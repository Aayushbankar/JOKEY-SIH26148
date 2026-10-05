//! JOCKY Language — Parser, AST, Type Checker, IR Lowering
//! 
//! Phase 1: Implementation of JOCKY language core.

#![warn(missing_docs)]
#![warn(clippy::all)]

/// Re-exports for public API
pub mod parser;
pub mod ast;
pub mod typeck;
pub mod ir;
pub mod diagnostics;
pub mod span;

/// Parse JOCKY source into AST
pub fn parse(source: &str) -> Result<ast::AstModule, crate::parser::ParseError> {
    crate::parser::parse(source)
}

/// Type check AST
pub fn type_check(ast: &ast::AstModule) -> Result<ast::TypedAst, ast::TypeError> {
    crate::typeck::type_check(ast)
}

/// Lower typed AST to IR
pub fn lower_to_ir(typed: &ast::TypedAst) -> Result<crate::ir::IrModule, crate::ir::LowerError> {
    crate::ir::lower_to_ir(typed)
}

/// Compile JOCKY source to IR
pub fn compile_to_ir(source: &str) -> Result<crate::ir::IrModule, CompileError> {
    let ast = parse(source)?;
    let typed = type_check(&ast)?;
    let ir = lower_to_ir(&typed)?;
    Ok(ir)
}

/// Compile JOCKY source to Execution Contract
pub fn compile_to_contract(source: &str, target: jockey_core::TargetSpec, policy: jockey_core::ExecPolicy) -> Result<jockey_core::ExecutionContract, CompileError> {
    let ir = compile_to_ir(source)?;
    let contract = jockey_core::build_contract(&ir, target, policy)?;
    Ok(contract)
}

/// Compile error type
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("Parse error: {0}")]
    Parse(#[from] crate::parser::ParseError),
    #[error("Type error: {0}")]
    Type(#[from] crate::ast::TypeError),
    #[error("IR lowering error: {0}")]
    Lower(#[from] crate::ir::LowerError),
    #[error("Contract build error: {0}")]
    Contract(#[from] jockey_core::ContractError),
}

#[cfg(test)]
mod tests;