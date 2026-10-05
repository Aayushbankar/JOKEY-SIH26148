//! JOCKY AST — Abstract Syntax Tree definitions

use std::collections::HashMap;
use std::fmt;
use serde::{Deserialize, Serialize};
use crate::span::Span;

/// Top-level AST module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstModule {
    pub name: String,
    pub statements: Vec<Statement>,
    pub span: Span,
}

/// All possible statements in JOCKY
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Statement {
    Hypothesis(HypothesisDecl),
    Collect(CollectDecl),
    Filter(FilterDecl),
    Match(MatchDecl),
    Correlate(CorrelateDecl),
    Timeline(TimelineDecl),
    Bind(BindDecl),
    Export(ExportDecl),
    Verify(VerifyDecl),
}

/// Hypothesis declaration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisDecl {
    pub description: String,
    pub mitre_tags: Vec<String>,
    pub span: Span,
}

/// Evidence type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    Process,
    File,
    Registry,
    Config,
    Logs,
    Network,
}

/// Collect declaration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectDecl {
    pub evidence_type: EvidenceType,
    pub binding: String,
    pub filter: Option<Expression>,
    pub span: Span,
}

/// Filter declaration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterDecl {
    pub source: String,
    pub filter: Expression,
    pub span: Span,
}

/// Match declaration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchDecl {
    pub source: String,
    pub pattern: Expression,
    pub span: Span,
}

/// Correlation declaration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelateDecl {
    pub source: String,
    pub target: String,
    pub relation: String,
    pub binding: String,
    pub params: CorrelationParams,
    pub span: Span,
}

/// Correlation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationParams {
    pub window: Option<Duration>,
}

/// Duration with unit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Duration {
    pub value: u64,
    pub unit: TimeUnit,
}

/// Time units
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeUnit {
    Seconds,
    Minutes,
    Hours,
}

/// Timeline declaration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineDecl {
    pub name: String,
    pub sources: Vec<String>,
    pub span: Span,
}

/// Bind declaration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindDecl {
    pub hypothesis: String,
    pub evidence_bindings: Vec<String>,
    pub span: Span,
}

/// Export declaration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportDecl {
    pub output_type: OutputType,
    pub name: String,
    pub format: ExportFormat,
    pub span: Span,
}

/// Output types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputType {
    Case,
    Graph,
    Timeline,
    Report,
}

/// Export formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    CaseUco,
    Cytoscape,
    Timesketch,
    Markdown,
    Graphml,
    Dot,
}

/// Verify declaration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyDecl {
    pub target: String,
    pub span: Span,
}

/// Evidence types for capability inference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceTypeForCap {
    Process,
    File,
    Registry,
    Config,
    Logs,
    Network,
}

/// Capabilities inferred from collect statements
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    ProcessEnumerate,
    ProcessGet,
    ProcessTree,
    FileEnumerate,
    FileHash,
    FileCollect,
    RegistryEnumerate,
    RegistryGet,
    RegistryMonitor,
    LogQuery,
    LogExport,
    LogTail,
    NetworkConnections,
    NetworkListen,
    NetworkCapture,
    NetworkResolve,
    ConfigEnumerate,
}

/// Expression AST nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expression {
    Binary(BinaryExpr),
    Unary(UnaryExpr),
    Literal(Literal),
    Identifier(String),
}

/// Binary expression
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryExpr {
    pub left: Box<Expression>,
    pub operator: BinaryOp,
    pub right: Box<Expression>,
    pub span: Span,
}

/// Binary operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryOp {
    Eq,
    Neq,
    Gt,
    Lt,
    Gte,
    Lte,
    Contains,
    Matches,
    In,
    And,
    Or,
}

/// Unary expression
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnaryExpr {
    pub operator: UnaryOp,
    pub operand: Box<Expression>,
    pub span: Span,
}

/// Unary operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOp {
    Not,
    Neg,
}

/// Literal values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Literal {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Array(Vec<Literal>),
}

/// Typed AST after type checking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedAst {
    pub module: AstModule,
    pub capabilities: Vec<Capability>,
    pub symbol_table: SymbolTable,
}

/// Symbol table for type checking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolTable {
    pub bindings: HashMap<String, BindingInfo>,
    pub hypotheses: HashMap<String, HypothesisInfo>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
            hypotheses: HashMap::new(),
        }
    }
}

/// Binding information in symbol table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingInfo {
    pub name: String,
    pub evidence_type: EvidenceType,
    pub inferred_capabilities: Vec<Capability>,
}

/// Hypothesis information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisInfo {
    pub description: String,
    pub mitre_tags: Vec<String>,
    pub bound_evidence: Vec<String>,
}

/// Error codes for type checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeErrorCode {
    UndefinedBinding,
    TypeMismatch,
    InvalidCorrelation,
    MissingCapability,
    CircularDependency,
    DuplicateBinding,
}

/// Type error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeError {
    pub message: String,
    pub span: Span,
    pub code: TypeErrorCode,
}

/// Type checking errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseError {
    pub message: String,
    pub span: Span,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Parse error at {}: {}", self.span, self.message)
    }
}

impl std::error::Error for ParseError {}

impl fmt::Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Type error at {}: {}", self.span, self.message)
    }
}

impl std::error::Error for TypeError {}