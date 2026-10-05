//! Collector trait and execution context definitions
//!
//! Provides the core `Collector` trait, execution context, and output structures.

use async_trait::async_trait;
use serde_json::Value;
use std::path::PathBuf;

pub use jockey_core::TargetSpec;
use jockey_evidence::model::Evidence;

/// Core Collector trait implemented by all artifact collectors
#[async_trait]
pub trait Collector: Send + Sync {
    /// Unique name of the collector (e.g. "proc_windows", "proc_linux")
    fn name(&self) -> &'static str;
    /// Semantic version of the collector
    fn version(&self) -> &'static str;
    /// Actions supported by this collector
    fn supported_actions(&self) -> Vec<&'static str>;
    /// Target operating systems supported by this collector
    fn supported_os(&self) -> Vec<&'static str>;
    /// Execute a collection action
    async fn execute(
        &self,
        action: &str,
        params: Value,
        ctx: &ExecutionContext,
    ) -> Result<CollectorOutput, CollectorError>;
}

/// Execution Context passed to collectors during execution
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Unique execution run ID
    pub run_id: String,
    /// Root path for writing collected evidence artifacts
    pub evidence_root: PathBuf,
    /// Target specification (host, OS, arch)
    pub target: TargetSpec,
    /// Temporary directory for scratch work
    pub temp_dir: PathBuf,
    /// Optional credentials for privileged collection
    pub credentials: Option<Value>,
}

/// Output produced by a collector invocation
#[derive(Debug, Clone)]
pub struct CollectorOutput {
    /// Evidence records generated during execution
    pub evidence: Vec<Evidence>,
    /// Artifact references pointing to disk files
    pub artifacts: Vec<ArtifactRef>,
    /// Execution metrics (timing, bytes read/written, errors)
    pub metrics: CollectorMetrics,
}

/// Reference to a physical or logical artifact on disk
#[derive(Debug, Clone)]
pub struct ArtifactRef {
    /// Path relative to evidence root or absolute path
    pub path: String,
    /// MIME type or category of artifact
    pub type_: String,
    /// Human-readable description
    pub description: String,
}

/// Metrics collected during collector execution
#[derive(Debug, Clone, Default)]
pub struct CollectorMetrics {
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Number of bytes read
    pub bytes_read: u64,
    /// Number of bytes written to evidence files
    pub bytes_written: u64,
    /// Any non-fatal error messages encountered
    pub errors: Vec<String>,
}

/// Errors returned by collector operations
#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    /// Collector was not found in registry
    #[error("collector not found: {0}")]
    NotFound(String),
    /// Permission denied while collecting artifact
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    /// Invalid parameter supplied in action invocation
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
    /// Action timed out
    #[error("timeout")]
    Timeout,
    /// Internal collection failure
    #[error("internal error: {0}")]
    Internal(String),
    /// Requested action is not supported by this collector
    #[error("unsupported action: {0}")]
    UnsupportedAction(String),
    /// Target operating system is not supported
    #[error("unsupported OS: {0}")]
    UnsupportedOS(String),
    /// I/O error during collection
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization or deserialization error
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
