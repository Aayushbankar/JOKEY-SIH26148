//! Linux File Collector — File enumeration, hashing, and collection
//!
//! Collects file metadata and content by walking the filesystem.
//! Provides forensic metadata: path, size, hash, timestamps, permissions, etc.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::trait_def::{Collector, CollectorOutput, ExecutionContext, CollectorError, CollectorMetrics, ArtifactRef};
use jockey_evidence::model::{Evidence, EvidenceType};
use async_trait::async_trait;
use serde_json::{json, Value};
use ulid::Ulid;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use walkdir::WalkDir;

/// Linux File Collector
pub struct FileLinuxCollector {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    version: String,
    #[allow(dead_code)]
    keypair: Arc<jockey_evidence::receipt::CollectorKeypair>,
}

impl FileLinuxCollector {
    /// Create a new instance of FileLinuxCollector
    pub fn new(keypair: Arc<jockey_evidence::receipt::CollectorKeypair>) -> Self {
        Self {
            name: "file_linux".to_string(),
            version: "0.1.0".to_string(),
            keypair,
        }
    }

    /// Enumerate files in a directory
    async fn enumerate_files(
        &self,
        root_path: &Path,
        filter: Option<&Value>,
        _context: &ExecutionContext,
    ) -> Result<Vec<FileInfo>, CollectorError> {
        let mut files = Vec::new();

        #[cfg(target_os = "linux")]
        {
            if !root_path.exists() {
                return Err(CollectorError::InvalidParameter(format!("Path does not exist: {}", root_path.display())));
            }

            let max_depth = filter
                .and_then(|f| f.get("max_depth"))
                .and_then(|v| v.as_u64())
                .unwrap_or(10) as usize;

            let extensions = filter
                .and_then(|f| f.get("extensions"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let name_contains = filter
                .and_then(|f| f.get("name_contains"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_lowercase());

            let min_size = filter
                .and_then(|f| f.get("min_size"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let max_size = filter
                .and_then(|f| f.get("max_size"))
                .and_then(|v| v.as_u64())
                .unwrap_or(u64::MAX);

            for entry in WalkDir::new(root_path)
                .max_depth(max_depth)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }

                let path = entry.path();
                let metadata = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let size = metadata.len();
                if size < min_size || size > max_size {
                    continue;
                }

                let file_name = entry.file_name().to_string_lossy().to_string();
                if let Some(ref nc) = name_contains {
                    if !file_name.to_lowercase().contains(nc) {
                        continue;
                    }
                }

                if !extensions.is_empty() {
                    let ext = path.extension()
                        .and_then(|e| e.to_str())
                        .map(|s| format!(".{}", s))
                        .unwrap_or_default();
                    if !extensions.iter().any(|e| e == &ext) {
                        continue;
                    }
                }

                if let Some(info) = self.get_file_info(path, &metadata).await {
                    files.push(info);
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root_path, filter);
            // Mock implementation for non-Linux platforms (for testing)
            files.push(FileInfo {
                path: "/etc/passwd".to_string(),
                size: 1024,
                modified: Some(Utc::now() - Duration::from_secs(86400)),
                accessed: Some(Utc::now() - Duration::from_secs(3600)),
                permissions: Some("0644".to_string()),
                hash: Some("mock_hash".to_string()),
            });
        }

        Ok(files)
    }

    /// Get file metadata
    async fn get_file_info(&self, path: &Path, metadata: &fs::Metadata) -> Option<FileInfo> {
        let size = metadata.len();
        let modified = metadata.modified().ok().and_then(|t| self.system_time_to_datetime(t));
        let accessed = metadata.accessed().ok().and_then(|t| self.system_time_to_datetime(t));
        
        // Get permissions
        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::MetadataExt;
            Some(format!("{:o}", metadata.mode() & 0o777))
        };
        #[cfg(not(unix))]
        let permissions = None;

        // Compute hash (optional - can be skipped for enumeration)
        let hash = None;

        Some(FileInfo {
            path: path.to_string_lossy().to_string(),
            size,
            modified,
            accessed,
            permissions,
            hash,
        })
    }

    /// Compute SHA-256 hash of file
    async fn hash_file(&self, path: &Path) -> Result<String, CollectorError> {
        let content = fs::read(path)
            .map_err(|e| CollectorError::Internal(format!("Failed to read file: {}", e)))?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Collect file content and hash
    async fn collect_file(&self, path: &Path) -> Result<FileInfo, CollectorError> {
        let metadata = fs::metadata(path)
            .map_err(|e| CollectorError::Internal(format!("Failed to read metadata: {}", e)))?;

        let hash = self.hash_file(path).await?;
        let hash_clone = hash.clone();

        let info = self.get_file_info(path, &metadata).await.unwrap_or_else(|| FileInfo {
            path: path.to_string_lossy().to_string(),
            size: metadata.len(),
            modified: None,
            accessed: None,
            permissions: None,
            hash: Some(hash_clone),
        });

        Ok(FileInfo {
            hash: Some(hash),
            ..info
        })
    }

    /// Convert SystemTime to DateTime<Utc>
    fn system_time_to_datetime(&self, time: SystemTime) -> Option<DateTime<Utc>> {
        let duration = time.duration_since(SystemTime::UNIX_EPOCH).ok()?;
        let secs = duration.as_secs() as i64;
        let nanos = duration.subsec_nanos();
        DateTime::from_timestamp(secs, nanos)
    }
}

/// File metadata structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub permissions: Option<String>,
    pub hash: Option<String>,
}

#[async_trait]
impl Collector for FileLinuxCollector {
    fn name(&self) -> &'static str {
        "file_linux"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn supported_actions(&self) -> Vec<&'static str> {
        vec!["enumerate", "hash", "collect", "metadata"]
    }

    fn supported_os(&self) -> Vec<&'static str> {
        vec!["linux"]
    }

    async fn execute(
        &self,
        action: &str,
        params: Value,
        context: &ExecutionContext,
    ) -> Result<CollectorOutput, CollectorError> {
        let root_path = params
            .get("path")
            .and_then(|v| v.as_str())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));

        let filter = params.get("filter");

        match action {
            "enumerate" => {
                let files = self.enumerate_files(&root_path, filter, context).await?;
                
                let mut evidence_list = Vec::new();
                let mut artifacts = Vec::new();
                
                for file in files {
                    let evidence_id = Ulid::new().to_string();
                    let path = format!("evidence/{}.jsonl", evidence_id);
                    
                    let file_json = serde_json::to_string(&file)?;
                    let file_bytes = file_json.as_bytes();
                    
                    let evidence_path = context.evidence_root.join(&path);
                    if let Some(parent) = evidence_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&evidence_path, file_bytes)?;
                    
                    let mut hasher = Sha256::new();
                    hasher.update(file_bytes);
                    let hash = hex::encode(hasher.finalize());
                    
                    let evidence = Evidence::new(
                        context.run_id.clone(),
                        action.to_string(),
                        self.name.clone(),
                        EvidenceType::File,
                        format!("File: {}", file.path),
                        path.clone(),
                        file_bytes.len() as u64,
                        hash,
                        json!({
                            "path": file.path,
                            "size": file.size,
                            "modified": file.modified.map(|t| t.to_rfc3339()),
                            "accessed": file.accessed.map(|t| t.to_rfc3339()),
                            "permissions": file.permissions,
                            "hash": file.hash,
                        }),
                    );
                    
                    evidence_list.push(evidence);
                    
                    artifacts.push(ArtifactRef {
                        path,
                        type_: "artifact/file".to_string(),
                        description: format!("File metadata: {}", file.path),
                    });
                }
                
                Ok(CollectorOutput {
                    evidence: evidence_list,
                    artifacts,
                    metrics: CollectorMetrics {
                        duration_ms: 0,
                        bytes_read: 0,
                        bytes_written: 0,
                        errors: vec![],
                    },
                })
            }
            "hash" => {
                let file_path = params
                    .get("file")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .ok_or_else(|| CollectorError::InvalidParameter("file path required".to_string()))?;
                
                let hash = self.hash_file(&file_path).await?;
                
                let evidence_id = Ulid::new().to_string();
                let path = format!("evidence/{}.jsonl", evidence_id);
                let result = json!({
                    "path": file_path.to_string_lossy(),
                    "hash": hash,
                    "algorithm": "sha256",
                });
                let result_bytes = serde_json::to_string(&result)?.into_bytes();
                
                let evidence_path = context.evidence_root.join(&path);
                if let Some(parent) = evidence_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&evidence_path, &result_bytes)?;

                let mut hasher = Sha256::new();
                hasher.update(&result_bytes);
                let evidence_hash = hex::encode(hasher.finalize());
                
                let evidence = Evidence::new(
                    context.run_id.clone(),
                    action.to_string(),
                    self.name.clone(),
                    EvidenceType::File,
                    format!("File hash: {}", file_path.display()),
                    path.clone(),
                    result_bytes.len() as u64,
                    evidence_hash,
                    json!({
                        "file": file_path.to_string_lossy(),
                        "hash": hash,
                        "algorithm": "sha256",
                    }),
                );
                
                Ok(CollectorOutput {
                    evidence: vec![evidence],
                    artifacts: vec![ArtifactRef {
                        path,
                        type_: "artifact/file_hash".to_string(),
                        description: format!("SHA-256 hash of {}", file_path.display()),
                    }],
                    metrics: CollectorMetrics {
                        duration_ms: 0,
                        bytes_read: 0,
                        bytes_written: result_bytes.len() as u64,
                        errors: vec![],
                    },
                })
            }
            "collect" => {
                let file_path = params
                    .get("file")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .ok_or_else(|| CollectorError::InvalidParameter("file path required".to_string()))?;
                
                let file_info = self.collect_file(&file_path).await?;
                
                let evidence_id = Ulid::new().to_string();
                let path = format!("evidence/{}.jsonl", evidence_id);
                
                // Copy file to evidence directory
                let evidence_path = context.evidence_root.join(&path);
                if let Some(parent) = evidence_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&file_path, &evidence_path)?;
                
                let file_bytes = fs::read(&file_path)?;
                let mut hasher = Sha256::new();
                hasher.update(&file_bytes);
                let hash = hex::encode(hasher.finalize());
                
                let file_json = serde_json::to_string(&file_info)?;
                let file_bytes_json = file_json.as_bytes();
                
                let evidence = Evidence::new(
                    context.run_id.clone(),
                    action.to_string(),
                    self.name.clone(),
                    EvidenceType::File,
                    format!("File: {}", file_path.display()),
                    path.clone(),
                    file_bytes_json.len() as u64,
                    hash,
                    json!({
                        "path": file_info.path,
                        "size": file_info.size,
                        "modified": file_info.modified.map(|t| t.to_rfc3339()),
                        "accessed": file_info.accessed.map(|t| t.to_rfc3339()),
                        "permissions": file_info.permissions,
                        "hash": file_info.hash,
                    }),
                );
                
                Ok(CollectorOutput {
                    evidence: vec![evidence],
                    artifacts: vec![ArtifactRef {
                        path,
                        type_: "artifact/file".to_string(),
                        description: format!("File content: {}", file_path.display()),
                    }],
                    metrics: CollectorMetrics {
                        duration_ms: 0,
                        bytes_read: file_bytes.len() as u64,
                        bytes_written: file_bytes.len() as u64,
                        errors: vec![],
                    },
                })
            }
            "metadata" => {
                let file_path = params
                    .get("file")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .ok_or_else(|| CollectorError::InvalidParameter("file path required".to_string()))?;
                
                let metadata = fs::metadata(&file_path)
                    .map_err(|e| CollectorError::Internal(format!("Failed to read metadata: {}", e)))?;
                
                let file_info = self.get_file_info(&file_path, &metadata).await.unwrap_or_else(|| FileInfo {
                    path: file_path.to_string_lossy().to_string(),
                    size: metadata.len(),
                    modified: None,
                    accessed: None,
                    permissions: None,
                    hash: None,
                });
                
                let evidence_id = Ulid::new().to_string();
                let path = format!("evidence/{}.jsonl", evidence_id);
                let file_json = serde_json::to_string(&file_info)?;
                let file_bytes = file_json.as_bytes();
                
                let evidence_path = context.evidence_root.join(&path);
                if let Some(parent) = evidence_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&evidence_path, file_bytes)?;
                
                let mut hasher = Sha256::new();
                hasher.update(file_bytes);
                let hash = hex::encode(hasher.finalize());
                
                let evidence = Evidence::new(
                    context.run_id.clone(),
                    action.to_string(),
                    self.name.clone(),
                    EvidenceType::File,
                    format!("File metadata: {}", file_path.display()),
                    path.clone(),
                    file_bytes.len() as u64,
                    hash,
                    json!({
                        "path": file_info.path,
                        "size": file_info.size,
                        "modified": file_info.modified.map(|t| t.to_rfc3339()),
                        "accessed": file_info.accessed.map(|t| t.to_rfc3339()),
                        "permissions": file_info.permissions,
                        "hash": file_info.hash,
                    }),
                );
                
                Ok(CollectorOutput {
                    evidence: vec![evidence],
                    artifacts: vec![ArtifactRef {
                        path,
                        type_: "artifact/file".to_string(),
                        description: format!("File metadata: {}", file_path.display()),
                    }],
                    metrics: CollectorMetrics {
                        duration_ms: 0,
                        bytes_read: 0,
                        bytes_written: file_bytes.len() as u64,
                        errors: vec![],
                    },
                })
            }
            _ => Err(CollectorError::UnsupportedAction(action.to_string())),
        }
    }
}