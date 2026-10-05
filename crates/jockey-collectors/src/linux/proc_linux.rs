//! Linux Process Collector — Process enumeration and metadata collection via /proc
//!
//! Collects process information by reading /proc filesystem.
//! Provides forensic metadata: PID, PPID, name, path, command line, start time, etc.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::trait_def::{Collector, CollectorOutput, ExecutionContext, CollectorError, CollectorMetrics, ArtifactRef};
use jockey_evidence::model::{Evidence, EvidenceType};
use async_trait::async_trait;
use serde_json::{json, Value};
use ulid::Ulid;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};

/// Linux Process Collector
pub struct ProcLinuxCollector {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    version: String,
    #[allow(dead_code)]
    keypair: Arc<jockey_evidence::receipt::CollectorKeypair>,
}

impl ProcLinuxCollector {
    /// Create a new instance of ProcLinuxCollector
    pub fn new(keypair: Arc<jockey_evidence::receipt::CollectorKeypair>) -> Self {
        Self {
            name: "proc_linux".to_string(),
            version: "0.1.0".to_string(),
            keypair,
        }
    }

    /// Collect all processes from /proc
    async fn collect_processes(&self, filter: Option<&Value>, _context: &ExecutionContext) -> Result<Vec<ProcessInfo>, CollectorError> {
        let mut processes = Vec::new();

        #[cfg(target_os = "linux")]
        {
            let proc_dir = Path::new("/proc");
            if !proc_dir.exists() {
                return Err(CollectorError::Internal("/proc directory not accessible".to_string()));
            }

            let entries = fs::read_dir(proc_dir)
                .map_err(|e| CollectorError::Internal(format!("Failed to read /proc: {}", e)))?;

            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }

                let dir_name = match path.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n,
                    None => continue,
                };

                // Check if directory name is a PID (numeric)
                let pid = match dir_name.parse::<u32>() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Read process info
                if let Some(info) = self.read_process_info(pid, &path).await {
                    // Apply filter if provided
                    if let Some(filter) = filter {
                        if !self.matches_filter(&info.name, info.pid, info.ppid, filter) {
                            continue;
                        }
                    }

                    processes.push(info);
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = filter;
            // Mock implementation for non-Linux platforms (for testing)
            processes.push(ProcessInfo {
                pid: 1234,
                ppid: 1,
                name: "systemd".to_string(),
                path: "/usr/lib/systemd/systemd".to_string(),
                cmdline: Some("/usr/lib/systemd/systemd --system".to_string()),
                start_time: Some(Utc::now() - Duration::from_secs(3600)),
                username: Some("root".to_string()),
            });
        }

        Ok(processes)
    }

    /// Read process information from /proc/<pid>/
    async fn read_process_info(&self, pid: u32, proc_path: &Path) -> Option<ProcessInfo> {
        // Read stat file for basic info
        let stat_path = proc_path.join("stat");
        let stat_content = fs::read_to_string(&stat_path).ok()?;
        
        let fields: Vec<&str> = stat_content.split_whitespace().collect();
        if fields.len() < 24 {
            return None;
        }

        // Parse stat fields
        // (1) pid  (2) comm  (3) state  (4) ppid
        let name = fields[1].trim_matches(|c| c == '(' || c == ')').to_string();
        let ppid = fields[3].parse::<u32>().unwrap_or(0);

        // Read cmdline
        let cmdline = self.read_cmdline(pid, proc_path);

        // Read exe link for binary path
        let path = self.read_exe_link(pid, proc_path);

        // Read start time
        let start_time = self.read_start_time(pid, proc_path, &fields);

        // Read username from status file
        let username = self.read_username(pid, proc_path);

        Some(ProcessInfo {
            pid,
            ppid,
            name,
            path,
            cmdline,
            start_time,
            username,
        })
    }

    /// Read command line from /proc/<pid>/cmdline
    fn read_cmdline(&self, pid: u32, proc_path: &Path) -> Option<String> {
        let cmdline_path = proc_path.join("cmdline");
        let content = fs::read(&cmdline_path).ok()?;
        if content.is_empty() {
            return None;
        }
        // cmdline is null-separated
        let cmdline = String::from_utf8_lossy(&content)
            .replace('\0', " ")
            .trim()
            .to_string();
        if cmdline.is_empty() {
            None
        } else {
            Some(cmdline)
        }
    }

    /// Read executable path from /proc/<pid>/exe
    fn read_exe_link(&self, pid: u32, proc_path: &Path) -> String {
        let exe_path = proc_path.join("exe");
        fs::read_link(&exe_path)
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| format!("/proc/{}/exe (unreadable)", pid))
    }

    /// Read process start time from stat
    fn read_start_time(&self, _pid: u32, _proc_path: &Path, fields: &[&str]) -> Option<DateTime<Utc>> {
        // Field 22 (index 21) is starttime in clock ticks
        if fields.len() < 22 {
            return None;
        }
        let starttime_ticks = fields[21].parse::<u64>().ok()?;
        
        // Get clock ticks per second
        let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        if clk_tck == 0 {
            return None;
        }

        // Read system uptime
        let uptime_content = fs::read_to_string("/proc/uptime").ok()?;
        let uptime_secs = uptime_content.split_whitespace()
            .next()
            .and_then(|s| s.parse::<f64>().ok())?;
        
        let process_start_secs = uptime_secs - (starttime_ticks as f64 / clk_tck as f64);
        
        let secs = process_start_secs as i64;
        let nanos = ((process_start_secs - secs as f64) * 1_000_000_000.0) as u32;
        
        DateTime::from_timestamp(secs, nanos)
    }

    /// Read username from /proc/<pid>/status
    fn read_username(&self, _pid: u32, proc_path: &Path) -> Option<String> {
        let status_path = proc_path.join("status");
        let content = fs::read_to_string(&status_path).ok()?;
        
        for line in content.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let uid = parts[1].parse::<u32>().ok()?;
                    return self.uid_to_username(uid);
                }
            }
        }
        None
    }

    /// Convert UID to username (simplified - in production would use /etc/passwd or libc)
    fn uid_to_username(&self, uid: u32) -> Option<String> {
        // Common UID mappings
        let name = match uid {
            0 => "root",
            65534 => "nobody",
            _ => return Some(uid.to_string()),
        };
        Some(name.to_string())
    }

    /// Check if process matches filter
    fn matches_filter(&self, name: &str, pid: u32, ppid: u32, filter: &Value) -> bool {
        if let Some(obj) = filter.as_object() {
            if let Some(name_filter) = obj.get("name_contains") {
                if let Some(s) = name_filter.as_str() {
                    if !name.to_lowercase().contains(&s.to_lowercase()) {
                        return false;
                    }
                }
            }
            if let Some(pid_filter) = obj.get("pid") {
                if let Some(p) = pid_filter.as_u64() {
                    if pid != p as u32 {
                        return false;
                    }
                }
            }
            if let Some(ppid_filter) = obj.get("ppid") {
                if let Some(p) = ppid_filter.as_u64() {
                    if ppid != p as u32 {
                        return false;
                    }
                }
            }
            true
        } else {
            true
        }
    }

    /// Build process tree from flat process list
    fn build_process_tree(processes: Vec<ProcessInfo>) -> Vec<ProcessTreeNode> {
        let mut nodes: HashMap<u32, ProcessTreeNode> = HashMap::new();
        let mut roots = Vec::new();
        
        // Create nodes
        for proc in &processes {
            nodes.insert(proc.pid, ProcessTreeNode {
                process: proc.clone(),
                children: Vec::new(),
            });
        }
        
        // Link children to parents
        for proc in &processes {
            if proc.ppid != 0 {
                if let Some(child_node) = nodes.remove(&proc.pid) {
                    if let Some(parent) = nodes.get_mut(&proc.ppid) {
                        parent.children.push(child_node);
                    } else {
                        roots.push(child_node);
                    }
                }
            }
        }
        
        // Collect remaining roots
        for (_pid, node) in nodes {
            roots.push(node);
        }
        
        roots
    }
}

/// Metadata structure describing an enumerated process
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub cmdline: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub username: Option<String>,
}

/// Tree node representing a process and its child processes
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessTreeNode {
    pub process: ProcessInfo,
    pub children: Vec<ProcessTreeNode>,
}

#[async_trait]
impl Collector for ProcLinuxCollector {
    fn name(&self) -> &'static str {
        "proc_linux"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn supported_actions(&self) -> Vec<&'static str> {
        vec!["list", "get", "tree"]
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
        match action {
            "list" => {
                let filter = params.get("filter");
                let processes = self.collect_processes(filter, context).await?;
                
                let mut evidence_list = Vec::new();
                let mut artifacts = Vec::new();
                
                for proc in processes {
                    let evidence_id = Ulid::new().to_string();
                    let path = format!("evidence/{}.jsonl", evidence_id);
                    
                    let proc_json = serde_json::to_string(&proc)?;
                    let proc_bytes = proc_json.as_bytes();
                    
                    let evidence_path = context.evidence_root.join(&path);
                    if let Some(parent) = evidence_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&evidence_path, proc_bytes)?;
                    
                    let mut hasher = Sha256::new();
                    hasher.update(proc_bytes);
                    let hash = hex::encode(hasher.finalize());
                    
                    let evidence = Evidence::new(
                        context.run_id.clone(),
                        action.to_string(),
                        self.name.clone(),
                        EvidenceType::Process,
                        format!("Process: {} (PID {})", proc.name, proc.pid),
                        path.clone(),
                        proc_bytes.len() as u64,
                        hash,
                        json!({
                            "pid": proc.pid,
                            "ppid": proc.ppid,
                            "name": proc.name,
                            "path": proc.path,
                            "cmdline": proc.cmdline,
                            "start_time": proc.start_time.map(|t| t.to_rfc3339()),
                            "username": proc.username,
                        }),
                    );
                    
                    evidence_list.push(evidence);
                    
                    artifacts.push(ArtifactRef {
                        path,
                        type_: "artifact/process".to_string(),
                        description: format!("Process {} (PID {})", proc.name, proc.pid),
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
            "get" => {
                let pid = params
                    .get("pid")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| CollectorError::InvalidParameter("pid required".to_string()))? as u32;
                
                let processes = self.collect_processes(None, context).await?;
                let proc = processes.into_iter()
                    .find(|p| p.pid == pid)
                    .ok_or_else(|| CollectorError::InvalidParameter(format!("Process {} not found", pid)))?;
                
                let evidence_id = Ulid::new().to_string();
                let path = format!("evidence/{}.jsonl", evidence_id);
                let proc_json = serde_json::to_string(&proc)?;
                let proc_bytes = proc_json.as_bytes();

                let evidence_path = context.evidence_root.join(&path);
                if let Some(parent) = evidence_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&evidence_path, proc_bytes)?;

                let mut hasher = Sha256::new();
                hasher.update(proc_bytes);
                let hash = hex::encode(hasher.finalize());

                let evidence = Evidence::new(
                    context.run_id.clone(),
                    action.to_string(),
                    self.name.clone(),
                    EvidenceType::Process,
                    format!("Process: {} (PID {})", proc.name, proc.pid),
                    path.clone(),
                    proc_bytes.len() as u64,
                    hash,
                    json!({
                        "pid": proc.pid,
                        "ppid": proc.ppid,
                        "name": proc.name,
                        "path": proc.path,
                        "cmdline": proc.cmdline,
                        "start_time": proc.start_time.map(|t| t.to_rfc3339()),
                        "username": proc.username,
                    }),
                );

                Ok(CollectorOutput {
                    evidence: vec![evidence],
                    artifacts: vec![ArtifactRef {
                        path,
                        type_: "artifact/process".to_string(),
                        description: format!("Process {} (PID {})", proc.name, proc.pid),
                    }],
                    metrics: CollectorMetrics {
                        duration_ms: 0,
                        bytes_read: 0,
                        bytes_written: proc_bytes.len() as u64,
                        errors: vec![],
                    },
                })
            }
            "tree" => {
                let processes = self.collect_processes(None, context).await?;
                let tree = Self::build_process_tree(processes);
                
                let evidence_id = Ulid::new().to_string();
                let path = format!("evidence/{}.jsonl", evidence_id);
                let tree_json = serde_json::to_string(&tree)?;
                
                let evidence_path = context.evidence_root.join(&path);
                if let Some(parent) = evidence_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&evidence_path, tree_json.as_bytes())?;

                let mut hasher = Sha256::new();
                hasher.update(tree_json.as_bytes());
                let hash = hex::encode(hasher.finalize());
                
                let evidence = Evidence::new(
                    context.run_id.clone(),
                    action.to_string(),
                    self.name.clone(),
                    EvidenceType::Process,
                    "Process Tree".to_string(),
                    path.clone(),
                    tree_json.len() as u64,
                    hash,
                    json!({ "process_count": tree.len() }),
                );
                
                Ok(CollectorOutput {
                    evidence: vec![evidence],
                    artifacts: vec![ArtifactRef {
                        path,
                        type_: "artifact/process_tree".to_string(),
                        description: "Process tree".to_string(),
                    }],
                    metrics: CollectorMetrics {
                        duration_ms: 0,
                        bytes_read: 0,
                        bytes_written: tree_json.len() as u64,
                        errors: vec![],
                    },
                })
            }
            _ => Err(CollectorError::UnsupportedAction(action.to_string())),
        }
    }
}