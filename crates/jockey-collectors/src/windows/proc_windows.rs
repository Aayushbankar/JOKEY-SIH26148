//! Windows Process Collector — Process enumeration and metadata collection
//!
//! Collects process information using Windows ToolHelp32 API.
//! Provides forensic metadata: PID, PPID, name, path, command line, start time, etc.

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::GetProcessTimes;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::OpenProcessToken;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::GetTokenInformation;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::TokenUser;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::TOKEN_INFORMATION_CLASS;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::trait_def::{Collector, CollectorOutput, ExecutionContext, CollectorError, CollectorMetrics, ArtifactRef};
use jockey_evidence::model::EvidenceType;
use async_trait::async_trait;
use serde_json::{json, Value};
use ulid::Ulid;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};

/// Windows Process Collector
pub struct ProcWindowsCollector {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    version: String,
    #[allow(dead_code)]
    keypair: Arc<jockey_evidence::receipt::CollectorKeypair>,
}

impl ProcWindowsCollector {
    /// Create a new instance of ProcWindowsCollector
    pub fn new(keypair: Arc<jockey_evidence::receipt::CollectorKeypair>) -> Self {
        Self {
            name: "proc_windows".to_string(),
            version: "0.1.0".to_string(),
            keypair,
        }
    }

    /// Collect all processes
    async fn collect_processes(&self, filter: Option<&Value>, _context: &ExecutionContext) -> Result<Vec<ProcessInfo>, CollectorError> {
        let mut processes = Vec::new();

        #[cfg(target_os = "windows")]
        {
            unsafe {
                let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if snapshot == HANDLE(-1 as _) {
                    return Err(CollectorError::Internal("Failed to create process snapshot".to_string()));
                }

                let mut entry: PROCESSENTRY32W = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

                if Process32FirstW(snapshot, &mut entry) == 0 {
                    CloseHandle(snapshot);
                    return Err(CollectorError::Internal("Failed to get first process".to_string()));
                }

                loop {
                    let process_name = wide_to_string(&entry.szExeFile);
                    let pid = entry.th32ProcessID;
                    let ppid = entry.th32ParentProcessID;

                    // Apply filter if provided
                    if let Some(filter) = filter {
                        if !self.matches_filter(&process_name, pid, ppid, filter) {
                            if Process32NextW(snapshot, &mut entry) == 0 {
                                break;
                            }
                            continue;
                        }
                    }

                    // Get additional process info
                    let info = self.get_process_info(pid, &process_name, ppid).await;

                    processes.push(info);

                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }

                CloseHandle(snapshot);
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = filter;
            // Mock implementation for non-Windows platforms (for testing)
            processes.push(ProcessInfo {
                pid: 1234,
                ppid: 1,
                name: "svchost.exe".to_string(),
                path: "C:\\Windows\\System32\\svchost.exe".to_string(),
                cmdline: Some("C:\\Windows\\System32\\svchost.exe -k netsvcs".to_string()),
                start_time: Some(Utc::now()),
                username: Some("SYSTEM".to_string()),
            });
        }

        Ok(processes)
    }

    /// Check if process matches filter
    #[allow(dead_code)]
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

    /// Get detailed process information
    async fn get_process_info(&self, pid: u32, name: &str, ppid: u32) -> ProcessInfo {
        #[cfg(target_os = "windows")]
        {
            unsafe {
                let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                if handle != 0 {
                    let path = get_process_path(handle);
                    let cmdline = get_command_line(handle);
                    let start_time = get_process_start_time(handle);
                    let username = get_process_user(handle);
                    CloseHandle(handle);

                    return ProcessInfo {
                        pid,
                        ppid,
                        name: name.to_string(),
                        path,
                        cmdline,
                        start_time,
                        username,
                    };
                }
            }

            ProcessInfo {
                pid,
                ppid,
                name: name.to_string(),
                path: "unknown".to_string(),
                cmdline: None,
                start_time: None,
                username: None,
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = (pid, ppid);
            ProcessInfo {
                pid,
                ppid,
                name: name.to_string(),
                path: format!("C:\\Windows\\System32\\{}", name),
                cmdline: Some(format!("{} -k netsvcs", name)),
                start_time: Some(Utc::now() - Duration::from_secs(3600)),
                username: Some("SYSTEM".to_string()),
            }
        }
    }
}

/// Metadata structure describing an enumerated process
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Process executable name
    pub name: String,
    /// Full binary path
    pub path: String,
    /// Command line arguments
    pub cmdline: Option<String>,
    /// Process start time
    pub start_time: Option<DateTime<Utc>>,
    /// User executing the process
    pub username: Option<String>,
}

/// Convert wide string to Rust String
#[cfg(target_os = "windows")]
fn wide_to_string(wide: &[u16; MAX_PATH]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(MAX_PATH);
    String::from_utf16_lossy(&wide[..len])
}

/// Get process executable path
#[cfg(target_os = "windows")]
fn get_process_path(handle: HANDLE) -> String {
    unsafe {
        let mut buffer: Vec<u16> = vec![0; MAX_PATH + 1];
        let size = (MAX_PATH + 1) as u32;
        if windows_sys::Win32::System::Threading::GetModuleFileNameExW(handle, 0, buffer.as_mut_ptr(), size) > 0 {
            let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
            String::from_utf16_lossy(&buffer[..len])
        } else {
            "unknown".to_string()
        }
    }
}

/// Get process command line (simplified)
#[cfg(target_os = "windows")]
fn get_command_line(_handle: HANDLE) -> Option<String> {
    None
}

/// Get process start time
#[cfg(target_os = "windows")]
fn get_process_start_time(handle: HANDLE) -> Option<DateTime<Utc>> {
    unsafe {
        let mut creation_time = std::mem::zeroed();
        let mut exit_time = std::mem::zeroed();
        let mut kernel_time = std::mem::zeroed();
        let mut user_time = std::mem::zeroed();

        if GetProcessTimes(handle, &mut creation_time, &mut exit_time, &mut kernel_time, &mut user_time) != 0 {
            let ft = (creation_time.dwHighDateTime as u64) << 32 | creation_time.dwLowDateTime as u64;
            const EPOCH_DIFF: u64 = 116444736000000000;
            if ft > EPOCH_DIFF {
                let unix_ns = (ft - EPOCH_DIFF) * 100;
                let secs = unix_ns / 1_000_000_000;
                let nanos = (unix_ns % 1_000_000_000) as u32;
                return Some(chrono::DateTime::from_timestamp(secs as i64, nanos).unwrap_or_else(Utc::now));
            }
        }
        None
    }
}

/// Get process username (simplified)
#[cfg(target_os = "windows")]
fn get_process_user(_handle: HANDLE) -> Option<String> {
    None
}

#[async_trait]
impl Collector for ProcWindowsCollector {
    fn name(&self) -> &'static str {
        "proc_windows"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn supported_actions(&self) -> Vec<&'static str> {
        vec!["list", "get", "tree"]
    }

    fn supported_os(&self) -> Vec<&'static str> {
        vec!["windows"]
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
                
                // Convert to Evidence objects
                let mut evidence_list = Vec::new();
                let mut artifacts = Vec::new();
                
                for proc in processes {
                    let evidence_id = Ulid::new().to_string();
                    let path = format!("evidence/{}.jsonl", evidence_id);
                    
                    // Create JSONL for the process
                    let proc_json = serde_json::to_string(&proc)?;
                    let proc_bytes = proc_json.as_bytes();
                    
                    // Write to evidence file
                    let evidence_path = context.evidence_root.join(&path);
                    if let Some(parent) = evidence_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&evidence_path, proc_bytes)?;
                    
                    // Compute SHA-256 hash
                    let mut hasher = Sha256::new();
                    hasher.update(proc_bytes);
                    let hash = hex::encode(hasher.finalize());
                    
                    let evidence = jockey_evidence::model::Evidence::new(
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
                
                let proc = self.get_process_info(pid, "unknown", 0).await;
                let evidence_id = Ulid::new().to_string();
                let path = format!("evidence/{}.jsonl", evidence_id);
                let proc_json = serde_json::to_string(&proc)?;
                let proc_bytes = proc_json.as_bytes();

                let evidence_path = context.evidence_root.join(&path);
                if let Some(parent) = evidence_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&evidence_path, proc_bytes)?;

                let mut hasher = Sha256::new();
                hasher.update(proc_bytes);
                let hash = hex::encode(hasher.finalize());

                let evidence = jockey_evidence::model::Evidence::new(
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
                let tree = build_process_tree(processes);
                
                let evidence_id = Ulid::new().to_string();
                let path = format!("evidence/{}.jsonl", evidence_id);
                let tree_json = serde_json::to_string(&tree)?;
                
                let evidence_path = context.evidence_root.join(&path);
                if let Some(parent) = evidence_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&evidence_path, tree_json.as_bytes())?;

                let mut hasher = Sha256::new();
                hasher.update(tree_json.as_bytes());
                let hash = hex::encode(hasher.finalize());
                
                let evidence = jockey_evidence::model::Evidence::new(
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
                    // Parent not found, treat as root
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

/// Tree node representing a process and its child processes
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessTreeNode {
    /// Process details
    pub process: ProcessInfo,
    /// Child process nodes
    pub children: Vec<ProcessTreeNode>,
}