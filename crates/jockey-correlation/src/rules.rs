//! JOCKY Correlation — Deterministic Correlation Rules
//!
//! Implements three deterministic correlation rules:
//! 1. `pid_link` - Parent-child process relationship
//! 2. `temporal_adjacent` - Events within a time window
//! 3. `evidence_support` - Shared indicators/IOCs across evidence

use crate::evidence::Evidence;
use crate::graph::CorrelationEdge;
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use std::collections::HashMap;

/// Correlation rule types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationMethod {
    PidLink,
    TemporalAdjacent,
    EvidenceSupport,
}

/// Configuration for a correlation rule
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    pub method: CorrelationMethod,
    pub window_seconds: Option<u64>,    // For temporal_adjacent
    pub min_confidence: f32,            // Minimum confidence threshold
    pub max_edges_per_node: usize,      // Limit edges per node
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            method: CorrelationMethod::PidLink,
            window_seconds: Some(300),
            min_confidence: 0.7,
            max_edges_per_node: 10,
        }
    }
}

/// Correlation rule trait
pub trait CorrelationRule: Send + Sync {
    fn method(&self) -> CorrelationMethod;
    fn name(&self) -> &'static str;
    fn correlate(&self, evidence: &[Evidence], config: &CorrelationConfig) -> Vec<CorrelationEdge>;
}

/// PID Link correlation - finds parent-child process relationships
pub struct PidLinkRule;

impl CorrelationRule for PidLinkRule {
    fn method(&self) -> CorrelationMethod {
        CorrelationMethod::PidLink
    }

    fn name(&self) -> &'static str {
        "pid_link"
    }

    fn correlate(&self, evidence: &[Evidence], _config: &CorrelationConfig) -> Vec<CorrelationEdge> {
        let mut edges = Vec::new();
        let mut pid_to_evidence: HashMap<u32, &Evidence> = HashMap::new();
        let mut ppid_to_evidence: HashMap<u32, Vec<&Evidence>> = HashMap::new();

        // Build PID and PPID indexes from process evidence
        for ev in evidence {
            if ev.evidence_type == "artifact/process" {
                if let Some(pid) = ev.metadata.get("pid").and_then(|v| v.as_u64()) {
                    pid_to_evidence.insert(pid as u32, ev);
                }
                if let Some(ppid) = ev.metadata.get("ppid").and_then(|v| v.as_u64()) {
                    ppid_to_evidence.entry(ppid as u32).or_default().push(ev);
                }
            }
        }

        // Find parent-child relationships
        for (pid, parent_ev) in pid_to_evidence {
            if let Some(children) = ppid_to_evidence.get(&pid) {
                for child_ev in children {
                    let confidence = calculate_pid_confidence(parent_ev, child_ev);
                    edges.push(CorrelationEdge {
                        relation: "pid_link".to_string(),
                        confidence,
                        method: "pid_link".to_string(),
                        details: serde_json::json!({
                            "parent_pid": parent_ev.metadata.get("pid"),
                            "child_pid": child_ev.metadata.get("pid"),
                            "parent_name": parent_ev.metadata.get("name"),
                            "child_name": child_ev.metadata.get("name"),
                        }),
                        evidence_ids: vec![parent_ev.id.clone(), child_ev.id.clone()],
                    });
                }
            }
        }

        edges
    }
}

/// Temporal Adjacent correlation - events within a time window
pub struct TemporalAdjacentRule;

impl CorrelationRule for TemporalAdjacentRule {
    fn method(&self) -> CorrelationMethod {
        CorrelationMethod::TemporalAdjacent
    }

    fn name(&self) -> &'static str {
        "temporal_adjacent"
    }

    fn correlate(&self, evidence: &[Evidence], config: &CorrelationConfig) -> Vec<CorrelationEdge> {
        let mut edges = Vec::new();
        let window = Duration::seconds(config.window_seconds.unwrap_or(300) as i64);

        // Sort evidence by collected_at timestamp
        let mut sorted: Vec<_> = evidence.iter().collect();
        sorted.sort_by_key(|ev| ev.collected_at);

        // Sliding window to find temporal neighbors
        for i in 0..sorted.len() {
            let ev_i = sorted[i];
            let window_end = ev_i.collected_at + window;

            for j in (i + 1)..sorted.len() {
                let ev_j = sorted[j];
                
                if ev_j.collected_at > window_end {
                    break;
                }

                // Different evidence types get lower confidence
                let type_match = ev_i.evidence_type == ev_j.evidence_type;
                let base_confidence = if type_match { 0.8 } else { 0.5 };
                let time_diff = (ev_j.collected_at - ev_i.collected_at).num_seconds() as f64;
                let window_secs = window.num_seconds() as f64;
                let time_factor = 1.0 - (time_diff / window_secs).min(1.0) * 0.3;
                let confidence = base_confidence * time_factor as f32;

                if confidence >= config.min_confidence {
                    edges.push(CorrelationEdge {
                        relation: "temporal_adjacent".to_string(),
                        confidence,
                        method: "temporal_adjacent".to_string(),
                        details: serde_json::json!({
                            "time_diff_seconds": time_diff,
                            "evidence_i_type": ev_i.evidence_type,
                            "evidence_j_type": ev_j.evidence_type,
                        }),
                        evidence_ids: vec![ev_i.id.clone(), ev_j.id.clone()],
                    });
                }
            }
        }

        edges
    }
}

/// Evidence Support correlation - shared indicators/IOCs across evidence
pub struct EvidenceSupportRule;

impl CorrelationRule for EvidenceSupportRule {
    fn method(&self) -> CorrelationMethod {
        CorrelationMethod::EvidenceSupport
    }

    fn name(&self) -> &'static str {
        "evidence_support"
    }

    fn correlate(&self, evidence: &[Evidence], config: &CorrelationConfig) -> Vec<CorrelationEdge> {
        let mut edges = Vec::new();
        let mut indicator_index: HashMap<String, Vec<&Evidence>> = HashMap::new();

        // Index all indicators/IOCs from evidence metadata
        for ev in evidence {
            // Extract IOCs from metadata
            let iocs = extract_iocs(&ev.metadata);
            for ioc in iocs {
                indicator_index.entry(ioc).or_default().push(ev);
            }
        }

        // Find evidence sharing indicators
        for (indicator, ev_list) in indicator_index {
            if ev_list.len() < 2 {
                continue;
            }

            // Create edges between all pairs sharing this indicator
            for i in 0..ev_list.len() {
                for j in (i + 1)..ev_list.len() {
                    let confidence = calculate_ioc_confidence(&indicator, ev_list[i], ev_list[j]);
                    if confidence >= config.min_confidence {
                        edges.push(CorrelationEdge {
                            relation: "evidence_support".to_string(),
                            confidence,
                            method: "evidence_support".to_string(),
                            details: serde_json::json!({
                                "shared_indicator": indicator,
                                "evidence_i_type": ev_list[i].evidence_type,
                                "evidence_j_type": ev_list[j].evidence_type,
                            }),
                            evidence_ids: vec![ev_list[i].id.clone(), ev_list[j].id.clone()],
                        });
                    }
                }
            }
        }

        // Deduplicate edges (keep highest confidence)
        deduplicate_edges(&mut edges);
        
        // Limit edges per node
        limit_edges_per_node(&mut edges, config.max_edges_per_node);

        edges
    }
}

/// Extract IOCs (IPs, domains, hashes, paths) from evidence metadata
fn extract_iocs(metadata: &Value) -> Vec<String> {
    let mut iocs = Vec::new();
    
    // Extract from common metadata fields
    if let Some(obj) = metadata.as_object() {
        // Network indicators
        if let Some(ips) = obj.get("destination_ips").or_else(|| obj.get("source_ips")) {
            if let Some(arr) = ips.as_array() {
                for ip in arr {
                    if let Some(s) = ip.as_str() {
                        iocs.push(format!("ip:{}", s));
                    }
                }
            }
        }
        
        if let Some(domains) = obj.get("domains").or_else(|| obj.get("hostnames")) {
            if let Some(arr) = domains.as_array() {
                for domain in arr {
                    if let Some(s) = domain.as_str() {
                        iocs.push(format!("domain:{}", s));
                    }
                }
            }
        }

        // File hashes
        if let Some(hash) = obj.get("hash").or_else(|| obj.get("sha256")) {
            if let Some(s) = hash.as_str() {
                iocs.push(format!("hash:{}", s));
            }
        }

        // File paths
        if let Some(path) = obj.get("path") {
            if let Some(s) = path.as_str() {
                iocs.push(format!("path:{}", s));
            }
        }

        // Registry keys
        if let Some(reg_path) = obj.get("registry_path").or_else(|| obj.get("path")) {
            if let Some(s) = reg_path.as_str() {
                iocs.push(format!("reg:{}", s));
            }
        }

        // Process names
        if let Some(name) = obj.get("name") {
            if let Some(s) = name.as_str() {
                iocs.push(format!("proc:{}", s));
            }
        }

        // Command line arguments
        if let Some(cmdline) = obj.get("cmdline").or_else(|| obj.get("command_line")) {
            if let Some(s) = cmdline.as_str() {
                // Extract potential IOCs from command line
                for token in s.split_whitespace() {
                    if token.contains('.') || token.contains('/') || token.contains('\\') {
                        iocs.push(format!("arg:{}", token));
                    }
                }
            }
        }

        // MITRE tags
        if let Some(mitre) = obj.get("mitre_tags") {
            if let Some(arr) = mitre.as_array() {
                for tag in arr {
                    if let Some(s) = tag.as_str() {
                        iocs.push(format!("mitre:{}", s));
                    }
                }
            }
        }
    }

    iocs
}

/// Calculate confidence for PID link
fn calculate_pid_confidence(parent: &Evidence, child: &Evidence) -> f32 {
    let mut confidence = 0.9;
    
    // Boost if same process name pattern
    if let (Some(p_name), Some(c_name)) = (
        parent.metadata.get("name").and_then(|v| v.as_str()),
        child.metadata.get("name").and_then(|v| v.as_str()),
    ) {
        if p_name == c_name {
            confidence = 0.95;
        }
    }

    // Boost if command line shows inheritance
    if let (Some(p_cmd), Some(c_cmd)) = (
        parent.metadata.get("cmdline").and_then(|v| v.as_str()),
        child.metadata.get("cmdline").and_then(|v| v.as_str()),
    ) {
        if c_cmd.contains(p_cmd) || p_cmd.contains(c_cmd) {
            confidence = (confidence + 0.05_f32).min(1.0_f32);
        }
    }

    confidence
}

/// Calculate confidence for shared IOC
fn calculate_ioc_confidence(indicator: &str, ev1: &Evidence, ev2: &Evidence) -> f32 {
    let base = match indicator.split(':').next() {
        Some("hash") => 0.95,      // Hash match is very strong
        Some("ip") => 0.85,        // IP match is strong
        Some("domain") => 0.8,     // Domain match is strong
        Some("path") => 0.7,       // Path match is moderate
        Some("reg") => 0.75,       // Registry match is moderate
        Some("proc") => 0.6,       // Process name match is weaker
        Some("arg") => 0.5,        // Command arg match is weak
        Some("mitre") => 0.65,     // MITRE tag match is moderate
        _ => 0.4,
    };

    // Boost if same evidence type
    if ev1.evidence_type == ev2.evidence_type {
        (base + 0.1_f32).min(1.0_f32)
    } else {
        base
    }
}

/// Deduplicate edges by keeping highest confidence for each evidence pair
fn deduplicate_edges(edges: &mut Vec<CorrelationEdge>) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::collections::HashMap;

    let mut best_edge: HashMap<u64, (usize, f32)> = HashMap::new();

    for (idx, edge) in edges.iter().enumerate() {
        let mut hasher = DefaultHasher::new();
        // Sort evidence IDs for consistent hashing
        let mut ids = edge.evidence_ids.clone();
        ids.sort();
        for id in &ids {
            id.hash(&mut hasher);
        }
        edge.relation.hash(&mut hasher);
        let key = hasher.finish();

        let confidence = edge.confidence;
        if let Some(&(_, existing_conf)) = best_edge.get(&key) {
            if confidence > existing_conf {
                best_edge.insert(key, (idx, confidence));
            }
        } else {
            best_edge.insert(key, (idx, confidence));
        }
    }

    // Keep only the best edges
    let keep_indices: Vec<usize> = best_edge.values().map(|&(idx, _)| idx).collect();
    edges.retain(|e| {
        let mut hasher = DefaultHasher::new();
        let mut ids = e.evidence_ids.clone();
        ids.sort();
        for id in &ids {
            id.hash(&mut hasher);
        }
        e.relation.hash(&mut hasher);
        best_edge.contains_key(&hasher.finish())
    });
}

/// Limit edges per node to prevent explosion
fn limit_edges_per_node(edges: &mut Vec<CorrelationEdge>, max_per_node: usize) {
    use std::collections::HashMap;
    let mut node_edge_count: HashMap<String, usize> = HashMap::new();

    edges.retain(|edge| {
        for evidence_id in &edge.evidence_ids {
            let count = node_edge_count.entry(evidence_id.clone()).or_insert(0);
            if *count >= max_per_node {
                return false;
            }
        }
        for evidence_id in &edge.evidence_ids {
            *node_edge_count.entry(evidence_id.clone()).or_insert(0) += 1;
        }
        true
    });
}

/// Main correlation function applying all rules
pub fn correlate(evidence: &[Evidence], configs: &[CorrelationConfig]) -> Vec<CorrelationEdge> {
    let mut all_edges = Vec::new();

    for config in configs {
        let rule: Box<dyn CorrelationRule> = match config.method {
            CorrelationMethod::PidLink => Box::new(PidLinkRule),
            CorrelationMethod::TemporalAdjacent => Box::new(TemporalAdjacentRule),
            CorrelationMethod::EvidenceSupport => Box::new(EvidenceSupportRule),
        };

        let edges = rule.correlate(evidence, config);
        all_edges.extend(edges);
    }

    // Global deduplication
    deduplicate_edges(&mut all_edges);
    all_edges
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Evidence;
    use jockey_evidence::model::EvidenceType;
    use chrono::Utc;
    use serde_json::json;
    use ulid::Ulid;

    fn make_process_evidence(pid: u32, ppid: u32, name: &str, cmdline: &str) -> Evidence {
        Evidence::new(
            "run-1".to_string(),
            "step-1".to_string(),
            "proc_linux".to_string(),
            EvidenceType::Process,
            format!("Process: {}", name),
            format!("/proc/{}", pid),
            1024,
            Ulid::new().to_string(),
            json!({
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "cmdline": cmdline,
            }),
        )
    }

    fn make_file_evidence(path: &str, hash: &str) -> Evidence {
        Evidence::new(
            "run-1".to_string(),
            "step-2".to_string(),
            "file_linux".to_string(),
            EvidenceType::File,
            format!("File: {}", path),
            path.to_string(),
            2048,
            Ulid::new().to_string(),
            json!({
                "path": path,
                "hash": hash,
            }),
        )
    }

    #[test]
    fn test_pid_link_rule() {
        let parent = make_process_evidence(100, 1, "bash", "bash");
        let child = make_process_evidence(200, 100, "ls", "ls -la");
        let unrelated = make_process_evidence(300, 1, "cat", "cat file");

        let evidence = vec![parent.clone(), child.clone(), unrelated];
        let config = CorrelationConfig::default();

        let rule = PidLinkRule;
        let edges = rule.correlate(&evidence, &config);

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].relation, "pid_link");
        assert!(edges[0].confidence >= 0.9);
        assert!(edges[0].evidence_ids.contains(&parent.id));
        assert!(edges[0].evidence_ids.contains(&child.id));
    }

    #[test]
    fn test_temporal_adjacent_rule() {
        let mut ev1 = make_process_evidence(100, 1, "bash", "bash");
        ev1.collected_at = Utc::now();
        
        let mut ev2 = make_process_evidence(200, 100, "ls", "ls -la");
        ev2.collected_at = Utc::now() + chrono::Duration::seconds(10);
        
        let mut ev3 = make_process_evidence(300, 1, "cat", "cat file");
        ev3.collected_at = Utc::now() + chrono::Duration::seconds(600); // Outside 300s window

        let evidence = vec![ev1, ev2, ev3];
        let config = CorrelationConfig {
            method: CorrelationMethod::TemporalAdjacent,
            window_seconds: Some(300),
            min_confidence: 0.5,
            max_edges_per_node: 10,
        };

        let rule = TemporalAdjacentRule;
        let edges = rule.correlate(&evidence, &config);

        // ev1 and ev2 should be correlated (10s apart)
        // ev3 is 600s away, outside window
        assert!(edges.len() >= 1);
    }

    #[test]
    fn test_evidence_support_rule_hash() {
        let hash = "abc123def456";
        let ev1 = make_file_evidence("/tmp/malware.exe", hash);
        let mut ev2 = make_file_evidence("/var/tmp/malware.exe", hash);
        ev2.metadata["mitre_tags"] = json!(["T1003.001"]);
        
        let evidence = vec![ev1, ev2];
        let config = CorrelationConfig {
            method: CorrelationMethod::EvidenceSupport,
            window_seconds: None,
            min_confidence: 0.5,
            max_edges_per_node: 10,
        };

        let rule = EvidenceSupportRule;
        let edges = rule.correlate(&evidence, &config);

        // Should find hash match
        assert!(edges.len() >= 1);
        let hash_edge = edges.iter().find(|e| {
            e.details.get("shared_indicator").and_then(|v| v.as_str()) == Some(&format!("hash:{}", hash))
        });
        assert!(hash_edge.is_some());
        assert!(hash_edge.unwrap().confidence >= 0.9);
    }

    #[test]
    fn test_full_correlate() {
        let parent = make_process_evidence(100, 1, "powershell", "powershell -enc ...");
        let child = make_process_evidence(200, 100, "cmd", "cmd /c whoami");
        let file = make_file_evidence("/tmp/output.txt", "hash123");

        let evidence = vec![parent, child, file];
        let configs = vec![
            CorrelationConfig { method: CorrelationMethod::PidLink, ..Default::default() },
            CorrelationConfig { method: CorrelationMethod::TemporalAdjacent, window_seconds: Some(300), ..Default::default() },
            CorrelationConfig { method: CorrelationMethod::EvidenceSupport, ..Default::default() },
        ];

        let edges = correlate(&evidence, &configs);
        
        // Should have pid_link + temporal_adjacent edges
        assert!(edges.len() >= 2);
        
        let methods: Vec<_> = edges.iter().map(|e| e.method.clone()).collect();
        assert!(methods.contains(&"pid_link".to_string()));
        assert!(methods.contains(&"temporal_adjacent".to_string()));
    }
}