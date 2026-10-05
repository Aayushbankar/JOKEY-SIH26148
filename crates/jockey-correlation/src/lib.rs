//! JOCKY Correlation — Deterministic Correlation Rules, Investigation Graph, Query API
//!
//! Implements three deterministic correlation rules:
//! - `pid_link`: Parent-child process relationships
//! - `temporal_adjacent`: Events within a time window
//! - `evidence_support`: Shared indicators/IOCs across evidence

#![warn(missing_docs)]
#![warn(clippy::all)]

/// Correlation Rules module
pub mod rules;

/// Correlation Engine module
pub mod engine {
    use crate::graph::{CorrelationEdge, EvidenceNode, InvestigationGraph};
    use crate::rules::CorrelationConfig;
    use crate::evidence::Evidence;
    use petgraph::graph::NodeIndex;
    use std::collections::HashMap;

    /// Correlator builds investigation graphs from evidence
    pub struct Correlator {
        configs: Vec<CorrelationConfig>,
    }

    impl Correlator {
        /// Create a new correlator with default rules
        pub fn new() -> Self {
            Self {
                configs: vec![
                    CorrelationConfig {
                        method: crate::rules::CorrelationMethod::PidLink,
                        ..Default::default()
                    },
                    CorrelationConfig {
                        method: crate::rules::CorrelationMethod::TemporalAdjacent,
                        window_seconds: Some(300),
                        ..Default::default()
                    },
                    CorrelationConfig {
                        method: crate::rules::CorrelationMethod::EvidenceSupport,
                        ..Default::default()
                    },
                ],
            }
        }

        /// Create a correlator with custom configs
        pub fn with_configs(configs: Vec<CorrelationConfig>) -> Self {
            Self { configs }
        }

        /// Build an investigation graph from evidence
        pub fn build_graph(&self, evidence: &[Evidence]) -> InvestigationGraph {
            let edges = crate::rules::correlate(evidence, &self.configs);
            
            let mut graph = InvestigationGraph::new();
            let mut node_map: HashMap<String, NodeIndex> = HashMap::new();

            // Add evidence nodes
            for ev in evidence {
                let node = EvidenceNode {
                    evidence_id: ev.id.clone(),
                    evidence_type: ev.evidence_type.clone(),
                    timestamp: ev.collected_at,
                    summary: format!("{}: {}", ev.evidence_type, ev.name),
                    metadata: ev.metadata.clone(),
                };
                let idx = graph.add_node(node);
                node_map.insert(ev.id.clone(), idx);
            }

            // Add correlation edges
            for edge in edges {
                if edge.evidence_ids.len() >= 2 {
                    let source_id = &edge.evidence_ids[0];
                    let target_id = &edge.evidence_ids[1];
                    
                    if let (Some(&source_idx), Some(&target_idx)) = 
                        (node_map.get(source_id), node_map.get(target_id)) {
                        graph.add_edge(source_idx, target_idx, edge);
                    }
                }
            }

            graph
        }
    }

    impl Default for Correlator {
        fn default() -> Self {
            Self::new()
        }
    }
}

/// Graph module
pub mod graph {
    use petgraph::graph::Graph;
    use serde_json::{Value, Map};
    use chrono::DateTime;
    
    /// Evidence Node in the investigation graph
    #[derive(Clone, Debug, serde::Serialize)]
    pub struct EvidenceNode {
        pub evidence_id: String,
        pub evidence_type: String,
        pub timestamp: DateTime<chrono::Utc>,
        pub summary: String,
        pub metadata: Value,
    }
    
    /// Correlation Edge connecting evidence nodes
    #[derive(Clone, Debug, serde::Serialize)]
    pub struct CorrelationEdge {
        pub relation: String,
        pub confidence: f32,
        pub method: String,
        pub details: Value,
        pub evidence_ids: Vec<String>,
    }

    /// Investigation Graph using petgraph
    pub type InvestigationGraph = Graph<EvidenceNode, CorrelationEdge, petgraph::Directed>;

    /// Extension trait for Cytoscape export
    pub trait CytoscapeExport {
        fn to_cytoscape_json(&self) -> Value;
    }

    impl CytoscapeExport for InvestigationGraph {
        fn to_cytoscape_json(&self) -> Value {
            let mut nodes = Vec::new();
            let mut edges = Vec::new();
            
            for idx in self.node_indices() {
                if let Some(node) = self.node_weight(idx) {
                    nodes.push(serde_json::json!({
                        "data": {
                            "id": node.evidence_id,
                            "label": node.summary,
                            "type": node.evidence_type,
                            "timestamp": node.timestamp.to_rfc3339(),
                            "metadata": node.metadata,
                        }
                    }));
                }
            }
            
            for edge_idx in self.edge_indices() {
                if let Some(edge) = self.edge_weight(edge_idx) {
                    let (source, target) = self.edge_endpoints(edge_idx).unwrap();
                    edges.push(serde_json::json!({
                        "data": {
                            "id": format!("edge-{}", edge_idx.index()),
                            "source": self.node_weight(source).unwrap().evidence_id,
                            "target": self.node_weight(target).unwrap().evidence_id,
                            "relation": edge.relation,
                            "confidence": edge.confidence,
                            "method": edge.method,
                            "details": edge.details,
                        }
                    }));
                }
            }
            
            let mut map = Map::new();
            map.insert("nodes".to_string(), Value::Array(nodes));
            map.insert("edges".to_string(), Value::Array(edges));
            Value::Object(map)
        }
    }
}

pub use graph::{CorrelationEdge, EvidenceNode, InvestigationGraph, CytoscapeExport};
pub use engine::Correlator;
pub use hypothesis::{Hypothesis, HypothesisStatus};
pub use rules::{correlate, CorrelationConfig, CorrelationMethod, CorrelationRule};

/// Hypothesis module for tracking investigative hypotheses
pub mod hypothesis {
    use serde_json::Value;
    use chrono::DateTime;

    /// Hypothesis in an investigation
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub struct Hypothesis {
        pub id: String,
        pub description: String,
        pub mitre_tags: Vec<String>,
        pub confidence: f32,
        pub status: HypothesisStatus,
        pub supporting_evidence_ids: Vec<String>,
        pub refuting_evidence_ids: Vec<String>,
        pub created_at: DateTime<chrono::Utc>,
        pub updated_at: DateTime<chrono::Utc>,
    }
    
    /// Hypothesis Status
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub enum HypothesisStatus {
        Open,
        Confirmed,
        Refuted,
        Superseded,
    }

    impl Hypothesis {
        pub fn new(id: String, description: String, mitre_tags: Vec<String>) -> Self {
            let now = chrono::Utc::now();
            Self {
                id,
                description,
                mitre_tags,
                confidence: 0.5,
                status: HypothesisStatus::Open,
                supporting_evidence_ids: Vec::new(),
                refuting_evidence_ids: Vec::new(),
                created_at: now,
                updated_at: now,
            }
        }
    }
}

/// Evidence module re-export from jockey-evidence
pub mod evidence {
    pub use jockey_evidence::model::Evidence;
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn test_stub_compiles() {
        assert!(true);
    }

    #[test]
    fn test_investigation_graph_construction() {
        let mut graph: InvestigationGraph = petgraph::graph::Graph::new();

        let n1 = graph.add_node(EvidenceNode {
            evidence_id: "ev-01".to_string(),
            evidence_type: "process".to_string(),
            timestamp: Utc::now(),
            summary: "Process spawned".to_string(),
            metadata: json!({"pid": 1234}),
        });

        let n2 = graph.add_node(EvidenceNode {
            evidence_id: "ev-02".to_string(),
            evidence_type: "file".to_string(),
            timestamp: Utc::now(),
            summary: "File created".to_string(),
            metadata: json!({"path": "/tmp/malicious"}),
        });

        let edge = CorrelationEdge {
            relation: "spawned_file".to_string(),
            confidence: 0.95,
            method: "proc_event".to_string(),
            details: json!({"action": "create"}),
            evidence_ids: vec!["ev-01".to_string(), "ev-02".to_string()],
        };

        graph.add_edge(n1, n2, edge);

        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);

        // Test Cytoscape export
        let cyto = graph.to_cytoscape_json();
        assert_eq!(cyto["nodes"].as_array().unwrap().len(), 2);
        assert_eq!(cyto["edges"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_hypothesis_model() {
        let hyp = Hypothesis {
            id: "hyp-001".to_string(),
            description: "Credential Dumping via LSASS".to_string(),
            mitre_tags: vec!["T1003.001".to_string()],
            confidence: 0.85,
            status: HypothesisStatus::Open,
            supporting_evidence_ids: vec!["ev-01".to_string()],
            refuting_evidence_ids: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(hyp.status, HypothesisStatus::Open);
        assert_eq!(hyp.confidence, 0.85);
    }

    #[test]
    fn test_correlator_build_graph() {
        let correlator = Correlator::new();
        
        let ev1 = crate::evidence::Evidence::new(
            "run-1".to_string(),
            "step-1".to_string(),
            "proc_linux".to_string(),
            jockey_evidence::model::EvidenceType::Process,
            "bash".to_string(),
            "/proc/100".to_string(),
            1024,
            "hash1".to_string(),
            serde_json::json!({"pid": 100, "ppid": 1, "name": "bash"}),
        );
        
        let mut ev2 = crate::evidence::Evidence::new(
            "run-1".to_string(),
            "step-2".to_string(),
            "proc_linux".to_string(),
            jockey_evidence::model::EvidenceType::Process,
            "ls".to_string(),
            "/proc/200".to_string(),
            1024,
            "hash2".to_string(),
            serde_json::json!({"pid": 200, "ppid": 100, "name": "ls"}),
        );
        // Make ev2 slightly later for temporal correlation
        ev2.collected_at = chrono::Utc::now() + chrono::Duration::seconds(10);

        let graph = correlator.build_graph(&[ev1, ev2]);
        
        assert_eq!(graph.node_count(), 2);
        assert!(graph.edge_count() >= 1); // pid_link + temporal
    }
}