//! JOCKY Collectors — Collector Trait, Windows/Linux Implementations
//! 
//! Provides the core collector trait, registry, and platform-specific forensic collectors.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod trait_def;
pub mod registry;
pub mod windows;
pub mod linux;

pub use trait_def::*;
pub use registry::*;
pub use jockey_evidence::model::Evidence;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn test_stub_compiles() {
        assert!(true);
    }

    #[test]
    fn test_registry_registration_and_lookup() {
        let mut registry = CollectorRegistry::new();
        assert!(registry.get("proc_windows").is_none());

        let keypair = Arc::new(jockey_evidence::receipt::CollectorKeypair::generate());
        let collector = Box::new(windows::ProcWindowsCollector::new(keypair.clone()));
        assert!(registry.register(collector).is_ok());

        assert!(registry.get("proc_windows").is_some());
        assert_eq!(registry.get_for_os("windows").len(), 1);
        assert_eq!(registry.get_for_os("linux").len(), 0);

        // Duplicate registration should fail
        let collector_dup = Box::new(windows::ProcWindowsCollector::new(keypair));
        assert!(matches!(
            registry.register(collector_dup),
            Err(RegistryError::AlreadyRegistered(_))
        ));
    }

    #[tokio::test]
    async fn test_proc_windows_metadata_and_execution() {
        let keypair = Arc::new(jockey_evidence::receipt::CollectorKeypair::generate());
        let collector = windows::ProcWindowsCollector::new(keypair);

        assert_eq!(collector.name(), "proc_windows");
        assert_eq!(collector.version(), "0.1.0");
        assert!(collector.supported_os().contains(&"windows"));
        assert!(collector.supported_actions().contains(&"list"));
        assert!(collector.supported_actions().contains(&"get"));
        assert!(collector.supported_actions().contains(&"tree"));

        let dir = tempdir().unwrap();
        let evidence_root = dir.path().to_path_buf();
        let temp_dir = evidence_root.join("tmp");

        let context = ExecutionContext {
            run_id: "test_run_1".to_string(),
            evidence_root: evidence_root.clone(),
            target: jockey_core::TargetSpec::live("localhost", "windows"),
            temp_dir,
            credentials: None,
        };

        // Test list action
        let list_output = collector
            .execute("list", serde_json::json!({}), &context)
            .await
            .expect("list action should succeed");

        assert!(!list_output.evidence.is_empty());
        assert_eq!(list_output.evidence.len(), list_output.artifacts.len());
        let ev = &list_output.evidence[0];
        assert_eq!(ev.run_id, "test_run_1");
        assert_eq!(ev.collector, "proc_windows");
        assert_eq!(ev.hash_algo, "sha256");

        // Verify evidence file exists on disk
        let disk_path = evidence_root.join(&ev.path);
        assert!(disk_path.exists());

        // Test tree action
        let tree_output = collector
            .execute("tree", serde_json::json!({}), &context)
            .await
            .expect("tree action should succeed");
        assert_eq!(tree_output.evidence.len(), 1);

        // Test get action
        let get_output = collector
            .execute("get", serde_json::json!({ "pid": 1234 }), &context)
            .await
            .expect("get action should succeed");
        assert_eq!(get_output.evidence.len(), 1);

        // Test unsupported action
        let err = collector
            .execute("invalid_action", serde_json::json!({}), &context)
            .await
            .unwrap_err();
        assert!(matches!(err, CollectorError::UnsupportedAction(_)));
    }
}