//! JOCKY Core — SQLite Storage
//!
//! Implements the relational schema per §17.1 with 6 tables and 5 indexes.

use std::path::Path;
use std::sync::Arc;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params, OptionalExtension};
use serde_json::Value;
use tracing::{debug, info};
use ulid::Ulid;

use crate::contract::ExecutionContract;
use crate::ir::IrModule;
use jockey_evidence::model::Evidence;
use jockey_evidence::receipt::EvidenceReceipt;
use jockey_evidence::provenance::ProvenanceRecord;

/// Storage error types
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database connection failed: {0}")]
    Connection(String),
    #[error("Migration failed: {0}")]
    Migration(String),
    #[error("Query failed: {0}")]
    Query(String),
    #[error("Serialization failed: {0}")]
    Serialization(String),
    #[error("Record not found: {0}")]
    NotFound(String),
}

/// SQLite-backed storage for JOCKY investigations
pub struct Storage {
    conn: Arc<Connection>,
}

impl Storage {
    /// Open or create a database at the given path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let conn = Connection::open(path)
            .map_err(|e| StorageError::Connection(e.to_string()))?;
        
        let storage = Self {
            conn: Arc::new(conn),
        };
        
        storage.migrate()?;
        info!("Storage initialized");
        Ok(storage)
    }

    /// Run database migrations
    fn migrate(&self) -> Result<(), StorageError> {
        // Enable foreign keys
        self.conn.execute("PRAGMA foreign_keys = ON", [])
            .map_err(|e| StorageError::Migration(e.to_string()))?;

        // Table 1: investigations
        self.conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS investigations (
                run_id TEXT PRIMARY KEY,
                ir_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_identifier TEXT NOT NULL,
                target_os TEXT NOT NULL,
                target_arch TEXT NOT NULL,
                policy_parallelism INTEGER NOT NULL,
                policy_continue_on_error INTEGER NOT NULL,
                policy_evidence_root TEXT NOT NULL,
                policy_hash_algorithm TEXT NOT NULL,
                context_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                error_message TEXT
            )
            "#,
            [],
        ).map_err(|e| StorageError::Migration(e.to_string()))?;

        // Table 2: evidence
        self.conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                step_id TEXT NOT NULL,
                collector TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                size INTEGER NOT NULL,
                hash TEXT NOT NULL,
                hash_algo TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES investigations(run_id) ON DELETE CASCADE
            )
            "#,
            [],
        ).map_err(|e| StorageError::Migration(e.to_string()))?;

        // Table 3: receipts
        self.conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS receipts (
                id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                collector TEXT NOT NULL,
                collector_version TEXT NOT NULL,
                signature TEXT NOT NULL,
                public_key TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                payload_hash_algo TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                host_info_json TEXT NOT NULL,
                FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE,
                FOREIGN KEY (run_id) REFERENCES investigations(run_id) ON DELETE CASCADE
            )
            "#,
            [],
        ).map_err(|e| StorageError::Migration(e.to_string()))?;

        // Table 4: provenance
        self.conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS provenance (
                id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                prev_provenance_id TEXT,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                actor_version TEXT NOT NULL,
                input_hashes_json TEXT NOT NULL,
                output_hashes_json TEXT NOT NULL,
                parameters_json TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                signature TEXT NOT NULL,
                FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE,
                FOREIGN KEY (receipt_id) REFERENCES receipts(id) ON DELETE CASCADE,
                FOREIGN KEY (prev_provenance_id) REFERENCES provenance(id) ON DELETE SET NULL
            )
            "#,
            [],
        ).map_err(|e| StorageError::Migration(e.to_string()))?;

        // Table 5: correlations
        self.conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS correlations (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                source_evidence_id TEXT NOT NULL,
                target_evidence_id TEXT NOT NULL,
                correlation_type TEXT NOT NULL,
                relation TEXT NOT NULL,
                params_json TEXT NOT NULL,
                binding TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES investigations(run_id) ON DELETE CASCADE,
                FOREIGN KEY (source_evidence_id) REFERENCES evidence(id) ON DELETE CASCADE,
                FOREIGN KEY (target_evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
            )
            "#,
            [],
        ).map_err(|e| StorageError::Migration(e.to_string()))?;

        // Table 6: findings
        self.conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                hypothesis TEXT NOT NULL,
                evidence_ids_json TEXT NOT NULL,
                mitre_tags_json TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES investigations(run_id) ON DELETE CASCADE
            )
            "#,
            [],
        ).map_err(|e| StorageError::Migration(e.to_string()))?;

        // Index 1: evidence by run_id
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_run_id ON evidence(run_id)",
            [],
        ).map_err(|e| StorageError::Migration(e.to_string()))?;

        // Index 2: receipts by evidence_id
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_receipts_evidence_id ON receipts(evidence_id)",
            [],
        ).map_err(|e| StorageError::Migration(e.to_string()))?;

        // Index 3: provenance by evidence_id
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_provenance_evidence_id ON provenance(evidence_id)",
            [],
        ).map_err(|e| StorageError::Migration(e.to_string()))?;

        // Index 4: correlations by run_id
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_correlations_run_id ON correlations(run_id)",
            [],
        ).map_err(|e| StorageError::Migration(e.to_string()))?;

        // Index 5: findings by run_id
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id)",
            [],
        ).map_err(|e| StorageError::Migration(e.to_string()))?;

        debug!("Database migrations completed");
        Ok(())
    }

    /// Insert an investigation record
    pub fn insert_investigation(&self, contract: &ExecutionContract) -> Result<(), StorageError> {
        let target = &contract.target;
        let policy = &contract.policy;

        self.conn.execute(
            r#"
            INSERT INTO investigations (
                run_id, ir_id, target_type, target_identifier, target_os, target_arch,
                policy_parallelism, policy_continue_on_error, policy_evidence_root,
                policy_hash_algorithm, context_json, created_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
            "#,
            params![
                contract.run_id,
                contract.ir_id,
                target.target_type,
                target.identifier,
                target.os,
                target.arch,
                policy.parallelism as i64,
                policy.continue_on_error as i64,
                policy.evidence_root,
                policy.hash_algorithm,
                serde_json::to_string(&contract.context).map_err(|e| StorageError::Serialization(e.to_string()))?,
                contract.created_at.to_rfc3339(),
            ],
        ).map_err(|e| StorageError::Query(e.to_string()))?;

        Ok(())
    }

    /// Update investigation status
    pub fn update_investigation_status(&self, run_id: &str, status: &str, error: Option<&str>) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE investigations SET status = ?, error_message = ? WHERE run_id = ?",
            params![status, error, run_id],
        ).map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// Mark investigation as started
    pub fn mark_investigation_started(&self, run_id: &str) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE investigations SET started_at = ?, status = 'running' WHERE run_id = ?",
            params![Utc::now().to_rfc3339(), run_id],
        ).map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// Mark investigation as completed
    pub fn mark_investigation_completed(&self, run_id: &str, status: &str) -> Result<(), StorageError> {
        self.conn.execute(
            "UPDATE investigations SET completed_at = ?, status = ? WHERE run_id = ?",
            params![Utc::now().to_rfc3339(), status, run_id],
        ).map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// Insert evidence record
    pub fn insert_evidence(&self, evidence: &Evidence) -> Result<(), StorageError> {
        self.conn.execute(
            r#"
            INSERT INTO evidence (
                id, run_id, step_id, collector, evidence_type, name, path,
                size, hash, hash_algo, metadata_json, collected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                evidence.id,
                evidence.run_id,
                evidence.step_id,
                evidence.collector,
                evidence.evidence_type,
                evidence.name,
                evidence.path,
                evidence.size as i64,
                evidence.hash,
                evidence.hash_algo,
                serde_json::to_string(&evidence.metadata).map_err(|e| StorageError::Serialization(e.to_string()))?,
                evidence.collected_at.to_rfc3339(),
            ],
        ).map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// Get evidence by run_id
    pub fn get_evidence_by_run(&self, run_id: &str) -> Result<Vec<Evidence>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, run_id, step_id, collector, evidence_type, name, path, size, hash, hash_algo, metadata_json, collected_at FROM evidence WHERE run_id = ?"
        ).map_err(|e| StorageError::Query(e.to_string()))?;

        let rows = stmt.query_map(params![run_id], |row| {
            let metadata_str: String = row.get(10)?;
            let collected_at_str: String = row.get(11)?;
            
            let metadata = serde_json::from_str(&metadata_str)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            let collected_at = DateTime::parse_from_rfc3339(&collected_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            Ok(Evidence {
                id: row.get(0)?,
                run_id: row.get(1)?,
                step_id: row.get(2)?,
                collector: row.get(3)?,
                evidence_type: row.get(4)?,
                name: row.get(5)?,
                path: row.get(6)?,
                size: row.get::<_, i64>(7)? as u64,
                hash: row.get(8)?,
                hash_algo: row.get(9)?,
                metadata,
                collected_at,
            })
        }).map_err(|e| StorageError::Query(e.to_string()))?;

        let mut evidence = Vec::new();
        for row in rows {
            evidence.push(row.map_err(|e| StorageError::Query(e.to_string()))?);
        }
        Ok(evidence)
    }

    /// Insert receipt record
    pub fn insert_receipt(&self, receipt: &EvidenceReceipt) -> Result<(), StorageError> {
        self.conn.execute(
            r#"
            INSERT INTO receipts (
                id, evidence_id, run_id, collector, collector_version,
                signature, public_key, payload_hash, payload_hash_algo,
                timestamp, host_info_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                receipt.id,
                receipt.evidence_id,
                receipt.run_id,
                receipt.collector,
                receipt.collector_version,
                receipt.signature,
                receipt.public_key,
                receipt.payload_hash,
                receipt.payload_hash_algo,
                receipt.timestamp.to_rfc3339(),
                serde_json::to_string(&receipt.host_info).map_err(|e| StorageError::Serialization(e.to_string()))?,
            ],
        ).map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// Get receipts by run_id
    pub fn get_receipts_by_run(&self, run_id: &str) -> Result<Vec<EvidenceReceipt>, StorageError> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, evidence_id, run_id, collector, collector_version,
                   signature, public_key, payload_hash, payload_hash_algo,
                   timestamp, host_info_json
            FROM receipts WHERE run_id = ?
            "#
        ).map_err(|e| StorageError::Query(e.to_string()))?;

        let rows = stmt.query_map(params![run_id], |row| {
            let host_info_json: String = row.get(10)?;
            let host_info = serde_json::from_str(&host_info_json)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            
            Ok(EvidenceReceipt {
                id: row.get(0)?,
                evidence_id: row.get(1)?,
                run_id: row.get(2)?,
                collector: row.get(3)?,
                collector_version: row.get(4)?,
                signature: row.get(5)?,
                public_key: row.get(6)?,
                payload_hash: row.get(7)?,
                payload_hash_algo: row.get(8)?,
                timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                host_info,
            })
        }).map_err(|e| StorageError::Query(e.to_string()))?;

        let mut receipts = Vec::new();
        for row in rows {
            receipts.push(row.map_err(|e| StorageError::Query(e.to_string()))?);
        }
        Ok(receipts)
    }

    /// Insert provenance record
    pub fn insert_provenance(&self, record: &ProvenanceRecord) -> Result<(), StorageError> {
        self.conn.execute(
            r#"
            INSERT INTO provenance (
                id, evidence_id, receipt_id, prev_provenance_id,
                action, actor, actor_version, input_hashes_json,
                output_hashes_json, parameters_json, timestamp, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                record.id,
                record.evidence_id,
                record.receipt_id,
                record.prev_provenance_id,
                record.action,
                record.actor,
                record.actor_version,
                serde_json::to_string(&record.input_hashes).map_err(|e| StorageError::Serialization(e.to_string()))?,
                serde_json::to_string(&record.output_hashes).map_err(|e| StorageError::Serialization(e.to_string()))?,
                serde_json::to_string(&record.parameters).map_err(|e| StorageError::Serialization(e.to_string()))?,
                record.timestamp.to_rfc3339(),
                record.signature,
            ],
        ).map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// Get provenance chain by evidence_id
    pub fn get_provenance_by_evidence(&self, evidence_id: &str) -> Result<Vec<ProvenanceRecord>, StorageError> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, evidence_id, receipt_id, prev_provenance_id,
                   action, actor, actor_version, input_hashes_json,
                   output_hashes_json, parameters_json, timestamp, signature
            FROM provenance WHERE evidence_id = ?
            ORDER BY timestamp ASC
            "#
        ).map_err(|e| StorageError::Query(e.to_string()))?;

        let rows = stmt.query_map(params![evidence_id], |row| {
            let input_hashes: Vec<String> = serde_json::from_str(&row.get::<_, String>(7)?)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            let output_hashes: Vec<String> = serde_json::from_str(&row.get::<_, String>(8)?)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            let parameters: Value = serde_json::from_str(&row.get::<_, String>(9)?)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            Ok(ProvenanceRecord {
                id: row.get(0)?,
                evidence_id: row.get(1)?,
                receipt_id: row.get(2)?,
                prev_provenance_id: row.get(3)?,
                action: row.get(4)?,
                actor: row.get(5)?,
                actor_version: row.get(6)?,
                input_hashes,
                output_hashes,
                parameters,
                timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(10)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                signature: row.get(11)?,
            })
        }).map_err(|e| StorageError::Query(e.to_string()))?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|e| StorageError::Query(e.to_string()))?);
        }
        Ok(records)
    }

    /// Insert correlation record
    pub fn insert_correlation(
        &self,
        run_id: &str,
        source_evidence_id: &str,
        target_evidence_id: &str,
        correlation_type: &str,
        relation: &str,
        params: &Value,
        binding: &str,
    ) -> Result<(), StorageError> {
        let id = Ulid::new().to_string();
        self.conn.execute(
            r#"
            INSERT INTO correlations (
                id, run_id, source_evidence_id, target_evidence_id,
                correlation_type, relation, params_json, binding, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                id,
                run_id,
                source_evidence_id,
                target_evidence_id,
                correlation_type,
                relation,
                serde_json::to_string(params).map_err(|e| StorageError::Serialization(e.to_string()))?,
                binding,
                Utc::now().to_rfc3339(),
            ],
        ).map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// Get correlations by run_id
    pub fn get_correlations_by_run(&self, run_id: &str) -> Result<Vec<CorrelationRow>, StorageError> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, run_id, source_evidence_id, target_evidence_id,
                   correlation_type, relation, params_json, binding, created_at
            FROM correlations WHERE run_id = ?
            "#
        ).map_err(|e| StorageError::Query(e.to_string()))?;

        let rows = stmt.query_map(params![run_id], |row| {
            Ok(CorrelationRow {
                id: row.get(0)?,
                run_id: row.get(1)?,
                source_evidence_id: row.get(2)?,
                target_evidence_id: row.get(3)?,
                correlation_type: row.get(4)?,
                relation: row.get(5)?,
                params: serde_json::from_str(&row.get::<_, String>(6)?)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                binding: row.get(7)?,
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
            })
        }).map_err(|e| StorageError::Query(e.to_string()))?;

        let mut correlations = Vec::new();
        for row in rows {
            correlations.push(row.map_err(|e| StorageError::Query(e.to_string()))?);
        }
        Ok(correlations)
    }

    /// Insert finding record
    pub fn insert_finding(
        &self,
        run_id: &str,
        hypothesis: &str,
        evidence_ids: &[String],
        mitre_tags: &[String],
        description: &str,
        severity: &str,
    ) -> Result<(), StorageError> {
        let id = Ulid::new().to_string();
        self.conn.execute(
            r#"
            INSERT INTO findings (
                id, run_id, hypothesis, evidence_ids_json,
                mitre_tags_json, description, severity, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                id,
                run_id,
                hypothesis,
                serde_json::to_string(evidence_ids).map_err(|e| StorageError::Serialization(e.to_string()))?,
                serde_json::to_string(mitre_tags).map_err(|e| StorageError::Serialization(e.to_string()))?,
                description,
                severity,
                Utc::now().to_rfc3339(),
            ],
        ).map_err(|e| StorageError::Query(e.to_string()))?;
        Ok(())
    }

    /// Get investigation by run_id
    pub fn get_investigation(&self, run_id: &str) -> Result<Option<InvestigationRow>, StorageError> {
        let row = self.conn.query_row(
            r#"
            SELECT run_id, ir_id, target_type, target_identifier, target_os, target_arch,
                   policy_parallelism, policy_continue_on_error, policy_evidence_root,
                   policy_hash_algorithm, context_json, created_at, started_at, completed_at, status, error_message
            FROM investigations WHERE run_id = ?
            "#,
            params![run_id],
            |row| {
                Ok(InvestigationRow {
                    run_id: row.get(0)?,
                    ir_id: row.get(1)?,
                    target_type: row.get(2)?,
                    target_identifier: row.get(3)?,
                    target_os: row.get(4)?,
                    target_arch: row.get(5)?,
                    policy_parallelism: row.get(6)?,
                    policy_continue_on_error: row.get(7)?,
                    policy_evidence_root: row.get(8)?,
                    policy_hash_algorithm: row.get(9)?,
                    context: serde_json::from_str(&row.get::<_, String>(10)?)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(11)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                    started_at: row.get::<_, Option<String>>(12)?
                        .map(|s| DateTime::parse_from_rfc3339(&s)
                            .map(|dt| dt.with_timezone(&Utc))
                            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e))))
                        .transpose()?,
                    completed_at: row.get::<_, Option<String>>(13)?
                        .map(|s| DateTime::parse_from_rfc3339(&s)
                            .map(|dt| dt.with_timezone(&Utc))
                            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e))))
                        .transpose()?,
                    status: row.get(14)?,
                    error_message: row.get(15)?,
                })
            },
        ).optional().map_err(|e| StorageError::Query(e.to_string()))?;

        Ok(row)
    }
}

/// Row type for investigations
#[derive(Debug, Clone)]
pub struct InvestigationRow {
    pub run_id: String,
    pub ir_id: String,
    pub target_type: String,
    pub target_identifier: String,
    pub target_os: String,
    pub target_arch: String,
    pub policy_parallelism: u32,
    pub policy_continue_on_error: bool,
    pub policy_evidence_root: String,
    pub policy_hash_algorithm: String,
    pub context: Value,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: String,
    pub error_message: Option<String>,
}

/// Row type for correlations
#[derive(Debug, Clone)]
pub struct CorrelationRow {
    pub id: String,
    pub run_id: String,
    pub source_evidence_id: String,
    pub target_evidence_id: String,
    pub correlation_type: String,
    pub relation: String,
    pub params: Value,
    pub binding: String,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_storage_open_and_migrate() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let storage = Storage::open(&db_path).unwrap();
        
        // Verify tables exist by querying them
        let count: i64 = storage.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert!(count >= 6, "Should have at least 6 tables");
    }

    #[test]
    fn test_insert_and_get_investigation() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let storage = Storage::open(&db_path).unwrap();

        let contract = ExecutionContract {
            ir_id: "test-ir".to_string(),
            run_id: "test-run-1".to_string(),
            target: crate::target::TargetSpec::live("localhost", "linux"),
            steps: vec![],
            policy: crate::contract::ExecPolicy::new()
                .with_evidence_root("/tmp/evidence")
                .with_parallelism(2),
            context: serde_json::json!({}),
            created_at: Utc::now(),
        };

        storage.insert_investigation(&contract).unwrap();
        let investigation = storage.get_investigation("test-run-1").unwrap();
        assert!(investigation.is_some());
        assert_eq!(investigation.unwrap().run_id, "test-run-1");
    }

    #[test]
    fn test_insert_and_get_evidence() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let storage = Storage::open(&db_path).unwrap();

        // First insert the investigation (FK requirement)
        let contract = ExecutionContract {
            ir_id: "test-ir".to_string(),
            run_id: "run-1".to_string(),
            target: crate::target::TargetSpec::live("localhost", "linux"),
            steps: vec![],
            policy: crate::contract::ExecPolicy::new()
                .with_evidence_root("/tmp/evidence"),
            context: serde_json::json!({}),
            created_at: chrono::Utc::now(),
        };
        storage.insert_investigation(&contract).unwrap();

        let evidence = Evidence::new(
            "run-1".to_string(),
            "step-1".to_string(),
            "proc_linux".to_string(),
            jockey_evidence::model::EvidenceType::Process,
            "test-process".to_string(),
            "/proc/123".to_string(),
            1024,
            "abcd1234".to_string(),
            serde_json::json!({"pid": 123}),
        );

        storage.insert_evidence(&evidence).unwrap();
        let retrieved = storage.get_evidence_by_run("run-1").unwrap();
        assert_eq!(retrieved.len(), 1);
        assert_eq!(retrieved[0].id, evidence.id);
    }
}