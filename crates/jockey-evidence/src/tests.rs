//! Evidence Crypto & Tamper Detection Tests
//!
//! Implements the 7 tamper detection scenarios from Milestone 2.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Evidence;
    use crate::receipt::{EvidenceReceipt, CollectorKeypair, HostInfo};
    use crate::provenance::ProvenanceRecord;
    use crate::verification::{verify_receipt, verify_provenance_chain, verify_investigation};
    use crate::{VerificationReport, VerificationStatus, VerificationSummary, EvidenceVerificationResult, VerificationChecks, ProvenanceVerificationResult, VerifyError};
    use chrono::Utc;
    use ulid::Ulid;
    use std::collections::HashMap;

    fn create_test_evidence() -> Evidence {
        Evidence::new(
            "run_123".to_string(),
            "step_1".to_string(),
            "proc_linux".to_string(),
            crate::model::EvidenceType::Process,
            "test_process".to_string(),
            "/proc/123/stat".to_string(),
            1024,
            "abcd1234".to_string(),
            serde_json::json!({}),
        )
    }

    fn create_test_keypair() -> CollectorKeypair {
        CollectorKeypair::generate()
    }

    fn create_test_host_info() -> HostInfo {
        HostInfo {
            hostname: "test-host".to_string(),
            os: "linux".to_string(),
            kernel: Some("6.1.0".to_string()),
            collector_pid: 1234,
        }
    }

    #[test]
    fn test_evidence_sign_verify_roundtrip() {
        // Test 1: Evidence Sign & Verify Roundtrip
        let evidence = create_test_evidence();
        let keypair = create_test_keypair();
        let host_info = create_test_host_info();

        // Generate receipt
        let receipt = EvidenceReceipt::new(
            &evidence,
            "proc_linux",
            "0.1.0",
            &keypair,
            host_info,
        );

        // Verify receipt
        let result = receipt.verify(&evidence, &keypair);
        assert!(result, "Valid evidence and receipt should pass verification");

        // Verify via verification module
        let verify_result = verify_receipt(&receipt, &evidence, &keypair);
        assert!(verify_result.is_ok(), "Verification should succeed for valid evidence");
    }

    #[test]
    fn test_evidence_bit_flip_tamper_detection() {
        // Test 2: Evidence Bit-Flip Tamper Detection
        let evidence = create_test_evidence();
        let keypair = create_test_keypair();
        let host_info = create_test_host_info();

        let receipt = EvidenceReceipt::new(
            &evidence,
            "proc_linux",
            "0.1.0",
            &keypair,
            host_info,
        );

        // Tamper with evidence hash (flip a bit)
        let mut tampered_evidence = evidence.clone();
        // Flip the first bit of the hash
        let mut hash_bytes = hex::decode(&tampered_evidence.hash).unwrap();
        hash_bytes[0] ^= 0x01;
        tampered_evidence.hash = hex::encode(hash_bytes);

        // Verification should fail
        let result = receipt.verify(&tampered_evidence, &keypair);
        assert!(!result, "Tampered evidence hash should fail verification");

        let verify_result = verify_receipt(&receipt, &tampered_evidence, &keypair);
        assert!(verify_result.is_err(), "Verification should fail for tampered evidence");
        match verify_result.unwrap_err() {
            VerifyError::HashMismatch { .. } => {}, // Expected
            e => panic!("Expected HashMismatch, got: {:?}", e),
        }
    }

    #[test]
    fn test_receipt_signature_tamper_detection() {
        // Test 3: Receipt Signature Tamper Detection
        let evidence = create_test_evidence();
        let keypair = create_test_keypair();
        let host_info = create_test_host_info();

        let mut receipt = EvidenceReceipt::new(
            &evidence,
            "proc_linux",
            "0.1.0",
            &keypair,
            host_info,
        );

        // Tamper with receipt signature (flip a bit)
        let mut sig_bytes = hex::decode(&receipt.signature).unwrap();
        sig_bytes[0] ^= 0x01;
        receipt.signature = hex::encode(sig_bytes);

        // Verification should fail
        let result = receipt.verify(&evidence, &keypair);
        assert!(!result, "Tampered receipt signature should fail verification");

        let verify_result = verify_receipt(&receipt, &evidence, &keypair);
        assert!(verify_result.is_err(), "Verification should fail for tampered signature");
        match verify_result.unwrap_err() {
            VerifyError::SignatureInvalid(_) => {}, // Expected
            e => panic!("Expected SignatureInvalid, got: {:?}", e),
        }
    }

    #[test]
    fn test_broken_provenance_chain_detection() {
        // Test 4: Broken Provenance Chain Detection
        let evidence = create_test_evidence();
        let keypair = create_test_keypair();
        let host_info = create_test_host_info();

        // Create a valid provenance chain
        let receipt = EvidenceReceipt::new(
            &evidence,
            "proc_linux",
            "0.1.0",
            &keypair,
            host_info,
        );

        let mut chain = vec![
            ProvenanceRecord::new_collected(
                evidence.id.clone(),
                receipt.id.clone(),
                "proc_linux",
                "0.1.0",
                evidence.hash.clone(),
            ),
            ProvenanceRecord::new_collected(
                evidence.id.clone(),
                receipt.id.clone(),
                "proc_linux",
                "0.1.0",
                evidence.hash.clone(),
            ),
        ];
        // Link second record to first
        chain[1].prev_provenance_id = Some(chain[0].id.clone());
        chain[1].action = "transformed".to_string();
        chain[1].input_hashes = vec![chain[0].output_hashes[0].clone()];
        chain[1].output_hashes = vec![evidence.hash.clone()];

        // Verify valid chain
        let result = verify_provenance_chain(&chain);
        assert!(result.is_ok(), "Valid provenance chain should pass");

        // Break the chain by modifying prev_provenance_id
        chain[1].prev_provenance_id = Some("broken-link-id".to_string());

        let result = verify_provenance_chain(&chain);
        assert!(result.is_err(), "Broken provenance chain should fail");
        match result.unwrap_err() {
            VerifyError::SignatureInvalid(msg) => {
                assert!(msg.contains("chain broken"), "Error should mention chain broken: {}", msg);
            },
            e => panic!("Expected SignatureInvalid for broken chain, got: {:?}", e),
        }
    }

    #[test]
    fn test_provenance_output_hash_tamper_detection() {
        // Test 5: Provenance Output Hash Tamper Detection
        // The verification checks that each record's input_hashes matches the previous record's output_hashes.
        // By creating a 2-record chain and tampering with the first record's output_hash,
        // the second record's input_hashes check will fail.
        let evidence = create_test_evidence();
        let keypair = create_test_keypair();
        let host_info = create_test_host_info();

        let receipt = EvidenceReceipt::new(
            &evidence,
            "proc_linux",
            "0.1.0",
            &keypair,
            host_info,
        );

        // Create a valid 2-record chain
        let mut chain = vec![
            ProvenanceRecord::new_collected(
                evidence.id.clone(),
                receipt.id.clone(),
                "proc_linux",
                "0.1.0",
                evidence.hash.clone(),
            ),
            ProvenanceRecord::new_collected(
                evidence.id.clone(),
                receipt.id.clone(),
                "proc_linux",
                "0.1.0",
                evidence.hash.clone(),
            ),
        ];
        // Link second record to first
        chain[1].prev_provenance_id = Some(chain[0].id.clone());
        chain[1].action = "transformed".to_string();
        chain[1].input_hashes = vec![chain[0].output_hashes[0].clone()];
        chain[1].output_hashes = vec![evidence.hash.clone()];

        // Verify valid chain
        let result = verify_provenance_chain(&chain);
        assert!(result.is_ok(), "Valid provenance chain should pass");

        // Tamper with first record's output hash
        chain[0].output_hashes[0] = "tampered_hash".to_string();

        // The second record's input_hashes still references the original hash,
        // so the chain link verification should fail
        let result = verify_provenance_chain(&chain);
        assert!(result.is_err(), "Tampered provenance output hash should fail chain verification");
        match result.unwrap_err() {
            VerifyError::HashMismatch { .. } => {}, // Expected
            e => panic!("Expected HashMismatch for tampered provenance hash, got: {:?}", e),
        }
    }

    #[test]
    fn test_full_investigation_verification_pass() {
        // Test 6: Full Investigation Verification Pass
        let evidence = create_test_evidence();
        let keypair = create_test_keypair();
        let host_info = create_test_host_info();

        let receipt = EvidenceReceipt::new(
            &evidence,
            "proc_linux",
            "0.1.0",
            &keypair,
            host_info,
        );

        let provenance_chain = vec![
            ProvenanceRecord::new_collected(
                evidence.id.clone(),
                receipt.id.clone(),
                "proc_linux",
                "0.1.0",
                evidence.hash.clone(),
            ),
        ];

        let mut keypairs = HashMap::new();
        keypairs.insert("proc_linux".to_string(), keypair);

        let report = verify_investigation(
            &[evidence.clone()],
            &[receipt],
            &[provenance_chain],
            &keypairs,
        ).unwrap();

        assert_eq!(report.overall_status, VerificationStatus::Pass);
        assert_eq!(report.summary.total_evidence, 1);
        assert_eq!(report.summary.verified_evidence, 1);
        assert_eq!(report.summary.failed_evidence, 0);
        assert_eq!(report.summary.verified_chains, 1);
        
        // Check evidence verification result
        assert_eq!(report.evidence_results.len(), 1);
        assert_eq!(report.evidence_results[0].status, VerificationStatus::Pass);
        assert!(report.evidence_results[0].checks.receipt_signature);
        assert!(report.evidence_results[0].checks.payload_hash);
        assert!(report.evidence_results[0].checks.timestamp);
        assert!(report.evidence_results[0].checks.collector_version);
        assert!(report.evidence_results[0].checks.provenance_chain);
    }

    #[test]
    fn test_full_investigation_verification_fail() {
        // Test 7: Full Investigation Verification Fail
        let evidence = create_test_evidence();
        let keypair = create_test_keypair();
        let host_info = create_test_host_info();

        let receipt = EvidenceReceipt::new(
            &evidence,
            "proc_linux",
            "0.1.0",
            &keypair,
            host_info,
        );

        // Tamper with the evidence hash
        let mut tampered_evidence = evidence.clone();
        let mut hash_bytes = hex::decode(&tampered_evidence.hash).unwrap();
        hash_bytes[0] ^= 0x01;
        tampered_evidence.hash = hex::encode(hash_bytes);

        let provenance_chain = vec![
            ProvenanceRecord::new_collected(
                tampered_evidence.id.clone(),
                receipt.id.clone(),
                "proc_linux",
                "0.1.0",
                tampered_evidence.hash.clone(),
            ),
        ];

        let mut keypairs = HashMap::new();
        keypairs.insert("proc_linux".to_string(), keypair);

        let report = verify_investigation(
            &[tampered_evidence],
            &[receipt],
            &[provenance_chain],
            &keypairs,
        ).unwrap();

        assert_eq!(report.overall_status, VerificationStatus::Fail);
        assert_eq!(report.summary.total_evidence, 1);
        assert_eq!(report.summary.verified_evidence, 0);
        assert_eq!(report.summary.failed_evidence, 1);
        
        // Check evidence verification result
        assert_eq!(report.evidence_results.len(), 1);
        assert_eq!(report.evidence_results[0].status, VerificationStatus::Fail);
        assert!(!report.evidence_results[0].errors.is_empty());
    }
}