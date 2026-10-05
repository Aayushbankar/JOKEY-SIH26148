//! Golden parser tests - validates all example scripts from docs/language/examples.md parse correctly

use std::fs;
use std::path::Path;

#[test]
fn golden_parser_tests() {
    let test_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/parser");
    
    let mut entries: Vec<_> = fs::read_dir(&test_dir)
        .expect("Failed to read golden test directory")
        .filter_map(|e| e.ok())
        .collect();
    
    entries.sort_by_key(|e| e.path());
    
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("jky") {
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("Failed to read {}", path.display()));
            
            // Parse and compile to IR
            let ir = jockey_language::compile_to_ir(&source)
                .unwrap_or_else(|e| panic!("Failed to parse {}: {:?}", path.display(), e));
            
            // Verify IR has expected structure
            assert!(!ir.metadata.name.is_empty(), "Module name should not be empty for {}", path.display());
            assert!(!ir.steps.is_empty(), "Should have at least one step for {}", path.display());
            
            // Verify each step has required fields
            for step in &ir.steps {
                assert!(!step.id.is_empty(), "Step ID should not be empty");
                assert!(!step.collector.is_empty(), "Collector should not be empty");
                assert!(!step.action.is_empty(), "Action should not be empty");
            }
            
            println!("✓ {} parsed successfully ({} steps)", path.file_name().unwrap().to_string_lossy(), ir.steps.len());
        }
    }
}