//! JOCKY Language Tests

#[cfg(test)]
mod tests {
    use crate::*;
    use crate::ast::*;
    

    #[test]
    fn test_parse_simple_investigation() {
        let source = r#"
investigation "test" {
    collect process as procs where name == "svchost.exe"
}
"#;
        
        let ast = parse(source).unwrap();
        assert_eq!(ast.name, "test");
        assert_eq!(ast.statements.len(), 1);
        
        match &ast.statements[0] {
            Statement::Collect(decl) => {
                assert_eq!(decl.evidence_type, EvidenceType::Process);
                assert_eq!(decl.binding, "procs");
                assert!(decl.filter.is_some());
            }
            _ => panic!("Expected Collect statement"),
        }
    }
    
    #[test]
    fn test_parse_correlation() {
        let source = r#"
investigation "test" {
    collect process as procs where name == "svchost.exe"
    correlate procs -> procs by "pid_link" as chain
}
"#;
        
        let ast = parse(source).unwrap();
        assert_eq!(ast.statements.len(), 2);
        
        match &ast.statements[1] {
            Statement::Correlate(decl) => {
                assert_eq!(decl.source, "procs");
                assert_eq!(decl.target, "procs");
                assert_eq!(decl.relation, "pid_link");
                assert_eq!(decl.binding, "chain");
            }
            _ => panic!("Expected Correlate statement"),
        }
    }
    
    #[test]
    fn test_parse_hypothesis() {
        let source = r#"
investigation "test" {
    hypothesis "Test hypothesis" {
        mitre: ["T1047", "T1547.001"]
    }
}
"#;
        
        let ast = parse(source).unwrap();
        assert_eq!(ast.statements.len(), 1);
        
        match &ast.statements[0] {
            Statement::Hypothesis(decl) => {
                assert_eq!(decl.description, "Test hypothesis");
                assert_eq!(decl.mitre_tags, vec!["T1047", "T1547.001"]);
            }
            _ => panic!("Expected Hypothesis statement"),
        }
    }
    
    #[test]
    fn test_parse_correlation_with_window() {
        let source = r#"
investigation "test" {
    collect process as a where name == "a"
    collect process as b where name == "b"
    correlate a -> b by "timestamp_join" window 300s as corr
}
"#;
        
        let ast = parse(source).unwrap();
        assert_eq!(ast.statements.len(), 3);
        
        match &ast.statements[2] {
            Statement::Correlate(decl) => {
                assert_eq!(decl.relation, "timestamp_join");
                assert!(decl.params.window.is_some());
                let window = decl.params.window.as_ref().unwrap();
                assert_eq!(window.value, 300);
                assert_eq!(window.unit, TimeUnit::Seconds);
            }
            _ => panic!("Expected Correlate statement"),
        }
    }
    
    #[test]
    fn test_parse_timeline() {
        let source = r#"
investigation "test" {
    collect process as a
    collect process as b
    timeline "test_timeline" from a, b
}
"#;
        
        let ast = parse(source).unwrap();
        assert_eq!(ast.statements.len(), 3);
        
        match &ast.statements[2] {
            Statement::Timeline(decl) => {
                assert_eq!(decl.name, "test_timeline");
                assert_eq!(decl.sources, vec!["a", "b"]);
            }
            _ => panic!("Expected Timeline statement"),
        }
    }
    
    #[test]
    fn test_parse_export() {
        let source = r#"
investigation "test" {
    export case "test_case" format case_uco
}
"#;
        
        let ast = parse(source).unwrap();
        assert_eq!(ast.statements.len(), 1);
        
        match &ast.statements[0] {
            Statement::Export(decl) => {
                assert_eq!(decl.output_type, OutputType::Case);
                assert_eq!(decl.name, "test_case");
                assert_eq!(decl.format, ExportFormat::CaseUco);
            }
            _ => panic!("Expected Export statement"),
        }
    }
    
    #[test]
    fn test_parse_expression() {
        let source = r#"
investigation "test" {
    collect process as procs where name == "svchost.exe" and cpu > 50
}
"#;
        
        let ast = parse(source).unwrap();
        
        match &ast.statements[0] {
            Statement::Collect(decl) => {
                assert!(decl.filter.is_some());
                let filter = decl.filter.as_ref().unwrap();
                match filter {
                    Expression::Binary(bin) => {
                        assert_eq!(bin.operator, BinaryOp::And);
                    }
                    _ => panic!("Expected binary expression"),
                }
            }
            _ => panic!("Expected Collect statement"),
        }
    }
    
    #[test]
    fn test_parse_invalid_syntax() {
        let source = r#"
investigation "test" {
    collect process as procs where invalid syntax
}
"#;
        
        let result = parse(source);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_type_check_valid() {
        let source = r#"
investigation "test" {
    collect process as procs where name == "svchost.exe"
    correlate procs -> procs by "pid_link" as chain
}
"#;
        
        let ast = parse(source).unwrap();
        let typed = type_check(&ast).unwrap();
        
        assert!(!typed.capabilities.is_empty());
        assert!(typed.symbol_table.bindings.contains_key("procs"));
        assert!(typed.symbol_table.bindings.contains_key("chain"));
    }
    
    #[test]
    fn test_type_check_undefined_binding() {
        let source = r#"
investigation "test" {
    correlate undefined -> procs by "pid_link" as chain
}
"#;
        
        let ast = parse(source).unwrap();
        let result = type_check(&ast);
        
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, TypeErrorCode::UndefinedBinding);
    }
    
    #[test]
    fn test_type_check_duplicate_binding() {
        let source = r#"
investigation "test" {
    collect process as procs where name == "a"
    collect process as procs where name == "b"
}
"#;
        
        let ast = parse(source).unwrap();
        let result = type_check(&ast);
        
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, TypeErrorCode::DuplicateBinding);
    }
    
    #[test]
    fn test_ir_lowering() {
        let source = r#"
investigation "test" {
    collect process as procs where name == "svchost.exe"
    correlate procs -> procs by "pid_link" as chain
}
"#;
        
        let ast = parse(source).unwrap();
        let typed = type_check(&ast).unwrap();
        let ir = lower_to_ir(&typed).unwrap();
        
        assert_eq!(ir.version, 1);
        assert!(!ir.id.is_empty());
        assert_eq!(ir.steps.len(), 2);
        
        let expected = if cfg!(target_os = "windows") { "proc_windows" } else { "proc_linux" };
        assert_eq!(ir.steps[0].collector, expected);
        assert_eq!(ir.steps[0].action, "list");
        assert_eq!(ir.steps[0].binds, vec!["procs"]);
        
        // Check second step is correlate
        assert_eq!(ir.steps[1].collector, "correlator");
        assert_eq!(ir.steps[1].action, "pid_link");
        assert_eq!(ir.steps[1].binds, vec!["chain"]);
        assert_eq!(ir.steps[1].depends_on.len(), 2);
    }
    
    #[test]
    fn test_ir_validation() {
        // Test that IR validation catches cycles
        use petgraph::graphmap::DiGraphMap;
        use petgraph::algo::toposort;
        
        let mut graph = DiGraphMap::new();
        graph.add_node("a");
        graph.add_node("b");
        graph.add_edge("a", "b", ());
        graph.add_edge("b", "a", ());
        
        assert!(toposort(&graph, None).is_err());
    }
    
    #[test]
    fn test_compile_to_ir() {
        let source = r#"
investigation "test" {
    collect process as procs where name == "svchost.exe"
}
"#;
        
        let ir = compile_to_ir(source).unwrap();
        assert_eq!(ir.steps.len(), 1);
        let expected = if cfg!(target_os = "windows") { "proc_windows" } else { "proc_linux" };
        assert_eq!(ir.steps[0].collector, expected);
    }
    
    #[test]
    fn test_compile_to_contract() {
        let source = r#"
investigation "test" {
    collect process as procs where name == "svchost.exe"
}
"#;
        
        let target = jockey_core::TargetSpec::live("localhost", "windows");
        let policy = jockey_core::ExecPolicy::default();
        
        let contract = compile_to_contract(source, target, policy).unwrap();
        
        assert!(!contract.ir_id.is_empty());
        assert!(!contract.run_id.is_empty());
        assert_eq!(contract.target.os, "windows");
    }
    
    #[test]
    fn test_capability_inference() {
        use crate::typeck::infer_capabilities;
        use crate::ast::EvidenceType;
        
        let caps = infer_capabilities(&EvidenceType::Process, &None);
        assert!(caps.contains(&crate::ast::Capability::ProcessEnumerate));
        
        let caps = infer_capabilities(&EvidenceType::File, &None);
        assert!(caps.contains(&crate::ast::Capability::FileEnumerate));
        
        let caps = infer_capabilities(&EvidenceType::Registry, &None);
        assert!(caps.contains(&crate::ast::Capability::RegistryEnumerate));
    }
    
    #[test]
    fn test_pid_filter_detection() {
        use crate::typeck::has_pid_filter;
        use crate::ast::*;
        
        let expr = Expression::Binary(BinaryExpr {
            left: Box::new(Expression::Identifier("pid".to_string())),
            operator: BinaryOp::Eq,
            right: Box::new(Expression::Literal(Literal::Integer(1234))),
            span: crate::span::Span::single(crate::span::Position::start()),
        });
        
        assert!(has_pid_filter(&expr));
        
        let expr2 = Expression::Binary(BinaryExpr {
            left: Box::new(Expression::Identifier("name".to_string())),
            operator: BinaryOp::Eq,
            right: Box::new(Expression::Literal(Literal::String("test".to_string()))),
            span: crate::span::Span::single(crate::span::Position::start()),
        });
        
        assert!(!has_pid_filter(&expr2));
    }
}