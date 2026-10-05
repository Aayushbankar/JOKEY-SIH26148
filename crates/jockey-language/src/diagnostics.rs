//! JOCKY Diagnostics — Error reporting and diagnostics

use crate::ast::*;
use crate::span::Span;
use serde::{Serialize, Deserialize};
use std::fmt;

/// Diagnostic severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Error,
    Warning,
    Info,
    Hint,
}

/// Diagnostic message with source location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
    pub span: Option<Span>,
    pub code: Option<String>,
    pub hints: Vec<String>,
}

impl Diagnostic {
    pub fn error(message: impl Into<String>, span: Span) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
            span: Some(span),
            code: None,
            hints: Vec::new(),
        }
    }
    
    pub fn warning(message: impl Into<String>, span: Span) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
            span: Some(span),
            code: None,
            hints: Vec::new(),
        }
    }
    
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }
    
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hints.push(hint.into());
        self
    }
}

/// Diagnostic collection
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiagnosticBag {
    pub items: Vec<Diagnostic>,
}

impl DiagnosticBag {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }
    
    pub fn add(&mut self, diagnostic: Diagnostic) {
        self.items.push(diagnostic);
    }
    
    pub fn has_errors(&self) -> bool {
        self.items.iter().any(|d| d.severity == Severity::Error)
    }
    
    pub fn errors(&self) -> Vec<&Diagnostic> {
        self.items.iter().filter(|d| d.severity == Severity::Error).collect()
    }
    
    pub fn warnings(&self) -> Vec<&Diagnostic> {
        self.items.iter().filter(|d| d.severity == Severity::Warning).collect()
    }
}

/// Report diagnostics to stdout/stderr
pub fn report_diagnostics(bag: &DiagnosticBag, source: &str) {
    for diag in &bag.items {
        let severity_str = match diag.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
            Severity::Hint => "hint",
        };
        
        if let Some(span) = diag.span {
            eprintln!("{}: {} at {}", severity_str, diag.message, span);
            // Print source context
            if let Some(line) = source.lines().nth(span.start.line.saturating_sub(1)) {
                eprintln!("  | {}", line.trim());
                eprintln!("  | {}{}", " ".repeat(span.start.column), "^".repeat(span.end.column.saturating_sub(span.start.column).max(1)));
            }
        } else {
            eprintln!("{}: {}", severity_str, diag.message);
        }
        
        if let Some(code) = &diag.code {
            eprintln!("  = help: {} =", code);
        }
        
        for hint in &diag.hints {
            eprintln!("  = hint: {} =", hint);
        }
    }
}