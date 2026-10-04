//! JOCKY Core — IR Module

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// IR Module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrModule {
    pub version: u32,
    pub id: String,
    pub metadata: IRMetadata,
    pub steps: Vec<IRStep>,
    pub outputs: Vec<IROutput>,
}

/// IR Metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRMetadata {
    pub name: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub created_at: DateTime<Utc>,
    pub tags: Vec<String>,
}

impl IRMetadata {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            author: None,
            created_at: chrono::Utc::now(),
            tags: Vec::new(),
        }
    }
    
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
    
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }
    
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// IR Step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IRStep {
    pub id: String,
    pub collector: String,
    pub action: String,
    pub params: serde_json::Value,
    pub binds: Vec<String>,
    pub depends_on: Vec<String>,
    pub condition: Option<String>,
}

impl IRStep {
    pub fn new(id: String, collector: impl Into<String>, action: impl Into<String>, params: serde_json::Value) -> Self {
        Self {
            id,
            collector: collector.into(),
            action: action.into(),
            params,
            binds: Vec::new(),
            depends_on: Vec::new(),
            condition: None,
        }
    }
    
    pub fn with_binds(mut self, binds: Vec<String>) -> Self {
        self.binds = binds;
        self
    }
    
    pub fn with_depends_on(mut self, deps: Vec<String>) -> Self {
        self.depends_on = deps;
        self
    }
}

/// IR Output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IROutput {
    pub name: String,
    pub from_step: String,
    pub field: Option<String>,
}