//! JOCKY Core — IR, Execution Contract, Policy Engine, Storage
//!
//! Core types shared across the JOCKY platform.

#![warn(missing_docs)]
#![warn(clippy::all)]

/// Re-exports for public API
pub mod ir;
pub mod contract;
pub mod policy;
pub mod storage;
pub mod target;
pub mod capability;
pub mod collector;

/// Re-export commonly used types
pub use target::TargetSpec;