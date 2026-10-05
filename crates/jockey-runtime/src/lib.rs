//! JOCKY Runtime — Execution Engine, Dispatcher, Sandbox

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod executor;
pub mod dispatcher;
pub mod sandbox;
pub mod collector_registry;

pub use executor::{Executor, ExecutionResult, ExecutionStatus, RuntimeError};
pub use collector_registry::{CollectorRegistry, RegistryError};
pub use dispatcher::Dispatcher;
pub use sandbox::Sandbox;

use jockey_core::contract::ExecutionContract;

/// Execute a contract
pub async fn execute(
    contract: ExecutionContract,
    registry: &CollectorRegistry,
) -> Result<ExecutionResult, RuntimeError> {
    let executor = Executor::new(registry);
    executor.execute(contract).await
}