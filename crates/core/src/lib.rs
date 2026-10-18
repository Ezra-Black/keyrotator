//! Core rotation logic: provider-agnostic engine, connector trait, consumer
//! fan-out, and secret storage. Front-ends (CLI, MCP server) are thin layers
//! on top of this crate.

pub mod connector;
pub mod consumers;
pub mod engine;
pub mod models;
pub mod providers;
pub mod secrets;

pub use connector::Connector;
pub use engine::RotationEngine;
pub use models::{
    Consumer, NewCredential, ProviderKind, RotationError, RotationStage, RotationStyle, Secret,
};
