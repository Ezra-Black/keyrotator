//! Core rotation logic: provider-agnostic engine, connector trait, consumer
//! fan-out, and config. Front-ends (CLI, MCP server) are thin layers on top
//! of this crate.

pub mod config;
pub mod connector;
pub mod consumers;
pub mod credstore;
pub mod engine;
pub mod models;
pub mod providers;

pub use config::Config;
pub use connector::Connector;
pub use engine::RotationEngine;
pub use models::{
    Consumer, NewCredential, OldKeyState, ProviderKind, RotationError, RotationOutcome,
    RotationStage, RotationStyle, Secret,
};
