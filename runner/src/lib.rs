//! Library surface of the verifier runner. The binary in `main.rs` is a thin
//! wrapper; integration tests exercise everything through this crate so the
//! exact production code paths are what gets tested.

pub mod config;
pub mod error;
pub mod flag;
pub mod intent;
pub mod redact;
pub mod routes;
pub mod sandbox;
pub mod state;
pub mod unpack;
pub mod verdict;
