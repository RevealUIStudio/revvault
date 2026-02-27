//! Migration utilities for importing secrets from external sources.
//!
//! Supported sources:
//! - Plaintext files (e.g., API key .txt files)
//! - Passage store (already compatible — mostly a verification step)

pub mod plaintext;

pub use plaintext::PlaintextImporter;
