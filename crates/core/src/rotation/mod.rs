//! Secret rotation engine.
//!
//! Provides a trait-based system for rotating API keys and credentials
//! across multiple providers (Stripe, Vercel, Neon).

pub mod config;
pub mod provider;

pub use config::RotationConfig;
pub use provider::RotationProvider;
