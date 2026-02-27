use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Result of a rotation operation.
#[derive(Debug, Serialize, Deserialize)]
pub struct RotationResult {
    pub provider: String,
    pub old_key_id: Option<String>,
    pub new_key_id: Option<String>,
    pub rotated_paths: Vec<String>,
    pub timestamp: String,
}

/// Trait for secret rotation providers.
///
/// Each provider (Stripe, Vercel, Neon) implements this trait to handle
/// its specific API key rotation flow.
#[async_trait]
pub trait RotationProvider: Send + Sync {
    /// Provider name (e.g., "stripe", "vercel", "neon").
    fn name(&self) -> &str;

    /// Check if rotation is possible with current credentials.
    async fn preflight(&self) -> Result<()>;

    /// Preview what would happen (dry run).
    async fn dry_run(&self) -> Result<String>;

    /// Execute the rotation: create new key, verify, revoke old.
    async fn rotate(&self) -> Result<RotationResult>;
}
