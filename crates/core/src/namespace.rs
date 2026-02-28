use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::RevvaultError;

/// Top-level namespace categories mirroring the store directory structure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Namespace {
    RevealUI,
    Credentials,
    Ssh,
    Project(String),
    Misc,
}

impl Namespace {
    /// Parse a namespace from the first path segment of a secret path.
    pub fn from_path_segment(segment: &str) -> Self {
        match segment.to_lowercase().as_str() {
            "revealui" => Self::RevealUI,
            "credentials" => Self::Credentials,
            "ssh" => Self::Ssh,
            "misc" => Self::Misc,
            other => Self::Project(other.to_string()),
        }
    }

    /// Get the directory name for this namespace.
    pub fn as_dir_name(&self) -> &str {
        match self {
            Self::RevealUI => "revealui",
            Self::Credentials => "credentials",
            Self::Ssh => "ssh",
            Self::Project(name) => name.as_str(),
            Self::Misc => "misc",
        }
    }

    /// List all known built-in namespaces.
    pub fn builtins() -> Vec<Self> {
        vec![
            Self::RevealUI,
            Self::Credentials,
            Self::Ssh,
            Self::Misc,
        ]
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Project(name) => write!(f, "{name}"),
            other => write!(f, "{}", other.as_dir_name()),
        }
    }
}

impl FromStr for Namespace {
    type Err = RevvaultError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(RevvaultError::InvalidNamespace("empty namespace".into()));
        }
        Ok(Self::from_path_segment(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_namespaces() {
        assert_eq!(Namespace::from_path_segment("revealui"), Namespace::RevealUI);
        assert_eq!(Namespace::from_path_segment("credentials"), Namespace::Credentials);
        assert_eq!(Namespace::from_path_segment("ssh"), Namespace::Ssh);
    }

    #[test]
    fn parse_unknown_as_project() {
        assert_eq!(
            Namespace::from_path_segment("myapp"),
            Namespace::Project("myapp".into())
        );
    }
}
