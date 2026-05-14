//! Value-shape validation for outbound sync.
//!
//! Shape predicates are used by both `revvault sync vercel` (push_mode) and the
//! rotation sync hook to gate values before they reach an external store. Three
//! structural violations — empty, null literal, Vercel v2-envelope — are always
//! refused regardless of declared shape (they are invalid for any consumer).
//! Per-shape checks apply on top.
//!
//! **No regex** — all checks use prefix matching, length tests, and
//! character-class predicates only.

use serde::{Deserialize, Serialize};

/// Declared shape of a secret value. Used by the sync manifest and rotation
/// providers to gate value-write paths.
///
/// The empty / null-literal / ciphertext-envelope structural checks run
/// regardless of declared shape. Per-shape checks apply on top of those
/// universal guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Shape {
    /// Any non-empty, non-null, non-ciphertext value passes.
    Any,
    /// `postgresql://...` or `postgres://...`
    PostgresUrl,
    /// `https://...` or `http://...`
    HttpsUrl,
    /// `sk_live_*` / `sk_test_*` / `pk_live_*` / `pk_test_*`
    StripeKey,
    /// `sk_live_*` or `pk_live_*` exclusively — refuses test keys.
    StripeKeyLiveOnly,
    /// `whsec_*`
    StripeWebhook,
    /// `price_*` or `prod_*` (Stripe resource IDs)
    StripeResource,
    /// `-----BEGIN ... PRIVATE KEY-----` PEM block
    PemPrivateKey,
    /// `-----BEGIN PUBLIC KEY-----` PEM block
    PemPublicKey,
    /// Hex string of exactly 64 characters (32 random bytes hex-encoded)
    Hex32,
    /// Hex string of exactly 128 characters (64 random bytes hex-encoded)
    Hex64,
    /// Contains `@` — basic email shape
    Email,
    /// One of the literal strings: `production`, `development`, `true`, `false`
    Flag,
}

/// Refusal reason; reported to the operator and to the audit log.
/// The value itself is never included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShapeViolation {
    /// Value is the empty string.
    Empty,
    /// Value is exactly the string `"null"`.
    NullLiteral,
    /// Value starts with the Vercel v2-envelope base64 prefix (`eyJ2IjoidjIi`).
    VercelEnvelope,
    /// Value is structurally valid (non-empty, non-null, non-envelope) but does
    /// not satisfy the declared shape constraint.
    WrongShape {
        expected: Shape,
        /// Best-effort classification of what the value actually looks like,
        /// so the operator can diagnose mismatches quickly.
        actual_hint: String,
    },
}

impl std::fmt::Display for ShapeViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "value is empty"),
            Self::NullLiteral => write!(f, "value is the literal string \"null\""),
            Self::VercelEnvelope => {
                write!(
                    f,
                    "value is a Vercel v2 ciphertext envelope (starts with eyJ2IjoidjIi)"
                )
            }
            Self::WrongShape {
                expected,
                actual_hint,
            } => write!(
                f,
                "expected shape {expected:?} but value looks like: {actual_hint}"
            ),
        }
    }
}

/// Validate `value` against `expected`. Returns `Ok(())` when the value passes
/// all checks; returns `Err(ShapeViolation)` with the first violation found.
///
/// Universal structural checks (empty / null / envelope) run first regardless
/// of the declared shape variant.
pub fn check(value: &str, expected: Shape) -> Result<(), ShapeViolation> {
    if value.is_empty() {
        return Err(ShapeViolation::Empty);
    }
    if value == "null" {
        return Err(ShapeViolation::NullLiteral);
    }
    if value.starts_with("eyJ2IjoidjIi") {
        return Err(ShapeViolation::VercelEnvelope);
    }

    match expected {
        Shape::Any => Ok(()),
        Shape::PostgresUrl => {
            if value.starts_with("postgresql://") || value.starts_with("postgres://") {
                Ok(())
            } else {
                Err(shape_mismatch(expected, value))
            }
        }
        Shape::HttpsUrl => {
            if value.starts_with("https://") || value.starts_with("http://") {
                Ok(())
            } else {
                Err(shape_mismatch(expected, value))
            }
        }
        Shape::StripeKey => {
            if matches_stripe_key(value) {
                Ok(())
            } else {
                Err(shape_mismatch(expected, value))
            }
        }
        Shape::StripeKeyLiveOnly => {
            if value.starts_with("sk_live_") || value.starts_with("pk_live_") {
                Ok(())
            } else {
                Err(shape_mismatch(expected, value))
            }
        }
        Shape::StripeWebhook => {
            if value.starts_with("whsec_") {
                Ok(())
            } else {
                Err(shape_mismatch(expected, value))
            }
        }
        Shape::StripeResource => {
            if value.starts_with("price_") || value.starts_with("prod_") {
                Ok(())
            } else {
                Err(shape_mismatch(expected, value))
            }
        }
        Shape::PemPrivateKey => {
            if value.starts_with("-----BEGIN") && value.contains("PRIVATE KEY") {
                Ok(())
            } else {
                Err(shape_mismatch(expected, value))
            }
        }
        Shape::PemPublicKey => {
            if value.starts_with("-----BEGIN PUBLIC KEY") {
                Ok(())
            } else {
                Err(shape_mismatch(expected, value))
            }
        }
        Shape::Hex32 => {
            if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
                Ok(())
            } else {
                Err(shape_mismatch(expected, value))
            }
        }
        Shape::Hex64 => {
            if value.len() == 128 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
                Ok(())
            } else {
                Err(shape_mismatch(expected, value))
            }
        }
        Shape::Email => {
            if value.contains('@') {
                Ok(())
            } else {
                Err(shape_mismatch(expected, value))
            }
        }
        Shape::Flag => {
            if matches!(value, "production" | "development" | "true" | "false") {
                Ok(())
            } else {
                Err(shape_mismatch(expected, value))
            }
        }
    }
}

fn shape_mismatch(expected: Shape, value: &str) -> ShapeViolation {
    ShapeViolation::WrongShape {
        expected,
        actual_hint: classify(value),
    }
}

fn matches_stripe_key(value: &str) -> bool {
    value.starts_with("sk_live_")
        || value.starts_with("sk_test_")
        || value.starts_with("pk_live_")
        || value.starts_with("pk_test_")
}

/// Best-effort categorisation of a value's shape. Used in error messages and
/// audit-log `value_shape` fields. Never logs the value itself — only the
/// category name.
pub fn classify(value: &str) -> String {
    if value.is_empty() {
        return "empty".into();
    }
    if value == "null" {
        return "null-literal".into();
    }
    if value.starts_with("eyJ2IjoidjIi") {
        return "vercel-envelope".into();
    }
    if value.starts_with("postgresql://") || value.starts_with("postgres://") {
        return "postgres-url".into();
    }
    if value.starts_with("https://") {
        return "https-url".into();
    }
    if value.starts_with("http://") {
        return "http-url".into();
    }
    if matches_stripe_key(value) {
        return "stripe-key".into();
    }
    if value.starts_with("whsec_") {
        return "stripe-webhook".into();
    }
    if value.starts_with("price_") || value.starts_with("prod_") {
        return "stripe-resource".into();
    }
    if value.starts_with("-----BEGIN") && value.contains("PRIVATE KEY") {
        return "pem-private-key".into();
    }
    if value.starts_with("-----BEGIN PUBLIC KEY") {
        return "pem-public-key".into();
    }
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return "hex32".into();
    }
    if value.len() == 128 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return "hex64".into();
    }
    if value.contains('@') {
        return "email".into();
    }
    if matches!(value, "production" | "development" | "true" | "false") {
        return "flag".into();
    }
    "unknown".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENVELOPE: &str = "eyJ2IjoidjIiLCJlcGsiOnsieCI6InRlc3QifX0=";

    fn all_shapes() -> Vec<Shape> {
        vec![
            Shape::Any,
            Shape::PostgresUrl,
            Shape::HttpsUrl,
            Shape::StripeKey,
            Shape::StripeKeyLiveOnly,
            Shape::StripeWebhook,
            Shape::StripeResource,
            Shape::PemPrivateKey,
            Shape::PemPublicKey,
            Shape::Hex32,
            Shape::Hex64,
            Shape::Email,
            Shape::Flag,
        ]
    }

    #[test]
    fn check_empty_always_rejected() {
        for shape in all_shapes() {
            assert_eq!(
                check("", shape),
                Err(ShapeViolation::Empty),
                "shape {shape:?} should reject empty"
            );
        }
    }

    #[test]
    fn check_null_literal_always_rejected() {
        for shape in all_shapes() {
            assert_eq!(
                check("null", shape),
                Err(ShapeViolation::NullLiteral),
                "shape {shape:?} should reject \"null\""
            );
        }
    }

    #[test]
    fn check_envelope_always_rejected() {
        for shape in all_shapes() {
            assert_eq!(
                check(ENVELOPE, shape),
                Err(ShapeViolation::VercelEnvelope),
                "shape {shape:?} should reject Vercel envelope"
            );
        }
    }

    #[test]
    fn check_any_accepts_non_empty_non_null_non_envelope() {
        assert!(check("some-value", Shape::Any).is_ok());
        assert!(check("postgresql://host/db", Shape::Any).is_ok());
        assert!(check("literally-anything", Shape::Any).is_ok());
    }

    #[test]
    fn check_postgres_url_accepts_both_prefixes() {
        assert!(check("postgresql://host/db", Shape::PostgresUrl).is_ok());
        assert!(check("postgres://host/db", Shape::PostgresUrl).is_ok());
    }

    #[test]
    fn check_postgres_url_rejects_non_postgres() {
        assert!(check("mysql://host/db", Shape::PostgresUrl).is_err());
        assert!(check("https://host/db", Shape::PostgresUrl).is_err());
    }

    #[test]
    fn check_https_url_accepts_both_schemes() {
        assert!(check("https://example.com/api", Shape::HttpsUrl).is_ok());
        assert!(check("http://localhost:3000", Shape::HttpsUrl).is_ok());
    }

    #[test]
    fn check_https_url_rejects_non_http() {
        assert!(check("ftp://example.com", Shape::HttpsUrl).is_err());
        assert!(check("postgresql://host/db", Shape::HttpsUrl).is_err());
    }

    #[test]
    fn check_stripe_key_accepts_all_four_prefixes() {
        assert!(check("sk_live_abc123", Shape::StripeKey).is_ok());
        assert!(check("sk_test_abc123", Shape::StripeKey).is_ok());
        assert!(check("pk_live_abc123", Shape::StripeKey).is_ok());
        assert!(check("pk_test_abc123", Shape::StripeKey).is_ok());
    }

    #[test]
    fn check_stripe_key_rejects_others() {
        assert!(check("whsec_abc123", Shape::StripeKey).is_err());
        assert!(check("rk_live_abc123", Shape::StripeKey).is_err());
    }

    #[test]
    fn check_stripe_key_live_only_rejects_test_keys() {
        assert!(check("sk_live_abc", Shape::StripeKeyLiveOnly).is_ok());
        assert!(check("pk_live_abc", Shape::StripeKeyLiveOnly).is_ok());
        assert!(check("sk_test_abc", Shape::StripeKeyLiveOnly).is_err());
        assert!(check("pk_test_abc", Shape::StripeKeyLiveOnly).is_err());
    }

    #[test]
    fn check_stripe_webhook_accepts_whsec() {
        assert!(check("whsec_abc123", Shape::StripeWebhook).is_ok());
        assert!(check("sk_live_abc", Shape::StripeWebhook).is_err());
    }

    #[test]
    fn check_stripe_resource_accepts_price_and_prod_prefixes() {
        assert!(check("price_abc123", Shape::StripeResource).is_ok());
        assert!(check("prod_abc123", Shape::StripeResource).is_ok());
        assert!(check("sub_abc123", Shape::StripeResource).is_err());
    }

    #[test]
    fn check_pem_private_key_accepts_pem_block() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgk\n-----END PRIVATE KEY-----";
        assert!(check(pem, Shape::PemPrivateKey).is_ok());
        let ec_pem = "-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----";
        assert!(check(ec_pem, Shape::PemPrivateKey).is_ok());
    }

    #[test]
    fn check_pem_private_key_rejects_non_pem() {
        assert!(check("postgresql://host", Shape::PemPrivateKey).is_err());
        assert!(check("-----BEGIN PUBLIC KEY-----", Shape::PemPrivateKey).is_err());
    }

    #[test]
    fn check_pem_public_key() {
        assert!(check(
            "-----BEGIN PUBLIC KEY-----\ndata\n-----END PUBLIC KEY-----",
            Shape::PemPublicKey
        )
        .is_ok());
        assert!(check("-----BEGIN PRIVATE KEY-----\ndata", Shape::PemPublicKey).is_err());
    }

    #[test]
    fn check_hex32_accepts_64_char_hex() {
        let hex64 = "a".repeat(64);
        assert!(check(&hex64, Shape::Hex32).is_ok());
        let valid = "0123456789abcdefABCDEF".repeat(2) + "01234567890123456789";
        assert_eq!(valid.len(), 64);
        assert!(check(&valid, Shape::Hex32).is_ok());
    }

    #[test]
    fn check_hex32_rejects_wrong_length() {
        assert!(check(&"a".repeat(63), Shape::Hex32).is_err());
        assert!(check(&"a".repeat(65), Shape::Hex32).is_err());
    }

    #[test]
    fn check_hex32_rejects_non_hex_chars() {
        let with_g = "g".repeat(64);
        assert!(check(&with_g, Shape::Hex32).is_err());
    }

    #[test]
    fn check_hex64_accepts_128_char_hex() {
        let hex128 = "b".repeat(128);
        assert!(check(&hex128, Shape::Hex64).is_ok());
    }

    #[test]
    fn check_hex64_rejects_64_chars() {
        assert!(check(&"b".repeat(64), Shape::Hex64).is_err());
    }

    #[test]
    fn check_email_accepts_value_containing_at() {
        assert!(check("user@example.com", Shape::Email).is_ok());
        assert!(check("a@b", Shape::Email).is_ok());
    }

    #[test]
    fn check_email_rejects_no_at() {
        assert!(check("notanemail", Shape::Email).is_err());
    }

    #[test]
    fn check_flag_accepts_known_literals() {
        assert!(check("production", Shape::Flag).is_ok());
        assert!(check("development", Shape::Flag).is_ok());
        assert!(check("true", Shape::Flag).is_ok());
        assert!(check("false", Shape::Flag).is_ok());
    }

    #[test]
    fn check_flag_rejects_other_strings() {
        assert!(check("staging", Shape::Flag).is_err());
        assert!(check("1", Shape::Flag).is_err());
    }

    #[test]
    fn classify_returns_correct_categories() {
        assert_eq!(classify(""), "empty");
        assert_eq!(classify("null"), "null-literal");
        assert_eq!(classify(ENVELOPE), "vercel-envelope");
        assert_eq!(classify("postgresql://h/db"), "postgres-url");
        assert_eq!(classify("postgres://h/db"), "postgres-url");
        assert_eq!(classify("https://example.com"), "https-url");
        assert_eq!(classify("http://localhost"), "http-url");
        assert_eq!(classify("sk_live_abc"), "stripe-key");
        assert_eq!(classify("sk_test_abc"), "stripe-key");
        assert_eq!(classify("whsec_abc"), "stripe-webhook");
        assert_eq!(classify("price_abc"), "stripe-resource");
        assert_eq!(
            classify("-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----"),
            "pem-private-key"
        );
        assert_eq!(classify("-----BEGIN PUBLIC KEY-----"), "pem-public-key");
        assert_eq!(classify(&"a".repeat(64)), "hex32");
        assert_eq!(classify(&"a".repeat(128)), "hex64");
        assert_eq!(classify("user@host.com"), "email");
        assert_eq!(classify("production"), "flag");
        assert_eq!(classify("some-random-value"), "unknown");
    }

    #[test]
    fn shape_serde_round_trip_kebab_case() {
        let shape = Shape::PostgresUrl;
        let json = serde_json::to_string(&shape).unwrap();
        assert_eq!(json, r#""postgres-url""#);
        let back: Shape = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Shape::PostgresUrl);
    }

    #[test]
    fn shape_violation_display_is_human_readable() {
        let v = ShapeViolation::Empty;
        assert!(v.to_string().contains("empty"));
        let v = ShapeViolation::NullLiteral;
        assert!(v.to_string().contains("null"));
        let v = ShapeViolation::VercelEnvelope;
        assert!(v.to_string().contains("Vercel"));
        let v = ShapeViolation::WrongShape {
            expected: Shape::StripeKey,
            actual_hint: "postgres-url".into(),
        };
        assert!(v.to_string().contains("StripeKey"));
        assert!(v.to_string().contains("postgres-url"));
    }
}
