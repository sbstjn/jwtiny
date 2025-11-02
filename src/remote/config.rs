//! Configuration constants for remote fetching

use std::time::Duration;

/// TTL for caching discovery documents (300 seconds = 5 minutes)
pub const DISCOVERY_TTL: Duration = Duration::from_secs(300);

/// TTL for caching JWKS documents (300 seconds = 5 minutes)
pub const JWKS_TTL: Duration = Duration::from_secs(300);
