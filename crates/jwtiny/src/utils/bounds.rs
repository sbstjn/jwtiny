//! Bounds validation utilities
//!
//! This module provides utilities for validating bounds on various values,
//! including timestamp bounds, field size limits, and cache key validation.

use crate::error::{Error, Result};
use crate::limits::{MAX_ISSUER_URL_LENGTH, MAX_JWKS_URI_LENGTH, MAX_TIMESTAMP, MIN_TIMESTAMP};

/// Check if timestamp is within acceptable bounds
pub(crate) fn validate_timestamp_bounds(value: i64) -> Result<()> {
    if !(MIN_TIMESTAMP..=MAX_TIMESTAMP).contains(&value) {
        return Err(Error::TimestampOutOfBounds {
            value,
            min: MIN_TIMESTAMP,
            max: MAX_TIMESTAMP,
        });
    }
    Ok(())
}

/// Apply clock skew to a timestamp with overflow protection
pub(crate) fn apply_clock_skew(timestamp: i64, skew_seconds: u64, add: bool) -> Result<i64> {
    let skew_i64 = skew_seconds as i64;
    if add {
        timestamp.checked_add(skew_i64)
    } else {
        timestamp.checked_sub(skew_i64)
    }
    .ok_or(Error::TimestampOverflow)
}

/// Validate string field size
pub(crate) fn validate_field_size(field: &str, value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        return Err(Error::HeaderFieldTooLong {
            field: field.into(),
            length: value.len(),
            max,
        });
    }
    Ok(())
}

/// Check if cache key length is valid to prevent DoS attacks
pub(crate) fn is_valid_cache_key(key: &str) -> bool {
    let max_key_length = MAX_ISSUER_URL_LENGTH.max(MAX_JWKS_URI_LENGTH);
    key.len() <= max_key_length
}
