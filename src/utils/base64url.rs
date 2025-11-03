/// Base64URL encoding/decoding per RFC 4648
/// No padding, URL-safe characters
use crate::error::{Error, Result};

const BASE64URL_CHARSET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes to Base64URL string
pub fn encode_bytes(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut result = Vec::new();
    let mut i = 0;

    // Process 3 bytes at a time
    while i + 2 < input.len() {
        let b1 = input[i];
        let b2 = input[i + 1];
        let b3 = input[i + 2];

        result.push(BASE64URL_CHARSET[(b1 >> 2) as usize]);
        result.push(BASE64URL_CHARSET[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize]);
        result.push(BASE64URL_CHARSET[(((b2 & 0x0f) << 2) | (b3 >> 6)) as usize]);
        result.push(BASE64URL_CHARSET[(b3 & 0x3f) as usize]);

        i += 3;
    }

    // Handle remaining bytes
    if i < input.len() {
        let b1 = input[i];
        result.push(BASE64URL_CHARSET[(b1 >> 2) as usize]);

        if i + 1 < input.len() {
            let b2 = input[i + 1];
            result.push(BASE64URL_CHARSET[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize]);
            result.push(BASE64URL_CHARSET[((b2 & 0x0f) << 2) as usize]);
        } else {
            result.push(BASE64URL_CHARSET[((b1 & 0x03) << 4) as usize]);
        }
    }

    // Base64URL charset contains only ASCII characters, so UTF-8 conversion is always safe
    String::from_utf8(result).expect("Base64URL encoding should produce valid UTF-8")
}

/// Encode string to Base64URL
pub fn encode(input: &str) -> String {
    encode_bytes(input.as_bytes())
}

/// Decode Base64URL string to bytes
pub fn decode_bytes(input: &str) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    // Build reverse lookup table
    let mut lookup = [0xffu8; 256];
    for (i, &c) in BASE64URL_CHARSET.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let input_bytes = input.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;

    while i < input_bytes.len() {
        // Get 4 characters (or less for final group)
        let c1 = input_bytes[i];
        let v1 = lookup[c1 as usize];
        if v1 == 0xff {
            return Err(Error::InvalidBase64(format!(
                "Invalid character: {}",
                c1 as char
            )));
        }

        if i + 1 >= input_bytes.len() {
            return Err(Error::InvalidBase64(
                "Incomplete Base64URL data".to_string(),
            ));
        }

        let c2 = input_bytes[i + 1];
        let v2 = lookup[c2 as usize];
        if v2 == 0xff {
            return Err(Error::InvalidBase64(format!(
                "Invalid character: {}",
                c2 as char
            )));
        }

        // First byte is always available
        result.push((v1 << 2) | (v2 >> 4));

        if i + 2 < input_bytes.len() {
            let c3 = input_bytes[i + 2];
            let v3 = lookup[c3 as usize];
            if v3 == 0xff {
                return Err(Error::InvalidBase64(format!(
                    "Invalid character: {}",
                    c3 as char
                )));
            }

            result.push(((v2 & 0x0f) << 4) | (v3 >> 2));

            if i + 3 < input_bytes.len() {
                let c4 = input_bytes[i + 3];
                let v4 = lookup[c4 as usize];
                if v4 == 0xff {
                    return Err(Error::InvalidBase64(format!(
                        "Invalid character: {}",
                        c4 as char
                    )));
                }

                result.push(((v3 & 0x03) << 6) | v4);
                i += 4;
            } else {
                i += 3;
            }
        } else {
            i += 2;
        }
    }

    Ok(result)
}

/// Decode Base64URL string to UTF-8 string
pub fn decode(input: &str) -> Result<String> {
    let bytes = decode_bytes(input)?;
    String::from_utf8(bytes).map_err(|e| Error::InvalidBase64(format!("Invalid UTF-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let tests = vec![
            "",
            "f",
            "fo",
            "foo",
            "foob",
            "fooba",
            "foobar",
            "Hello, World!",
            "The quick brown fox jumps over the lazy dog",
        ];

        for test in tests {
            let encoded = encode(test);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(test, decoded, "Roundtrip failed for: {}", test);
        }
    }

    #[test]
    fn test_encode_bytes() {
        assert_eq!(encode_bytes(b""), "");
        assert_eq!(encode_bytes(b"f"), "Zg");
        assert_eq!(encode_bytes(b"fo"), "Zm8");
        assert_eq!(encode_bytes(b"foo"), "Zm9v");
        assert_eq!(encode_bytes(b"foob"), "Zm9vYg");
        assert_eq!(encode_bytes(b"fooba"), "Zm9vYmE");
        assert_eq!(encode_bytes(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_decode_invalid() {
        assert!(decode_bytes("!!!").is_err());
        assert!(decode_bytes("A").is_err()); // Incomplete
    }

    #[test]
    fn test_url_safe_characters() {
        // Base64URL uses - and _ instead of + and /
        let bytes = vec![0xfb, 0xff];
        let encoded = encode_bytes(&bytes);
        assert!(encoded.contains('-') || encoded.contains('_'));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }
}
