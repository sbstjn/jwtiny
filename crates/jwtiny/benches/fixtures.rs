//! Static fixture loading for benchmark tests
//!
//! Loads RSA and ECDSA keys from pre-generated PEM files and creates valid JWT tokens.

use aws_lc_rs::signature::RsaKeyPair as AwsLcRsaKeyPair;
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey},
};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

/// RSA key sizes to test
pub const RSA_KEY_SIZES: &[usize] = &[2048, 3072, 4096];

/// ECDSA curves to test
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcdsaCurve {
    P256,
    P384,
    P521,
}

/// Benchmark scenario identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Scenario {
    pub algorithm: String,
    pub key_size: Option<usize>,
    pub curve: Option<EcdsaCurve>,
}

impl Scenario {
    pub fn name(&self) -> String {
        match (self.key_size, self.curve) {
            (Some(size), None) => format!("{}-{}", self.algorithm, size),
            (None, Some(curve)) => {
                let curve_name = match curve {
                    EcdsaCurve::P256 => "P256",
                    EcdsaCurve::P384 => "P384",
                    EcdsaCurve::P521 => "P521",
                };
                format!("{}-{}", self.algorithm, curve_name)
            }
            _ => self.algorithm.clone(),
        }
    }
}

/// RSA key pair with DER-encoded public key
#[derive(Clone)]
pub struct RsaKeyPair {
    pub public_key_der: Vec<u8>,
    pub public_key_pem: String,
    pub encoding_key: EncodingKey,
}

/// ECDSA key pair with DER-encoded public key
pub struct EcdsaKeyPair {
    pub public_key_der: Vec<u8>,
    pub encoding_key: Option<EncodingKey>,
    pub decoding_key: Option<DecodingKey>,
}

/// All benchmark fixtures
pub struct BenchFixtures {
    pub rsa_keys: HashMap<(String, usize), RsaKeyPair>,
    pub ecdsa_keys: HashMap<(String, EcdsaCurve), EcdsaKeyPair>,
    pub tokens: HashMap<Scenario, String>,
}

static FIXTURES_DIR: OnceLock<PathBuf> = OnceLock::new();

fn fixtures_dir() -> &'static PathBuf {
    FIXTURES_DIR.get_or_init(|| {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.push("benches");
        dir.push("fixtures");
        dir
    })
}

impl BenchFixtures {
    /// Load all fixtures from PEM files
    pub fn load() -> Self {
        let mut rsa_keys = HashMap::new();
        let mut ecdsa_keys = HashMap::new();
        let mut tokens = HashMap::new();

        // Load RSA keys for all sizes and algorithms
        for &size in RSA_KEY_SIZES {
            let key_pair = load_rsa_key(size);
            for alg_name in &["RS256", "RS384", "RS512"] {
                rsa_keys.insert((alg_name.to_string(), size), key_pair.clone());
            }
        }

        // Load ECDSA keys for all curves (excluding P-521/ES512)
        let ecdsa_combinations = [
            (EcdsaCurve::P256, "ES256"),
            (EcdsaCurve::P384, "ES384"),
            // P-521/ES512 skipped - jsonwebtoken doesn't support it
        ];
        for (curve, alg_name) in ecdsa_combinations {
            let key_pair = load_ecdsa_key(curve, alg_name);
            ecdsa_keys.insert((alg_name.to_string(), curve), key_pair);
        }

        // Generate tokens for all scenarios
        for ((alg_name, size), rsa_key) in &rsa_keys {
            let scenario = Scenario {
                algorithm: alg_name.clone(),
                key_size: Some(*size),
                curve: None,
            };
            let token = generate_rsa_token(alg_name, rsa_key);
            tokens.insert(scenario, token);
        }

        for ((alg_name, curve), ecdsa_key) in &ecdsa_keys {
            let scenario = Scenario {
                algorithm: alg_name.clone(),
                key_size: None,
                curve: Some(*curve),
            };
            let token = generate_ecdsa_token(alg_name, ecdsa_key);
            tokens.insert(scenario, token);
        }

        Self {
            rsa_keys,
            ecdsa_keys,
            tokens,
        }
    }

    /// Get public key DER for jwtiny validation
    pub fn get_public_key_der(&self, scenario: &Scenario) -> Option<Vec<u8>> {
        match (scenario.key_size, scenario.curve) {
            (Some(size), None) => self
                .rsa_keys
                .get(&(scenario.algorithm.clone(), size))
                .map(|k| k.public_key_der.clone()),
            (None, Some(curve)) => self
                .ecdsa_keys
                .get(&(scenario.algorithm.clone(), curve))
                .map(|k| k.public_key_der.clone()),
            _ => None,
        }
    }

    /// Get DecodingKey for jsonwebtoken validation
    pub fn get_decoding_key(&self, scenario: &Scenario) -> Option<DecodingKey> {
        match (scenario.key_size, scenario.curve) {
            (Some(size), None) => self
                .rsa_keys
                .get(&(scenario.algorithm.clone(), size))
                .and_then(|k| DecodingKey::from_rsa_pem(k.public_key_pem.as_bytes()).ok()),
            (None, Some(curve)) => self
                .ecdsa_keys
                .get(&(scenario.algorithm.clone(), curve))
                .and_then(|k| k.decoding_key.clone()),
            _ => None,
        }
    }
}

fn load_rsa_key(size: usize) -> RsaKeyPair {
    let mut pem_path = fixtures_dir().clone();
    pem_path.push(format!("rsa{}.pem", size));

    let pem = std::fs::read_to_string(&pem_path)
        .unwrap_or_else(|_| panic!("Failed to read RSA-{} key from {:?}", size, pem_path));

    use rsa::pkcs8::DecodePrivateKey as RsaDecodePrivateKey;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&pem)
        .unwrap_or_else(|_| panic!("Failed to parse RSA-{} key from PEM", size));
    let public_key = RsaPublicKey::from(&private_key);

    // Extract public key DER using aws_lc_rs (same approach as jwtiny tests)
    use aws_lc_rs::signature::KeyPair;
    let pkcs8_doc = private_key
        .to_pkcs8_der()
        .expect("Failed to serialize private key to PKCS#8");
    let keypair = AwsLcRsaKeyPair::from_pkcs8(pkcs8_doc.as_bytes())
        .expect("Failed to create RsaKeyPair from PKCS#8");
    // Extract public key DER from the keypair
    let public_key_der = keypair.public_key().as_ref().to_vec();

    // Get PEM for jsonwebtoken
    let public_key_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .expect("Failed to encode public key to PEM");

    // Create encoding key for token generation
    let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes())
        .expect("Failed to create EncodingKey from RSA PEM");

    RsaKeyPair {
        public_key_der,
        public_key_pem,
        encoding_key,
    }
}

fn load_ecdsa_key(curve: EcdsaCurve, alg_name: &str) -> EcdsaKeyPair {
    use elliptic_curve::pkcs8::{DecodePrivateKey, EncodePublicKey};

    let mut pem_path = fixtures_dir().clone();
    let curve_num = match curve {
        EcdsaCurve::P256 => 256,
        EcdsaCurve::P384 => 384,
        EcdsaCurve::P521 => panic!("P-521/ES512 not supported in benchmarks"),
    };
    pem_path.push(format!("ecdsa{}.pem", curve_num));

    let pem = std::fs::read_to_string(&pem_path).unwrap_or_else(|_| {
        panic!(
            "Failed to read ECDSA P-{} key from {:?}",
            curve_num, pem_path
        )
    });

    let (public_key_der, encoding_key, decoding_key) = match (curve, alg_name) {
        (EcdsaCurve::P256, "ES256") => {
            use p256::ecdsa::{SigningKey, VerifyingKey};
            let signing_key =
                SigningKey::from_pkcs8_pem(&pem).expect("Failed to parse P-256 key from PEM");
            let verifying_key = VerifyingKey::from(&signing_key);

            let public_key_der = verifying_key
                .to_public_key_der()
                .expect("Failed to encode P-256 key to DER")
                .to_vec();

            // Create encoding key from PEM (for signing)
            let private_key_pem = signing_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .expect("Failed to encode P-256 private key to PEM");
            let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes()).ok();

            // Create decoding key from x,y coordinates (for verification)
            let point = verifying_key.to_encoded_point(false);
            let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(point.x().unwrap().as_slice());
            let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(point.y().unwrap().as_slice());
            let decoding_key = DecodingKey::from_ec_components(&x_b64, &y_b64).ok();

            (public_key_der, encoding_key, decoding_key)
        }
        (EcdsaCurve::P384, "ES384") => {
            use p384::ecdsa::{SigningKey, VerifyingKey};
            let signing_key =
                SigningKey::from_pkcs8_pem(&pem).expect("Failed to parse P-384 key from PEM");
            let verifying_key = VerifyingKey::from(&signing_key);

            let public_key_der = verifying_key
                .to_public_key_der()
                .expect("Failed to encode P-384 key to DER")
                .to_vec();

            // Create encoding key from PEM (for signing)
            let private_key_pem = signing_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .expect("Failed to encode P-384 private key to PEM");
            let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes()).ok();

            // Create decoding key from x,y coordinates (for verification)
            let point = verifying_key.to_encoded_point(false);
            let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(point.x().unwrap().as_slice());
            let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(point.y().unwrap().as_slice());
            let decoding_key = DecodingKey::from_ec_components(&x_b64, &y_b64).ok();

            (public_key_der, encoding_key, decoding_key)
        }
        _ => panic!(
            "Invalid curve/algorithm combination: {:?} / {} (P-521/ES512 not supported)",
            curve, alg_name
        ),
    };

    EcdsaKeyPair {
        public_key_der,
        encoding_key,
        decoding_key,
    }
}

fn generate_rsa_token(alg_name: &str, key_pair: &RsaKeyPair) -> String {
    let algorithm = match alg_name {
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        _ => panic!("Invalid RSA algorithm: {}", alg_name),
    };

    let header = Header::new(algorithm);
    // Use valid timestamps within bounds (max: 4_102_444_800 = 2100-01-01)
    // Set exp to a far future date that's still valid
    let exp = 4_000_000_000u64; // ~2096, well within bounds
    let iat = 1_700_000_000u64; // ~2023
    let nbf = 1_700_000_000u64; // ~2023
    let claims = json!({
        "sub": "benchmark-user",
        "iss": "benchmark-issuer",
        "aud": "benchmark-audience",
        "exp": exp,
        "iat": iat,
        "nbf": nbf,
    });

    encode(&header, &claims, &key_pair.encoding_key)
        .expect(&format!("Failed to encode {} token", alg_name))
}

fn generate_ecdsa_token(alg_name: &str, key_pair: &EcdsaKeyPair) -> String {
    let algorithm = match alg_name {
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        _ => panic!(
            "Invalid ECDSA algorithm: {} (ES512 not supported)",
            alg_name
        ),
    };

    let encoding_key = key_pair
        .encoding_key
        .as_ref()
        .expect("Encoding key should be present for ES256/ES384");

    let header = Header::new(algorithm);
    // Use valid timestamps within bounds (max: 4_102_444_800 = 2100-01-01)
    // Set exp to a far future date that's still valid
    let exp = 4_000_000_000u64; // ~2096, well within bounds
    let iat = 1_700_000_000u64; // ~2023
    let nbf = 1_700_000_000u64; // ~2023
    let claims = json!({
        "sub": "benchmark-user",
        "iss": "benchmark-issuer",
        "aud": "benchmark-audience",
        "exp": exp,
        "iat": iat,
        "nbf": nbf,
    });

    encode(&header, &claims, encoding_key).expect(&format!("Failed to encode {} token", alg_name))
}
