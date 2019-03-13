use ring::{digest, hmac};

use super::b64;

/// Compute the signature for the given data and key.
/// This is done using an HMAC key using the SHA256 digest.
///
/// If computing the signature failed, an error is returned.
pub fn signature(key: &[u8], data: &[u8]) -> Vec<u8> {
    let skey = hmac::SigningKey::new(&digest::SHA256, key);
    hmac::sign(&skey, data).as_ref().to_owned()
}

/// Compute the signature for the given data and key.
/// This is done using an HMAC key using the SHA256 digest.
///
/// The resulting signature is encoded as base64 string in an URL-safe manner.
///
/// If computing the signature failed, an error is returned.
pub fn signature_encoded(key: &[u8], data: &[u8]) -> String {
    b64::encode(&signature(key, data))
}
