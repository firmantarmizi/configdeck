use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

type HmacSha1 = Hmac<Sha1>;

const PERIOD_SECONDS: i64 = 30;
const DIGITS_MODULUS: u32 = 1_000_000;

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("randomness unavailable")]
    Randomness,
    #[error("invalid TOTP code")]
    InvalidCode,
    #[error("TOTP code was already used")]
    ReplayedCode,
}

pub fn generate_secret() -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut secret = Zeroizing::new(vec![0_u8; 20]);
    getrandom::fill(secret.as_mut()).map_err(|_| TotpError::Randomness)?;
    Ok(secret)
}

pub fn verify_at(
    secret: &[u8],
    code: &str,
    unix_seconds: i64,
    last_used_step: Option<i64>,
) -> Result<i64, TotpError> {
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TotpError::InvalidCode);
    }
    let candidate = code.as_bytes();
    let current_step = unix_seconds.div_euclid(PERIOD_SECONDS);
    let mut replayed = false;
    for offset in [-1_i64, 0, 1] {
        let step = current_step + offset;
        if step < 0 {
            continue;
        }
        let Ok(counter) = u64::try_from(step) else {
            continue;
        };
        let expected = format!("{:06}", hotp(secret, counter));
        if expected.as_bytes().ct_eq(candidate).into() {
            if last_used_step.is_some_and(|last| step <= last) {
                replayed = true;
                continue;
            }
            return Ok(step);
        }
    }
    if replayed {
        Err(TotpError::ReplayedCode)
    } else {
        Err(TotpError::InvalidCode)
    }
}

pub fn provisioning_uri(secret: &[u8], email: &str) -> String {
    let encoded_secret = BASE32_NOPAD.encode(secret);
    let account_label = format!("ConfigDeck:{email}");
    let label = utf8_percent_encode(&account_label, NON_ALPHANUMERIC);
    let issuer = utf8_percent_encode("ConfigDeck", NON_ALPHANUMERIC);
    format!(
        "otpauth://totp/{label}?secret={encoded_secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )
}

pub fn encoded_secret(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

#[cfg(test)]
pub(crate) fn code_at(secret: &[u8], unix_seconds: i64) -> String {
    let step = u64::try_from(unix_seconds.div_euclid(PERIOD_SECONDS)).expect("positive test time");
    format!("{:06}", hotp(secret, step))
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    binary % DIGITS_MODULUS
}

#[cfg(test)]
mod tests {
    use super::{hotp, verify_at};

    #[test]
    fn follows_rfc_6238_sha1_vector_at_59_seconds() {
        let secret = b"12345678901234567890";
        assert_eq!(hotp(secret, 1), 287_082);
        assert_eq!(verify_at(secret, "287082", 59, None).unwrap(), 1);
    }

    #[test]
    fn rejects_replayed_timestep() {
        let secret = b"12345678901234567890";
        assert!(verify_at(secret, "287082", 59, Some(1)).is_err());
    }

    #[test]
    fn rejects_malformed_codes() {
        assert!(verify_at(b"secret", "12345", 59, None).is_err());
        assert!(verify_at(b"secret", "12345a", 59, None).is_err());
    }
}
