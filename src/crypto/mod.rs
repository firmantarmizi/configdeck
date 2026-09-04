use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const FORMAT_VERSION: u8 = 1;
const NONCE_SIZE: usize = 12;
const DEK_SIZE: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("operating system randomness unavailable")]
    Randomness,
    #[error("invalid nonce length")]
    InvalidNonce,
    #[error("invalid data encryption key length")]
    InvalidDek,
    #[error("authenticated encryption failed")]
    Authentication,
    #[error("key derivation failed")]
    KeyDerivation,
}

#[derive(Clone)]
pub struct CryptoManager {
    master_key: Arc<Zeroizing<[u8; 32]>>,
    previous_master_key: Option<Arc<Zeroizing<[u8; 32]>>>,
}

impl std::fmt::Debug for CryptoManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CryptoManager")
            .field("master_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedBlob {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_SIZE],
}

#[derive(Clone, Debug)]
pub struct CurrentValueContext<'a> {
    pub service_id: &'a str,
    pub environment_id: &'a str,
    pub variable_id: &'a str,
    pub version: u64,
    pub dek_version: u64,
}

#[derive(Clone, Debug)]
pub struct ProposedValueContext<'a> {
    pub service_id: &'a str,
    pub environment_id: &'a str,
    pub change_request_id: &'a str,
    pub item_id: &'a str,
    pub item_revision: u64,
    pub dek_version: u64,
}

impl CryptoManager {
    pub fn new(master_key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            master_key: Arc::new(master_key),
            previous_master_key: None,
        }
    }

    pub fn with_previous(
        master_key: Zeroizing<[u8; 32]>,
        previous_master_key: Zeroizing<[u8; 32]>,
    ) -> Self {
        Self {
            master_key: Arc::new(master_key),
            previous_master_key: Some(Arc::new(previous_master_key)),
        }
    }

    pub fn fingerprint(&self) -> Vec<u8> {
        fingerprint(self.master_key.as_ref())
    }

    pub fn previous_fingerprint(&self) -> Option<Vec<u8>> {
        self.previous_master_key
            .as_ref()
            .map(|key| fingerprint(key.as_ref()))
    }

    pub const fn has_previous_key(&self) -> bool {
        self.previous_master_key.is_some()
    }

    pub fn generate_dek(&self) -> Result<Zeroizing<[u8; DEK_SIZE]>, CryptoError> {
        let mut dek = Zeroizing::new([0_u8; DEK_SIZE]);
        getrandom::fill(dek.as_mut()).map_err(|_| CryptoError::Randomness)?;
        Ok(dek)
    }

    pub fn wrap_dek(
        &self,
        environment_id: &str,
        dek_version: u64,
        kek_version: u64,
        dek: &[u8; DEK_SIZE],
    ) -> Result<EncryptedBlob, CryptoError> {
        let aad = wrapped_dek_aad(environment_id, dek_version, kek_version);
        encrypt(self.master_key.as_ref(), dek, &aad)
    }

    pub fn unwrap_dek(
        &self,
        environment_id: &str,
        dek_version: u64,
        kek_version: u64,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Zeroizing<[u8; DEK_SIZE]>, CryptoError> {
        let aad = wrapped_dek_aad(environment_id, dek_version, kek_version);
        let plaintext =
            decrypt(self.master_key.as_ref(), ciphertext, nonce, &aad).or_else(|_| {
                self.previous_master_key
                    .as_ref()
                    .map_or(Err(CryptoError::Authentication), |key| {
                        decrypt(key.as_ref(), ciphertext, nonce, &aad)
                    })
            })?;
        let mut plaintext = Zeroizing::new(plaintext);
        let result: [u8; DEK_SIZE] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidDek)?;
        plaintext.zeroize();
        Ok(Zeroizing::new(result))
    }

    pub fn unwrap_dek_with_primary(
        &self,
        environment_id: &str,
        dek_version: u64,
        kek_version: u64,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Zeroizing<[u8; DEK_SIZE]>, CryptoError> {
        let aad = wrapped_dek_aad(environment_id, dek_version, kek_version);
        let mut plaintext =
            Zeroizing::new(decrypt(self.master_key.as_ref(), ciphertext, nonce, &aad)?);
        let result: [u8; DEK_SIZE] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidDek)?;
        plaintext.zeroize();
        Ok(Zeroizing::new(result))
    }

    pub fn unwrap_dek_with_previous(
        &self,
        environment_id: &str,
        dek_version: u64,
        kek_version: u64,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Zeroizing<[u8; DEK_SIZE]>, CryptoError> {
        let key = self
            .previous_master_key
            .as_ref()
            .ok_or(CryptoError::Authentication)?;
        let aad = wrapped_dek_aad(environment_id, dek_version, kek_version);
        let mut plaintext = Zeroizing::new(decrypt(key.as_ref(), ciphertext, nonce, &aad)?);
        let result: [u8; DEK_SIZE] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidDek)?;
        plaintext.zeroize();
        Ok(Zeroizing::new(result))
    }

    pub fn encrypt_current_value(
        &self,
        dek: &[u8; DEK_SIZE],
        context: &CurrentValueContext<'_>,
        value: &[u8],
    ) -> Result<EncryptedBlob, CryptoError> {
        encrypt(dek, value, &current_value_aad(context))
    }

    pub fn decrypt_current_value(
        &self,
        dek: &[u8; DEK_SIZE],
        context: &CurrentValueContext<'_>,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        Ok(Zeroizing::new(decrypt(
            dek,
            ciphertext,
            nonce,
            &current_value_aad(context),
        )?))
    }

    pub fn encrypt_proposed_value(
        &self,
        dek: &[u8; DEK_SIZE],
        context: &ProposedValueContext<'_>,
        value: &[u8],
    ) -> Result<EncryptedBlob, CryptoError> {
        encrypt(dek, value, &proposed_value_aad(context))
    }

    pub fn decrypt_proposed_value(
        &self,
        dek: &[u8; DEK_SIZE],
        context: &ProposedValueContext<'_>,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        Ok(Zeroizing::new(decrypt(
            dek,
            ciphertext,
            nonce,
            &proposed_value_aad(context),
        )?))
    }

    pub fn encrypt_totp_seed(
        &self,
        user_id: &str,
        crypto_version: u64,
        seed: &[u8],
    ) -> Result<EncryptedBlob, CryptoError> {
        let key = self.derive_key(b"totp-seed-key-v1")?;
        encrypt(&key, seed, &totp_aad(user_id, crypto_version))
    }

    pub fn decrypt_totp_seed(
        &self,
        user_id: &str,
        crypto_version: u64,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let aad = totp_aad(user_id, crypto_version);
        let key = self.derive_key(b"totp-seed-key-v1")?;
        match decrypt(&key, ciphertext, nonce, &aad) {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(_) => {
                self.decrypt_totp_seed_with_previous(user_id, crypto_version, ciphertext, nonce)
            }
        }
    }

    pub fn decrypt_totp_seed_with_primary(
        &self,
        user_id: &str,
        crypto_version: u64,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let key = self.derive_key(b"totp-seed-key-v1")?;
        Ok(Zeroizing::new(decrypt(
            &key,
            ciphertext,
            nonce,
            &totp_aad(user_id, crypto_version),
        )?))
    }

    pub fn decrypt_totp_seed_with_previous(
        &self,
        user_id: &str,
        crypto_version: u64,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let master_key = self
            .previous_master_key
            .as_ref()
            .ok_or(CryptoError::Authentication)?;
        let key = derive_key(master_key.as_ref(), b"totp-seed-key-v1")?;
        Ok(Zeroizing::new(decrypt(
            &key,
            ciphertext,
            nonce,
            &totp_aad(user_id, crypto_version),
        )?))
    }

    pub fn csrf_token(&self, session_token: &str) -> Result<String, CryptoError> {
        let key = self.derive_key(b"csrf-token-key-v1")?;
        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(key.as_ref())
            .map_err(|_| CryptoError::KeyDerivation)?;
        mac.update(session_token.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    pub fn blind_index(&self, purpose: &[u8], value: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = self.derive_key(purpose)?;
        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(key.as_ref())
            .map_err(|_| CryptoError::KeyDerivation)?;
        mac.update(value);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn seal_import_preview(
        &self,
        user_id: &str,
        session_id: &str,
        environment_id: &str,
        plaintext: &[u8],
    ) -> Result<String, CryptoError> {
        let key = self.derive_key(b"import-preview-token-key-v1")?;
        let encrypted = encrypt(
            &key,
            plaintext,
            &import_preview_aad(user_id, session_id, environment_id),
        )?;
        let mut token = Vec::with_capacity(1 + NONCE_SIZE + encrypted.ciphertext.len());
        token.push(FORMAT_VERSION);
        token.extend_from_slice(&encrypted.nonce);
        token.extend_from_slice(&encrypted.ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(token))
    }

    pub fn open_import_preview(
        &self,
        user_id: &str,
        session_id: &str,
        environment_id: &str,
        token: &str,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let token = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| CryptoError::Authentication)?;
        if token.len() < 1 + NONCE_SIZE + 16 || token[0] != FORMAT_VERSION {
            return Err(CryptoError::Authentication);
        }
        let key = self.derive_key(b"import-preview-token-key-v1")?;
        Ok(Zeroizing::new(decrypt(
            &key,
            &token[1 + NONCE_SIZE..],
            &token[1..=NONCE_SIZE],
            &import_preview_aad(user_id, session_id, environment_id),
        )?))
    }

    fn derive_key(&self, purpose: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        derive_key(self.master_key.as_ref(), purpose)
    }
}

fn fingerprint(key: &[u8; 32]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"configdeck-kek-fingerprint-v1");
    digest.update(key);
    digest.finalize().to_vec()
}

fn derive_key(master_key: &[u8; 32], purpose: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"configdeck-hkdf-v1"), master_key);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(purpose, key.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<EncryptedBlob, CryptoError> {
    let mut nonce = [0_u8; NONCE_SIZE];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
    let cipher_key: &Key = key.into();
    let cipher_nonce: &Nonce = (&nonce).into();
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let ciphertext = cipher
        .encrypt(
            cipher_nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Authentication)?;
    Ok(EncryptedBlob { ciphertext, nonce })
}

fn decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce: &[u8; NONCE_SIZE] = nonce.try_into().map_err(|_| CryptoError::InvalidNonce)?;
    let cipher_key: &Key = key.into();
    let cipher_nonce: &Nonce = nonce.into();
    let cipher = ChaCha20Poly1305::new(cipher_key);
    cipher
        .decrypt(
            cipher_nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Authentication)
}

fn wrapped_dek_aad(environment_id: &str, dek_version: u64, kek_version: u64) -> Vec<u8> {
    AadBuilder::new("environment-dek")
        .field(environment_id.as_bytes())
        .number(dek_version)
        .number(kek_version)
        .finish()
}

fn current_value_aad(context: &CurrentValueContext<'_>) -> Vec<u8> {
    AadBuilder::new("variable-current")
        .field(context.service_id.as_bytes())
        .field(context.environment_id.as_bytes())
        .field(context.variable_id.as_bytes())
        .number(context.version)
        .number(context.dek_version)
        .finish()
}

fn proposed_value_aad(context: &ProposedValueContext<'_>) -> Vec<u8> {
    AadBuilder::new("change-request-proposed-value")
        .field(context.service_id.as_bytes())
        .field(context.environment_id.as_bytes())
        .field(context.change_request_id.as_bytes())
        .field(context.item_id.as_bytes())
        .number(context.item_revision)
        .number(context.dek_version)
        .finish()
}

fn totp_aad(user_id: &str, crypto_version: u64) -> Vec<u8> {
    AadBuilder::new("totp-seed")
        .field(user_id.as_bytes())
        .number(crypto_version)
        .finish()
}

fn import_preview_aad(user_id: &str, session_id: &str, environment_id: &str) -> Vec<u8> {
    AadBuilder::new("import-preview")
        .field(user_id.as_bytes())
        .field(session_id.as_bytes())
        .field(environment_id.as_bytes())
        .finish()
}

struct AadBuilder(Vec<u8>);

impl AadBuilder {
    fn new(purpose: &str) -> Self {
        let mut value = Self(vec![FORMAT_VERSION]);
        value = value.field(b"configdeck");
        value.field(purpose.as_bytes())
    }

    fn field(mut self, field: &[u8]) -> Self {
        let length = u32::try_from(field.len()).expect("AAD field length is bounded");
        self.0.extend_from_slice(&length.to_be_bytes());
        self.0.extend_from_slice(field);
        self
    }

    fn number(self, value: u64) -> Self {
        self.field(&value.to_be_bytes())
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{CryptoManager, CurrentValueContext, ProposedValueContext, decrypt};

    fn crypto(byte: u8) -> CryptoManager {
        CryptoManager::new(Zeroizing::new([byte; 32]))
    }

    #[test]
    fn decrypts_rfc_8439_ciphertext_after_dependency_upgrade() {
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let ciphertext_and_tag = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16, 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb,
            0xd0, 0x60, 0x06, 0x91,
        ];

        let plaintext = decrypt(&key, &ciphertext_and_tag, &nonce, &aad).unwrap();

        assert_eq!(
            plaintext,
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        );
    }

    #[test]
    fn wraps_and_unwraps_dek() {
        let manager = crypto(1);
        let dek = manager.generate_dek().unwrap();
        let wrapped = manager.wrap_dek("env-a", 1, 1, &dek).unwrap();
        let opened = manager
            .unwrap_dek("env-a", 1, 1, &wrapped.ciphertext, &wrapped.nonce)
            .unwrap();
        assert_eq!(opened.as_ref(), dek.as_ref());
    }

    #[test]
    fn wrong_key_and_modified_ciphertext_fail() {
        let manager = crypto(1);
        let wrong = crypto(2);
        let dek = manager.generate_dek().unwrap();
        let wrapped = manager.wrap_dek("env-a", 1, 1, &dek).unwrap();
        assert!(
            wrong
                .unwrap_dek("env-a", 1, 1, &wrapped.ciphertext, &wrapped.nonce)
                .is_err()
        );
        let mut tampered = wrapped.ciphertext.clone();
        tampered[0] ^= 1;
        assert!(
            manager
                .unwrap_dek("env-a", 1, 1, &tampered, &wrapped.nonce)
                .is_err()
        );
    }

    #[test]
    fn aad_prevents_cross_record_ciphertext_swap() {
        let manager = crypto(3);
        let dek = manager.generate_dek().unwrap();
        let first = CurrentValueContext {
            service_id: "service-a",
            environment_id: "env-a",
            variable_id: "variable-a",
            version: 1,
            dek_version: 1,
        };
        let second = CurrentValueContext {
            variable_id: "variable-b",
            ..first.clone()
        };
        let encrypted = manager
            .encrypt_current_value(&dek, &first, b"value")
            .unwrap();
        assert!(
            manager
                .decrypt_current_value(&dek, &second, &encrypted.ciphertext, &encrypted.nonce)
                .is_err()
        );
    }

    #[test]
    fn encryption_uses_fresh_nonces() {
        let manager = crypto(4);
        let dek = manager.generate_dek().unwrap();
        let context = CurrentValueContext {
            service_id: "service-a",
            environment_id: "env-a",
            variable_id: "variable-a",
            version: 1,
            dek_version: 1,
        };
        let a = manager
            .encrypt_current_value(&dek, &context, b"same")
            .unwrap();
        let b = manager
            .encrypt_current_value(&dek, &context, b"same")
            .unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn proposed_value_is_bound_to_request_and_item() {
        let manager = crypto(6);
        let dek = manager.generate_dek().unwrap();
        let context = ProposedValueContext {
            service_id: "service-a",
            environment_id: "env-a",
            change_request_id: "request-a",
            item_id: "item-a",
            item_revision: 1,
            dek_version: 1,
        };
        let encrypted = manager
            .encrypt_proposed_value(&dek, &context, b"restricted")
            .unwrap();
        let other_item = ProposedValueContext {
            item_id: "item-b",
            ..context.clone()
        };
        assert!(
            manager
                .decrypt_proposed_value(&dek, &other_item, &encrypted.ciphertext, &encrypted.nonce,)
                .is_err()
        );
    }

    #[test]
    fn import_preview_token_is_bound_to_user_session_and_environment() {
        let manager = crypto(5);
        let token = manager
            .seal_import_preview("user-a", "session-a", "env-a", b"sensitive preview")
            .unwrap();
        let opened = manager
            .open_import_preview("user-a", "session-a", "env-a", &token)
            .unwrap();
        assert_eq!(opened.as_slice(), b"sensitive preview");
        assert!(
            manager
                .open_import_preview("user-b", "session-a", "env-a", &token)
                .is_err()
        );
        assert!(
            manager
                .open_import_preview("user-a", "session-b", "env-a", &token)
                .is_err()
        );
        assert!(
            manager
                .open_import_preview("user-a", "session-a", "env-b", &token)
                .is_err()
        );
    }
}
