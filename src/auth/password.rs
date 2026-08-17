use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct PasswordService {
    params: Params,
}

impl std::fmt::Debug for PasswordService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PasswordService")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("invalid Argon2 parameters")]
    InvalidParameters,
    #[error("password hashing failed")]
    Hash,
    #[error("password worker failed")]
    Worker,
}

impl PasswordService {
    pub fn production() -> Result<Self, PasswordError> {
        let params =
            Params::new(19_456, 2, 1, Some(32)).map_err(|_| PasswordError::InvalidParameters)?;
        Ok(Self { params })
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self {
            params: Params::new(1_024, 1, 1, Some(32)).expect("valid test parameters"),
        }
    }

    pub async fn hash(&self, password: Zeroizing<String>) -> Result<String, PasswordError> {
        let service = self.clone();
        tokio::task::spawn_blocking(move || service.hash_sync(password.as_bytes()))
            .await
            .map_err(|_| PasswordError::Worker)?
    }

    pub async fn verify(
        &self,
        password: Zeroizing<String>,
        encoded_hash: String,
    ) -> Result<bool, PasswordError> {
        let service = self.clone();
        tokio::task::spawn_blocking(move || service.verify_sync(password.as_bytes(), &encoded_hash))
            .await
            .map_err(|_| PasswordError::Worker)?
    }

    pub fn needs_rehash(&self, encoded_hash: &str) -> bool {
        let expected = format!(
            "$argon2id$v=19$m={},t={},p={}$",
            self.params.m_cost(),
            self.params.t_cost(),
            self.params.p_cost()
        );
        !encoded_hash.starts_with(&expected)
    }

    fn argon2(&self) -> Argon2<'_> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone())
    }

    fn hash_sync(&self, password: &[u8]) -> Result<String, PasswordError> {
        let mut salt = [0_u8; 16];
        getrandom::fill(&mut salt).map_err(|_| PasswordError::Hash)?;
        let salt = SaltString::encode_b64(&salt).map_err(|_| PasswordError::Hash)?;
        self.argon2()
            .hash_password(password, &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| PasswordError::Hash)
    }

    fn verify_sync(&self, password: &[u8], encoded_hash: &str) -> Result<bool, PasswordError> {
        let parsed = PasswordHash::new(encoded_hash).map_err(|_| PasswordError::Hash)?;
        Ok(self.argon2().verify_password(password, &parsed).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::PasswordService;

    #[tokio::test]
    async fn argon2id_hash_round_trip_and_wrong_password() {
        let service = PasswordService::for_tests();
        let hash = service
            .hash(Zeroizing::new("correct horse".to_owned()))
            .await
            .unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(
            service
                .verify(Zeroizing::new("correct horse".to_owned()), hash.clone())
                .await
                .unwrap()
        );
        assert!(
            !service
                .verify(Zeroizing::new("wrong".to_owned()), hash.clone())
                .await
                .unwrap()
        );
        assert!(!service.needs_rehash(&hash));
        assert!(service.needs_rehash("$argon2id$v=19$m=8,t=1,p=1$old$hash"));
    }
}
