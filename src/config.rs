use std::{env, fs, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ipnet::IpNet;
use zeroize::Zeroizing;

use crate::error::ConfigError;

const DEFAULT_KEY_FILE: &str = "/run/secrets/configdeck_master_key";
const DEFAULT_PREVIOUS_KEY_FILE: &str = "/run/secrets/configdeck_master_key_previous";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Environment {
    Development,
    Test,
    Production,
}

impl Environment {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value {
            "development" => Ok(Self::Development),
            "test" => Ok(Self::Test),
            "production" => Ok(Self::Production),
            _ => Err(ConfigError::InvalidEnvironment),
        }
    }

    pub const fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

#[derive(Clone, Debug)]
pub struct DatabaseSettings {
    pub url: String,
    pub max_connections: u32,
    pub busy_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct SessionSettings {
    pub cookie_name: String,
    pub secure_cookie: bool,
    pub idle_timeout: time::Duration,
    pub absolute_timeout: time::Duration,
    pub recent_auth_timeout: time::Duration,
}

#[derive(Clone, Debug)]
pub struct OperationsSettings {
    pub backup_dir: PathBuf,
    pub restore_intent_path: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct BootstrapSettings {
    pub admin_email: Option<String>,
    pub admin_password: Option<Zeroizing<String>>,
}

#[derive(Clone)]
pub struct Settings {
    pub environment: Environment,
    pub bind_address: SocketAddr,
    pub database: DatabaseSettings,
    pub master_key: Option<Zeroizing<[u8; 32]>>,
    pub previous_master_key: Option<Zeroizing<[u8; 32]>>,
    pub session: SessionSettings,
    pub operations: OperationsSettings,
    pub trusted_proxies: Vec<IpNet>,
    pub bootstrap: BootstrapSettings,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Settings")
            .field("environment", &self.environment)
            .field("bind_address", &self.bind_address)
            .field("database", &self.database)
            .field(
                "master_key",
                &self.master_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "previous_master_key",
                &self.previous_master_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("session", &self.session)
            .field("operations", &self.operations)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("bootstrap", &"[REDACTED]")
            .finish()
    }
}

impl Settings {
    pub fn from_env(require_master_key: bool) -> Result<Self, ConfigError> {
        let environment = Environment::parse(
            &env::var("CONFIGDECK_ENV").map_err(|_| ConfigError::MissingEnvironment)?,
        )?;
        let bind_address = env::var("CONFIGDECK_BIND")
            .unwrap_or_else(|_| "0.0.0.0:3000".to_owned())
            .parse()
            .map_err(|_| ConfigError::InvalidBindAddress)?;
        let database_url = env::var("CONFIGDECK_DATABASE_URL")
            .unwrap_or_else(|_| "sqlite://data/configdeck.db".to_owned());
        let max_connections = env::var("CONFIGDECK_DB_MAX_CONNECTIONS")
            .ok()
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| ConfigError::InvalidDatabasePoolSize)?
            .unwrap_or(5);
        if !(1..=16).contains(&max_connections) {
            return Err(ConfigError::InvalidDatabasePoolSize);
        }

        let master_key = if require_master_key {
            Some(load_master_key(environment)?)
        } else {
            None
        };
        let previous_master_key = if require_master_key {
            load_previous_master_key()?
        } else {
            None
        };
        let bootstrap = bootstrap_settings()?;
        let trusted_proxies = parse_trusted_proxies()?;
        let secure_cookie = environment.is_production();
        let backup_dir = env::var("CONFIGDECK_BACKUP_DIR")
            .map_or_else(|_| PathBuf::from("/backup"), PathBuf::from);
        let restore_intent_path = env::var("CONFIGDECK_RESTORE_INTENT_FILE").map_or_else(
            |_| PathBuf::from("/data/restore-intent.json"),
            PathBuf::from,
        );

        Ok(Self {
            environment,
            bind_address,
            database: DatabaseSettings {
                url: database_url,
                max_connections,
                busy_timeout: Duration::from_secs(5),
            },
            master_key,
            previous_master_key,
            session: SessionSettings {
                cookie_name: if secure_cookie {
                    "__Host-configdeck_session".to_owned()
                } else {
                    "configdeck_session".to_owned()
                },
                secure_cookie,
                idle_timeout: time::Duration::minutes(30),
                absolute_timeout: time::Duration::hours(12),
                recent_auth_timeout: time::Duration::minutes(5),
            },
            operations: OperationsSettings {
                backup_dir,
                restore_intent_path,
            },
            trusted_proxies,
            bootstrap,
        })
    }
}

fn load_previous_master_key() -> Result<Option<Zeroizing<[u8; 32]>>, ConfigError> {
    let path = env::var("CONFIGDECK_PREVIOUS_MASTER_KEY_FILE")
        .map_or_else(|_| PathBuf::from(DEFAULT_PREVIOUS_KEY_FILE), PathBuf::from);
    match fs::read_to_string(&path) {
        Ok(value) => decode_master_key(&value).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ConfigError::ReadMasterKey {
            path,
            source: error,
        }),
    }
}

fn load_master_key(environment: Environment) -> Result<Zeroizing<[u8; 32]>, ConfigError> {
    let path = env::var("CONFIGDECK_MASTER_KEY_FILE")
        .map_or_else(|_| PathBuf::from(DEFAULT_KEY_FILE), PathBuf::from);
    let development_fallback = (!environment.is_production())
        .then(|| env::var("CONFIGDECK_MASTER_KEY").ok())
        .flatten();
    load_master_key_from(environment, &path, development_fallback.as_deref())
}

fn load_master_key_from(
    environment: Environment,
    path: &std::path::Path,
    development_fallback: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>, ConfigError> {
    match fs::read_to_string(path) {
        Ok(value) => decode_master_key(&value),
        Err(error)
            if !environment.is_production() && error.kind() == std::io::ErrorKind::NotFound =>
        {
            let value = development_fallback
                .ok_or_else(|| ConfigError::MissingMasterKey(path.to_path_buf()))?;
            decode_master_key(value)
        }
        Err(error) => Err(ConfigError::ReadMasterKey {
            path: path.to_path_buf(),
            source: error,
        }),
    }
}

pub fn decode_master_key(value: &str) -> Result<Zeroizing<[u8; 32]>, ConfigError> {
    let decoded = Zeroizing::new(
        STANDARD
            .decode(value.trim())
            .map_err(|_| ConfigError::InvalidMasterKeyEncoding)?,
    );
    let key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| ConfigError::InvalidMasterKeyLength)?;
    Ok(Zeroizing::new(key))
}

fn bootstrap_settings() -> Result<BootstrapSettings, ConfigError> {
    let email = env::var("CONFIGDECK_ADMIN_EMAIL").ok();
    let password = env::var("CONFIGDECK_ADMIN_PASSWORD")
        .ok()
        .map(Zeroizing::new);
    if email.is_some() != password.is_some() {
        return Err(ConfigError::IncompleteBootstrapCredentials);
    }
    Ok(BootstrapSettings {
        admin_email: email,
        admin_password: password,
    })
}

fn parse_trusted_proxies() -> Result<Vec<IpNet>, ConfigError> {
    env::var("CONFIGDECK_TRUSTED_PROXIES")
        .unwrap_or_default()
        .split(',')
        .filter(|value| !value.trim().is_empty())
        .map(|value| IpNet::from_str(value.trim()).map_err(|_| ConfigError::InvalidTrustedProxy))
        .collect()
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    use super::{Environment, decode_master_key, load_master_key_from};

    #[test]
    fn master_key_requires_exactly_32_bytes() {
        assert!(decode_master_key(&STANDARD.encode([7_u8; 32])).is_ok());
        assert!(decode_master_key(&STANDARD.encode([7_u8; 31])).is_err());
        assert!(decode_master_key("not-base64").is_err());
    }

    #[test]
    fn missing_key_never_generates_a_default() {
        let missing = std::path::Path::new("definitely-not-a-configdeck-key");
        assert!(load_master_key_from(Environment::Production, missing, None).is_err());
        assert!(load_master_key_from(Environment::Development, missing, None).is_err());
    }

    #[test]
    fn environment_fallback_is_rejected_in_production() {
        let missing = std::path::Path::new("definitely-not-a-configdeck-key");
        let fallback = STANDARD.encode([8_u8; 32]);
        assert!(load_master_key_from(Environment::Production, missing, Some(&fallback)).is_err());
        assert!(load_master_key_from(Environment::Development, missing, Some(&fallback)).is_ok());
    }
}
