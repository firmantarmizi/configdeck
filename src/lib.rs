#![forbid(unsafe_code)]

pub mod audit;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod dashboard;
pub mod db;
pub mod dotenv;
pub mod environments;
pub mod error;
pub mod operations;
pub mod organization;
pub mod requests;
pub mod rotations;
pub mod services;
pub mod users;
pub mod variables;
pub mod web;

use std::sync::{Arc, atomic::AtomicBool};

use auth::{AuthService, PasswordService, SessionManager};
use config::Settings;
use crypto::CryptoManager;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub pool: SqlitePool,
    pub crypto: CryptoManager,
    pub passwords: PasswordService,
    pub sessions: SessionManager,
    pub auth: AuthService,
    pub readiness: Arc<AtomicBool>,
}
