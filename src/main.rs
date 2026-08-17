use std::sync::{Arc, atomic::AtomicBool};

use anyhow::{Context, Result};
use configdeck::{
    AppState,
    auth::{AuthService, PasswordService, SessionManager, bootstrap_initial_admin},
    config::Settings,
    crypto::CryptoManager,
    db, operations, web,
};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "serve".to_owned());
    if command == "healthcheck" {
        return healthcheck().await;
    }
    let needs_key = command != "migrate";
    let settings = Arc::new(Settings::from_env(needs_key).context("invalid configuration")?);
    if command == "serve" {
        operations::preflight_restore_intent(&settings.operations, &settings.database.url).await?;
    }
    let pool = db::connect_and_migrate(&settings.database).await?;

    if command == "migrate" {
        info!("database migrations completed");
        return Ok(());
    }
    if command != "serve" {
        anyhow::bail!("unknown command; expected `serve` or `migrate`");
    }

    let master_key = settings
        .master_key
        .clone()
        .context("master key is required while serving")?;
    let crypto = settings.previous_master_key.clone().map_or_else(
        || CryptoManager::new(master_key.clone()),
        |previous| CryptoManager::with_previous(master_key.clone(), previous),
    );
    db::initialize_and_validate_key_registry(&pool, &crypto).await?;
    db::validate_active_environment_keys(&pool, &crypto).await?;
    db::validate_totp_seeds(&pool, &crypto).await?;
    operations::reconcile_restore_intent(&pool, &settings.operations).await?;

    let passwords = PasswordService::production()?;
    bootstrap_initial_admin(&pool, &crypto, &passwords, &settings.bootstrap).await?;

    let sessions = SessionManager::new(pool.clone(), crypto.clone(), settings.session.clone());
    let auth = AuthService::new(
        pool.clone(),
        crypto.clone(),
        passwords.clone(),
        sessions.clone(),
    )
    .await?;
    let state = AppState {
        settings: Arc::clone(&settings),
        pool,
        crypto,
        passwords,
        sessions,
        auth,
        readiness: Arc::new(AtomicBool::new(true)),
    };

    let listener = TcpListener::bind(settings.bind_address)
        .await
        .with_context(|| format!("failed to bind {}", settings.bind_address))?;
    info!(address = %settings.bind_address, "ConfigDeck listening");
    axum::serve(
        listener,
        web::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("HTTP server failed")?;
    Ok(())
}

async fn healthcheck() -> Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let address =
        std::env::var("CONFIGDECK_HEALTH_ADDRESS").unwrap_or_else(|_| "127.0.0.1:3000".to_owned());
    let mut stream = tokio::net::TcpStream::connect(&address)
        .await
        .context("health endpoint is unreachable")?;
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::with_capacity(256);
    stream.take(1024).read_to_end(&mut response).await?;
    if response.starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        anyhow::bail!("health endpoint returned a non-success response")
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
