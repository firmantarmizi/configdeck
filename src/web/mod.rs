use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use askama::Template;
use axum::{
    Form, Json, Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Multipart, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tower_http::{catch_panic::CatchPanicLayer, timeout::TimeoutLayer};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    AppState, audit,
    auth::{AuthenticatedSession, PrivilegedAuthLevel},
    dashboard as dashboard_data, db, environments,
    error::AppError,
    operations, organization, requests, rotations, services,
    users::{self, Capability},
    variables,
};

const STYLE: &str = include_str!("../../static/app.css");
const REQUEST_IMPORT_MAX_ENTRIES: usize = 50;
const SCRIPT: &str = include_str!("../../static/app.js");
const THEME_SCRIPT: &str = include_str!("../../static/theme.js");
const CONFIGDECK_LOGO: &str = include_str!("../../static/configdeck-logo.svg");

#[derive(Clone, Debug)]
struct ClientIdentity(String);

#[derive(Clone, Copy)]
struct AppChrome<'a> {
    csrf_token: &'a str,
    active_nav: &'a str,
    section_label: &'static str,
    user_email: &'a str,
    user_role: &'static str,
    recent_active: bool,
    permissions: AppPermissions,
}

#[derive(Clone, Copy)]
struct AppPermissions {
    can_manage_users: bool,
    can_view_audit: bool,
    can_manage_system: bool,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate<'a> {
    csrf_token: &'a str,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate<'a> {
    chrome: AppChrome<'a>,
    overview: &'a dashboard_data::DashboardOverview,
    branding: &'a organization::OrganizationBranding,
}

#[derive(Template)]
#[template(path = "organization_setup.html")]
struct OrganizationSetupTemplate<'a> {
    csrf_token: &'a str,
    current_name: &'a str,
}

#[derive(Template)]
#[template(path = "users.html")]
struct UsersTemplate<'a> {
    chrome: AppChrome<'a>,
    users: &'a [users::UserRecord],
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditTemplate<'a> {
    chrome: AppChrome<'a>,
    page: &'a audit::AuditPage,
    filter: &'a audit::AuditFilter,
}

#[derive(Template)]
#[template(path = "maintenance.html")]
struct MaintenanceTemplate<'a> {
    chrome: AppChrome<'a>,
    backups: &'a [operations::BackupRecord],
    restore_intent: &'a Option<operations::RestoreIntent>,
    rotations: &'a rotations::RotationOverview,
}

#[derive(Template)]
#[template(path = "password_change.html")]
struct PasswordChangeTemplate<'a> {
    csrf_token: &'a str,
    forced: bool,
}

#[derive(Template)]
#[template(path = "services.html")]
struct ServicesTemplate<'a> {
    chrome: AppChrome<'a>,
    can_manage: bool,
    services: &'a [services::ServiceRecord],
}

#[derive(Template)]
#[template(path = "environments.html")]
struct EnvironmentsTemplate<'a> {
    chrome: AppChrome<'a>,
    can_manage: bool,
    can_create_request: bool,
    can_apply: bool,
    workspace: &'a environments::ComparisonWorkspace,
}

#[derive(Template)]
#[template(path = "variables.html")]
struct VariablesTemplate<'a> {
    chrome: AppChrome<'a>,
    can_apply: bool,
    can_reveal_restricted: bool,
    can_create_request: bool,
    environment: &'a variables::EnvironmentContext,
    variables: &'a [variables::VariableView],
    query: &'a str,
    visibility: &'a str,
}

#[derive(Template)]
#[template(path = "service_access.html")]
struct ServiceAccessTemplate<'a> {
    chrome: AppChrome<'a>,
    service: &'a users::ServiceAccessContext,
    users: &'a [users::ServiceAccessUser],
}

#[derive(Template)]
#[template(path = "change_request_new.html")]
struct ChangeRequestNewTemplate<'a> {
    chrome: AppChrome<'a>,
    environment: &'a variables::EnvironmentContext,
}

#[derive(Template)]
#[template(path = "request_import.html")]
struct RequestImportTemplate<'a> {
    chrome: AppChrome<'a>,
    environment: &'a variables::EnvironmentContext,
    issues: &'a [crate::dotenv::ParseIssue],
}

#[derive(Template)]
#[template(path = "request_import_preview.html")]
struct RequestImportPreviewTemplate<'a> {
    chrome: AppChrome<'a>,
    environment: &'a variables::EnvironmentContext,
    preview_token: &'a str,
    entries: &'a [RequestImportPreviewEntry],
    requires_reason: bool,
}

#[derive(Template)]
#[template(path = "change_requests.html")]
struct ChangeRequestsTemplate<'a> {
    chrome: AppChrome<'a>,
    groups: &'a [ChangeRequestGroup],
    page: &'a requests::ChangeRequestPage,
    can_review: bool,
}

struct ChangeRequestGroup {
    environment_id: String,
    service_name: String,
    environment_name: String,
    requests: Vec<requests::ChangeRequestSummary>,
}

#[derive(Template)]
#[template(path = "change_request_detail.html")]
struct ChangeRequestDetailTemplate<'a> {
    chrome: AppChrome<'a>,
    request: &'a requests::ChangeRequestDetail,
    items: &'a [requests::ChangeRequestItemView],
    can_fulfill: bool,
    can_review: bool,
    can_apply: bool,
}

#[derive(Template)]
#[template(path = "change_request_preview.html")]
struct ChangeRequestPreviewTemplate<'a> {
    chrome: AppChrome<'a>,
    environment: &'a variables::EnvironmentContext,
    dotenv: &'a str,
    fingerprint: &'a str,
    request_ids: &'a str,
    item_count: usize,
}

#[derive(Template)]
#[template(path = "variable_reveal.html")]
struct VariableRevealTemplate<'a> {
    key: &'a str,
    value: &'a str,
    version: Option<i64>,
}

#[derive(Template)]
#[template(path = "variable_history.html")]
struct VariableHistoryTemplate<'a> {
    chrome: AppChrome<'a>,
    variable_id: &'a str,
    key: &'a str,
    can_reveal_restricted: bool,
    history: &'a [variables::HistoryView],
}

#[derive(Template)]
#[template(path = "import.html")]
struct ImportTemplate<'a> {
    chrome: AppChrome<'a>,
    environment: &'a variables::EnvironmentContext,
    issues: &'a [crate::dotenv::ParseIssue],
}

#[derive(Template)]
#[template(path = "import_preview.html")]
struct ImportPreviewTemplate<'a> {
    chrome: AppChrome<'a>,
    environment: &'a variables::EnvironmentContext,
    preview_token: &'a str,
    entries: &'a [ImportPreviewEntry],
}

struct ImportPreviewEntry {
    key: String,
    group_name: Option<String>,
    description: Option<String>,
    starts_group: bool,
    suggested_type: &'static str,
}

#[derive(Template)]
#[template(path = "export.html")]
struct ExportTemplate<'a> {
    chrome: AppChrome<'a>,
    environment: &'a variables::EnvironmentContext,
    dotenv: &'a str,
    keys: &'a [String],
}

#[derive(Template)]
#[template(path = "totp_setup.html")]
struct TotpSetupTemplate<'a> {
    encoded_secret: &'a str,
    provisioning_uri: &'a str,
    qr_code_data_uri: &'a str,
    csrf_token: &'a str,
}

#[derive(Template)]
#[template(path = "recent_auth.html")]
struct RecentAuthTemplate<'a> {
    csrf_token: &'a str,
    return_to: &'a str,
    high_impact: bool,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPageTemplate<'a> {
    code: u16,
    title: &'a str,
    message: &'a str,
    back_href: &'a str,
    back_label: &'a str,
}

#[derive(Deserialize)]
struct LoginForm {
    email: String,
    password: String,
    totp_code: Option<String>,
    csrf_token: String,
}

#[derive(Deserialize)]
struct TotpConfirmForm {
    code: String,
    csrf_token: String,
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf_token: String,
}

#[derive(Deserialize)]
struct RestoreIntentForm {
    backup_identifier: String,
    reason: String,
    csrf_token: String,
}

#[derive(Deserialize)]
struct RotationForm {
    reason: String,
    csrf_token: String,
}

#[derive(Deserialize)]
struct RecentAuthForm {
    password: String,
    totp_code: Option<String>,
    csrf_token: String,
    return_to: String,
    level: String,
}

#[derive(Default, Deserialize)]
struct RecentAuthQuery {
    #[serde(default)]
    return_to: String,
    #[serde(default)]
    level: String,
}

#[derive(Default, Deserialize)]
struct PageQuery {
    #[serde(default)]
    page: u32,
}

#[derive(Deserialize)]
struct MetadataForm {
    name: String,
    description: Option<String>,
    csrf_token: String,
}

#[derive(Deserialize)]
struct AppliedVariableForm {
    key: String,
    value: String,
    visibility: String,
    value_type: String,
    description: Option<String>,
    group_name: Option<String>,
    reason: String,
    csrf_token: String,
}

#[derive(Deserialize)]
struct AppliedDeleteForm {
    reason: String,
    csrf_token: String,
}

#[derive(Deserialize)]
struct ServiceAccessForm {
    user_id: String,
    granted: bool,
    csrf_token: String,
}

#[derive(Deserialize)]
struct UserCreateForm {
    email: String,
    initial_password: String,
    role: String,
    csrf_token: String,
}

#[derive(Deserialize)]
struct UserRoleForm {
    role: String,
    csrf_token: String,
}

#[derive(Deserialize)]
struct UserActiveForm {
    active: bool,
    csrf_token: String,
}

#[derive(Deserialize)]
struct UserPasswordResetForm {
    temporary_password: String,
    confirm_password: String,
    csrf_token: String,
}

#[derive(Deserialize)]
struct InlineVariableEditForm {
    new_key: String,
    value: String,
    value_source: String,
    visibility: String,
    value_type: String,
    description: Option<String>,
    reason: String,
    csrf_token: String,
}

#[derive(Deserialize)]
struct PasswordChangeForm {
    current_password: String,
    new_password: String,
    confirm_password: String,
    csrf_token: String,
}

#[derive(Deserialize)]
struct FulfillValueForm {
    value: String,
    csrf_token: String,
}

#[derive(Deserialize)]
struct RejectRequestForm {
    reason: String,
    csrf_token: String,
}

#[derive(Deserialize)]
struct ApplyRequestForm {
    request_ids: String,
    fingerprint: String,
    csrf_token: String,
}

#[derive(Deserialize)]
struct ImportSourceForm {
    dotenv: String,
    csrf_token: String,
}

#[derive(Deserialize, Serialize)]
struct ImportPreviewPayload {
    purpose: String,
    expires_at: i64,
    entries: Vec<crate::dotenv::Entry>,
}

#[derive(Deserialize, Serialize)]
struct RequestImportPreviewPayload {
    purpose: String,
    expires_at: i64,
    entries: Vec<RequestImportPayloadEntry>,
}

#[derive(Deserialize, Serialize)]
struct RequestImportPayloadEntry {
    action: String,
    entry: crate::dotenv::Entry,
}

struct RequestImportPreviewEntry {
    action: String,
    key: String,
    group_name: Option<String>,
    description: Option<String>,
    starts_group: bool,
    suggested_type: &'static str,
}

#[derive(Default, Deserialize)]
struct VariableQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    visibility: String,
}

#[derive(Default, Deserialize)]
struct KeySearchQuery {
    #[serde(default)]
    q: String,
}

#[derive(Serialize)]
struct ApiEnvironments {
    service: environments::ServiceContext,
    environments: Vec<environments::EnvironmentRecord>,
}

#[derive(Serialize)]
struct ApiVariables {
    environment: variables::EnvironmentContext,
    variables: Vec<variables::VariableView>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(core_routes())
        .merge(configuration_routes())
        .merge(change_routes())
        .merge(api_and_asset_routes())
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(CatchPanicLayer::new())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rotation_write_guard,
        ))
        .layer(middleware::from_fn(friendly_error_pages))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            request_context,
        ))
        .with_state(state)
}

async fn rotation_write_guard(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method();
    let path = request.uri().path();
    let safe_method = matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    let permitted_maintenance_action = path == "/maintenance/rotate-kek"
        || (path.starts_with("/maintenance/environments/") && path.ends_with("/rotate-dek"));
    let authentication_action = path == "/login" || path == "/logout" || path.starts_with("/auth/");
    if !safe_method
        && !permitted_maintenance_action
        && !authentication_action
        && rotations::write_blocked(&state.pool, &state.crypto)
            .await
            .unwrap_or(true)
    {
        return AppError::Conflict.into_response();
    }
    next.run(request).await
}

fn core_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/dashboard", get(dashboard))
        .route(
            "/setup/organization",
            get(organization_setup_page).post(organization_setup_complete),
        )
        .route("/organization/logo", get(organization_logo))
        .route("/users", get(user_list).post(user_create))
        .route("/users/{id}/role", post(user_role_update))
        .route("/users/{id}/active", post(user_active_update))
        .route("/users/{id}/totp-reset", post(user_totp_reset))
        .route("/users/{id}/password-reset", post(user_password_reset))
        .route(
            "/account/password",
            get(password_change_page).post(password_change),
        )
        .route("/audit", get(audit_list))
        .route("/maintenance", get(maintenance_page))
        .route("/maintenance/backups", post(backup_create))
        .route("/maintenance/restore-intent", post(restore_intent_create))
        .route("/maintenance/rotate-kek", post(kek_rotate))
        .route(
            "/maintenance/environments/{id}/rotate-dek",
            post(dek_rotate),
        )
        .route("/auth/totp/setup", get(totp_setup).post(totp_confirm))
        .route("/auth/recent", get(recent_auth_page).post(recent_auth))
}

fn configuration_routes() -> Router<AppState> {
    Router::new()
        .route("/services", get(service_list).post(service_create))
        .route("/services/{id}/update", post(service_update))
        .route("/services/{id}/archive", post(service_archive))
        .route("/services/{id}/restore", post(service_restore))
        .route(
            "/services/{id}/access",
            get(service_access_page).post(service_access_update),
        )
        .route(
            "/services/{id}/environments",
            get(environment_list).post(environment_create),
        )
        .route(
            "/services/{id}/keys/request-edit",
            post(shared_key_request_edit),
        )
        .route("/environments/{id}/update", post(environment_update))
        .route("/environments/{id}/archive", post(environment_archive))
        .route("/environments/{id}/restore", post(environment_restore))
        .route(
            "/environments/{id}/variables",
            get(variable_list).post(variable_record_applied),
        )
        .route(
            "/environments/{environment_id}/variables/{variable_id}/request-edit",
            post(variable_request_edit),
        )
        .route("/environments/{id}/import", get(import_page))
        .route("/environments/{id}/import/preview", post(import_preview))
        .route("/environments/{id}/import/commit", post(import_commit))
        .route("/environments/{id}/export", get(environment_export))
        .route(
            "/environments/{id}/change-requests/new",
            get(change_request_new),
        )
        .route(
            "/environments/{id}/change-requests/import",
            get(request_import_page),
        )
        .route(
            "/environments/{id}/change-requests/import/preview",
            post(request_import_preview),
        )
        .route(
            "/environments/{id}/change-requests/import/commit",
            post(request_import_commit),
        )
        .route(
            "/environments/{id}/change-requests",
            post(change_request_create),
        )
        .route(
            "/environments/{id}/export/download",
            post(environment_export_download),
        )
        .route("/variables/{id}/reveal", post(variable_reveal))
        .route("/variables/{id}/copy", post(variable_copy))
        .route("/variables/{id}/history", get(variable_history))
        .route(
            "/variables/{id}/delete-applied",
            post(variable_delete_applied),
        )
        .route(
            "/variable-versions/{id}/reveal",
            post(variable_version_reveal),
        )
}

fn change_routes() -> Router<AppState> {
    Router::new()
        .route("/change-requests", get(change_request_list))
        .route("/change-requests/{id}", get(change_request_detail))
        .route(
            "/change-requests/{id}/approve",
            post(change_request_approve),
        )
        .route("/change-requests/{id}/reject", post(change_request_reject))
        .route(
            "/change-requests/{id}/preview",
            post(change_request_preview_one),
        )
        .route(
            "/change-requests/preview",
            post(change_request_preview_selected),
        )
        .route("/change-requests/apply", post(change_request_apply))
        .route(
            "/change-request-items/{id}/fulfill",
            post(change_request_fulfill),
        )
}

fn api_and_asset_routes() -> Router<AppState> {
    Router::new()
        .route("/api/services", get(api_service_list))
        .route("/api/search/keys", get(api_key_search))
        .route("/api/services/{id}/environments", get(api_environment_list))
        .route("/api/environments/{id}/variables", get(api_variable_list))
        .route("/api/environments/{id}/export", get(api_environment_export))
        .route("/api/change-requests", post(api_change_request_create))
        .route("/static/app.css", get(stylesheet))
        .route("/static/app.js", get(script))
        .route("/static/theme.js", get(theme_script))
        .route("/static/configdeck-logo.svg", get(configdeck_logo))
}

async fn index(State(state): State<AppState>, headers: HeaderMap) -> Redirect {
    if authenticated_raw(&state, &headers).await.is_ok() {
        Redirect::to("/dashboard")
    } else {
        Redirect::to("/login")
    }
}

async fn health() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({ "status": "ok" })),
    )
}

async fn ready(State(state): State<AppState>) -> Response {
    if state.readiness.load(Ordering::Acquire) && db::ready(&state.pool).await {
        (
            StatusCode::OK,
            axum::Json(serde_json::json!({ "status": "ready" })),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({ "status": "unavailable" })),
        )
            .into_response()
    }
}

fn asset_cache_control(state: &AppState, production_policy: &'static str) -> &'static str {
    if state.settings.environment.is_production() {
        production_policy
    } else {
        "no-store"
    }
}

async fn stylesheet(State(state): State<AppState>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (
                header::CACHE_CONTROL,
                asset_cache_control(&state, "public, max-age=3600"),
            ),
        ],
        STYLE,
    )
}

async fn script(State(state): State<AppState>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (
                header::CACHE_CONTROL,
                asset_cache_control(&state, "public, max-age=3600"),
            ),
        ],
        SCRIPT,
    )
}

async fn theme_script(State(state): State<AppState>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (
                header::CACHE_CONTROL,
                asset_cache_control(&state, "public, max-age=3600"),
            ),
        ],
        THEME_SCRIPT,
    )
}

async fn configdeck_logo(State(state): State<AppState>) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            (
                header::CACHE_CONTROL,
                asset_cache_control(&state, "public, max-age=86400"),
            ),
        ],
        CONFIGDECK_LOGO,
    )
}

async fn login_page(State(state): State<AppState>) -> Result<Response, AppError> {
    let csrf = random_web_token()?;
    let html = LoginTemplate { csrf_token: &csrf }.render()?;
    let mut response = Html(html).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie_header(
            &login_csrf_cookie_name(&state),
            &csrf,
            state.settings.session.secure_cookie,
            600,
        )?,
    );
    Ok(response)
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    client: Option<axum::extract::Extension<ClientIdentity>>,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let cookie =
        cookie_value(&headers, &login_csrf_cookie_name(&state)).ok_or(AppError::Forbidden)?;
    if cookie
        .as_bytes()
        .ct_eq(form.csrf_token.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(AppError::Forbidden);
    }
    let client_identity = client
        .as_ref()
        .map_or("unknown", |identity| identity.0.0.as_str());
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let outcome = state
        .auth
        .authenticate(
            &form.email,
            Zeroizing::new(form.password),
            form.totp_code.as_deref().filter(|value| !value.is_empty()),
            client_identity,
            user_agent,
        )
        .await?;
    let destination = if outcome.enrollment_required {
        "/auth/totp/setup"
    } else if outcome.password_change_required {
        "/account/password"
    } else {
        "/dashboard"
    };
    let mut response = Redirect::to(destination).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        session_cookie(&state, &outcome.tokens.session_token)?,
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        expire_cookie(
            &login_csrf_cookie_name(&state),
            state.settings.session.secure_cookie,
        )?,
    );
    Ok(response)
}

async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (raw, session) = authenticated_raw(&state, &headers).await?;
    if session.authentication_state != crate::auth::AuthenticationState::Full {
        return Ok(Redirect::to("/auth/totp/setup").into_response());
    }
    if session.user.must_change_password {
        return Ok(Redirect::to("/account/password").into_response());
    }
    if !organization::is_onboarding_complete(&state.pool, &session).await? {
        if session.user.role == crate::users::Role::Administrator {
            return Ok(Redirect::to("/setup/organization").into_response());
        }
        return Err(AppError::Forbidden);
    }
    let csrf = state
        .crypto
        .csrf_token(&raw)
        .map_err(|_| AppError::Crypto)?;
    state.sessions.verify_csrf(&session, &csrf)?;
    let overview = dashboard_data::overview(&state.pool, &session).await?;
    let branding = organization::branding(&state.pool, &session).await?;
    let html = DashboardTemplate {
        chrome: app_chrome(&state, &session, &csrf, "overview"),
        overview: &overview,
        branding: &branding,
    }
    .render()?;
    Ok(Html(html).into_response())
}

async fn organization_setup_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (raw, session) = authenticated_raw(&state, &headers).await?;
    session.require_full()?;
    if session.user.must_change_password {
        return Ok(Redirect::to("/account/password").into_response());
    }
    if session.user.role != crate::users::Role::Administrator {
        return Err(AppError::Forbidden);
    }
    if organization::is_onboarding_complete(&state.pool, &session).await? {
        return Ok(Redirect::to("/dashboard").into_response());
    }
    let csrf = state
        .crypto
        .csrf_token(&raw)
        .map_err(|_| AppError::Crypto)?;
    state.sessions.verify_csrf(&session, &csrf)?;
    let branding = organization::branding(&state.pool, &session).await?;
    Ok(Html(
        OrganizationSetupTemplate {
            csrf_token: &csrf,
            current_name: &branding.name,
        }
        .render()?,
    )
    .into_response())
}

async fn organization_setup_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    let (_, session) = authenticated_raw(&state, &headers).await?;
    session.require_full()?;
    if session.user.role != crate::users::Role::Administrator {
        return Err(AppError::Forbidden);
    }
    let mut csrf_token = None;
    let mut organization_name = None;
    let mut logo = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::InvalidRequest)?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "csrf_token" => {
                csrf_token = Some(field.text().await.map_err(|_| AppError::InvalidRequest)?);
            }
            "organization_name" => {
                organization_name = Some(field.text().await.map_err(|_| AppError::InvalidRequest)?);
            }
            "logo" => {
                let mime_type = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_owned();
                let data = field.bytes().await.map_err(|_| AppError::InvalidRequest)?;
                if !data.is_empty() {
                    if data.len() > organization::MAX_LOGO_BYTES {
                        return Err(AppError::InvalidRequest);
                    }
                    logo = Some(organization::UploadedLogo {
                        mime_type,
                        data: data.to_vec(),
                    });
                }
            }
            _ => {}
        }
    }
    state
        .sessions
        .verify_csrf(&session, csrf_token.as_deref().ok_or(AppError::Forbidden)?)?;
    organization::complete_setup(
        &state.pool,
        &session,
        organization::OrganizationSetupInput {
            name: organization_name.ok_or(AppError::InvalidRequest)?,
            logo,
        },
    )
    .await?;
    Ok(Redirect::to("/dashboard").into_response())
}

async fn organization_logo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    session.require_full()?;
    if !organization::is_onboarding_complete(&state.pool, &session).await? {
        return Err(AppError::OrganizationSetupRequired);
    }
    let logo = organization::logo(&state.pool, &session).await?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, logo.mime_type)
        .header(header::CACHE_CONTROL, "private, max-age=300")
        .body(Body::from(logo.data))
        .map_err(|error| AppError::Internal(anyhow::anyhow!(error)))
}

async fn user_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    let records = users::list_users(&state.pool, &session).await?;
    Ok(Html(
        UsersTemplate {
            chrome: app_chrome(&state, &session, &csrf, "users"),
            users: &records,
        }
        .render()?,
    )
    .into_response())
}

async fn maintenance_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    let backups = operations::list_backups(&state.settings.operations, &session).await?;
    let restore_intent =
        operations::read_restore_intent(&state.settings.operations, &session).await?;
    let rotation_overview = rotations::overview(&state.pool, &state.crypto, &session).await?;
    Ok(Html(
        MaintenanceTemplate {
            chrome: app_chrome(&state, &session, &csrf, "maintenance"),
            backups: &backups,
            restore_intent: &restore_intent,
            rotations: &rotation_overview,
        }
        .render()?,
    )
    .into_response())
}

async fn kek_rotate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RotationForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    session.require_full()?;
    if !session.user.role.allows(Capability::RotateKeys) {
        return Err(AppError::Forbidden);
    }
    if !state
        .sessions
        .has_recent_auth(&session, PrivilegedAuthLevel::HighImpact)
    {
        return Ok(Redirect::to("/auth/recent?return_to=/maintenance&level=high").into_response());
    }
    rotations::rotate_kek(
        &state.pool,
        &state.crypto,
        &state.sessions,
        &session,
        &state.readiness,
        &form.reason,
    )
    .await?;
    Ok(Redirect::to("/maintenance").into_response())
}

async fn dek_rotate(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<RotationForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    session.require_full()?;
    if !session.user.role.allows(Capability::RotateKeys) {
        return Err(AppError::Forbidden);
    }
    if !state
        .sessions
        .has_recent_auth(&session, PrivilegedAuthLevel::HighImpact)
    {
        return Ok(Redirect::to("/auth/recent?return_to=/maintenance&level=high").into_response());
    }
    rotations::rotate_dek(
        &state.pool,
        &state.crypto,
        &state.sessions,
        &session,
        &state.readiness,
        &environment_id,
        &form.reason,
    )
    .await?;
    Ok(Redirect::to("/maintenance").into_response())
}

async fn backup_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    session.require_full()?;
    if !session.user.role.allows(Capability::CreateBackup) {
        return Err(AppError::Forbidden);
    }
    if !state
        .sessions
        .has_recent_auth(&session, PrivilegedAuthLevel::Standard)
    {
        return Ok(Redirect::to("/auth/recent?return_to=/maintenance").into_response());
    }
    operations::create_backup(
        &state.pool,
        &state.settings.operations,
        &state.sessions,
        &session,
    )
    .await?;
    Ok(Redirect::to("/maintenance").into_response())
}

async fn restore_intent_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RestoreIntentForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    session.require_full()?;
    if !session.user.role.allows(Capability::CreateRestoreIntent) {
        return Err(AppError::Forbidden);
    }
    if !state
        .sessions
        .has_recent_auth(&session, PrivilegedAuthLevel::Standard)
    {
        return Ok(Redirect::to("/auth/recent?return_to=/maintenance").into_response());
    }
    operations::create_restore_intent(
        &state.pool,
        &state.settings.operations,
        &state.sessions,
        &session,
        &form.backup_identifier,
        &form.reason,
    )
    .await?;
    Ok(Redirect::to("/maintenance").into_response())
}

async fn user_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<UserCreateForm>,
) -> Result<Response, AppError> {
    let (_, session, _) = authenticated_full_with_csrf(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    users::create_user(
        &state.pool,
        &state.passwords,
        &session,
        users::UserCreateInput {
            email: form.email,
            initial_password: Zeroizing::new(form.initial_password),
            role: form.role,
        },
    )
    .await?;
    Ok(Redirect::to("/users").into_response())
}

async fn user_role_update(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<UserRoleForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    if !state
        .sessions
        .has_recent_auth(&session, PrivilegedAuthLevel::Standard)
    {
        return Ok(Redirect::to("/auth/recent?return_to=/users").into_response());
    }
    users::update_role(&state.pool, &state.sessions, &session, &user_id, &form.role).await?;
    Ok(Redirect::to("/users").into_response())
}

async fn user_active_update(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<UserActiveForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    if !state
        .sessions
        .has_recent_auth(&session, PrivilegedAuthLevel::Standard)
    {
        return Ok(Redirect::to("/auth/recent?return_to=/users").into_response());
    }
    users::set_active(
        &state.pool,
        &state.sessions,
        &session,
        &user_id,
        form.active,
    )
    .await?;
    Ok(Redirect::to("/users").into_response())
}

async fn user_totp_reset(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    if !state
        .sessions
        .has_recent_auth(&session, PrivilegedAuthLevel::Standard)
    {
        return Ok(Redirect::to("/auth/recent?return_to=/users").into_response());
    }
    users::reset_totp(&state.pool, &state.sessions, &session, &user_id).await?;
    Ok(Redirect::to("/users").into_response())
}

async fn user_password_reset(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<UserPasswordResetForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    if !state
        .sessions
        .has_recent_auth(&session, PrivilegedAuthLevel::Standard)
    {
        return Ok(Redirect::to("/auth/recent?return_to=/users").into_response());
    }
    if form.temporary_password != form.confirm_password {
        return Err(AppError::InvalidRequest);
    }
    users::reset_password(
        &state.pool,
        &state.passwords,
        &state.sessions,
        &session,
        &user_id,
        Zeroizing::new(form.temporary_password),
    )
    .await?;
    Ok(Redirect::to("/users").into_response())
}

async fn password_change_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (raw, session) = authenticated_raw(&state, &headers).await?;
    session.require_full()?;
    let csrf = state
        .crypto
        .csrf_token(&raw)
        .map_err(|_| AppError::Crypto)?;
    state.sessions.verify_csrf(&session, &csrf)?;
    Ok(Html(
        PasswordChangeTemplate {
            csrf_token: &csrf,
            forced: session.user.must_change_password,
        }
        .render()?,
    )
    .into_response())
}

async fn password_change(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PasswordChangeForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated_raw(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    if form.new_password != form.confirm_password {
        return Err(AppError::InvalidRequest);
    }
    users::change_own_password(
        &state.pool,
        &state.passwords,
        &session,
        Zeroizing::new(form.current_password),
        Zeroizing::new(form.new_password),
    )
    .await?;
    let mut response = Redirect::to("/login").into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        expire_cookie(
            &state.settings.session.cookie_name,
            state.settings.session.secure_cookie,
        )?,
    );
    Ok(response)
}

async fn audit_list(
    State(state): State<AppState>,
    Query(filter): Query<audit::AuditFilter>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    let page = audit::list(&state.pool, &session, &filter).await?;
    Ok(Html(
        AuditTemplate {
            chrome: app_chrome(&state, &session, &csrf, "audit"),
            page: &page,
            filter: &filter,
        }
        .render()?,
    )
    .into_response())
}

async fn service_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    let records = services::list_accessible(&state.pool, &session).await?;
    let html = ServicesTemplate {
        chrome: app_chrome(&state, &session, &csrf, "configurations"),
        can_manage: session
            .user
            .role
            .allows(crate::users::Capability::ManageMetadata),
        services: &records,
    }
    .render()?;
    Ok(Html(html).into_response())
}

async fn service_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<MetadataForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    services::create_with_default_environments(
        &state.pool,
        &state.crypto,
        &session,
        services::ServiceInput {
            name: form.name,
            description: form.description,
        },
    )
    .await?;
    Ok(Redirect::to("/services").into_response())
}

async fn service_update(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<MetadataForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    services::update(
        &state.pool,
        &session,
        &service_id,
        services::ServiceInput {
            name: form.name,
            description: form.description,
        },
    )
    .await?;
    Ok(Redirect::to("/services").into_response())
}

async fn service_archive(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    set_service_archived(&state, &headers, &form.csrf_token, &service_id, true).await
}

async fn service_restore(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    set_service_archived(&state, &headers, &form.csrf_token, &service_id, false).await
}

async fn service_access_page(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    let (service, users) = users::list_service_access(&state.pool, &session, &service_id).await?;
    Ok(Html(
        ServiceAccessTemplate {
            chrome: app_chrome(&state, &session, &csrf, "configurations"),
            service: &service,
            users: &users,
        }
        .render()?,
    )
    .into_response())
}

async fn service_access_update(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ServiceAccessForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    users::set_service_access(
        &state.pool,
        &session,
        &service_id,
        &form.user_id,
        form.granted,
    )
    .await?;
    Ok(Redirect::to(&format!("/services/{service_id}/access")).into_response())
}

async fn set_service_archived(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    service_id: &str,
    archived: bool,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(state, headers).await?;
    state.sessions.verify_csrf(&session, csrf)?;
    services::set_archived(&state.pool, &session, service_id, archived).await?;
    Ok(Redirect::to("/services").into_response())
}

async fn environment_list(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    let workspace =
        environments::comparison_for_service(&state.pool, &state.crypto, &session, &service_id)
            .await?;
    let html = EnvironmentsTemplate {
        chrome: app_chrome(&state, &session, &csrf, "configurations"),
        can_manage: session
            .user
            .role
            .allows(crate::users::Capability::ManageMetadata),
        can_create_request: session.user.role.allows(Capability::CreateChangeRequest),
        can_apply: session.user.role.allows(Capability::ApplyRequest),
        workspace: &workspace,
    }
    .render()?;
    Ok(Html(html).into_response())
}

async fn variable_request_edit(
    State(state): State<AppState>,
    Path((environment_id, variable_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<InlineVariableEditForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    let request_id = requests::create_inline_edit(
        &state.pool,
        &state.crypto,
        &session,
        &environment_id,
        requests::InlineEditInput {
            variable_id,
            new_key: form.new_key,
            value: form.value,
            value_source: form.value_source,
            visibility: form.visibility,
            value_type: form.value_type,
            description: form.description,
            reason: form.reason,
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/change-requests/{request_id}")).into_response())
}

async fn shared_key_request_edit(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    headers: HeaderMap,
    Form(mut fields): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    let csrf = fields
        .remove("csrf_token")
        .ok_or(AppError::InvalidRequest)?;
    state.sessions.verify_csrf(&session, &csrf)?;
    let current_key = fields
        .remove("current_key")
        .ok_or(AppError::InvalidRequest)?;
    let new_key = fields.remove("new_key").ok_or(AppError::InvalidRequest)?;
    let visibility = fields
        .remove("visibility")
        .ok_or(AppError::InvalidRequest)?;
    let value_type = fields
        .remove("value_type")
        .ok_or(AppError::InvalidRequest)?;
    let reason = fields.remove("reason").ok_or(AppError::InvalidRequest)?;
    let item_count = fields
        .remove("item_count")
        .ok_or(AppError::InvalidRequest)?
        .parse::<usize>()
        .map_err(|_| AppError::InvalidRequest)?;
    if item_count == 0 || item_count > REQUEST_IMPORT_MAX_ENTRIES {
        return Err(AppError::InvalidRequest);
    }
    let mut values = Vec::with_capacity(item_count);
    for index in 0..item_count {
        let environment_id = fields
            .remove(&format!("environment_id_{index}"))
            .ok_or(AppError::InvalidRequest)?;
        let variable_id = fields
            .remove(&format!("variable_id_{index}"))
            .unwrap_or_default();
        if variable_id.is_empty() {
            continue;
        }
        values.push(requests::SharedInlineValueInput {
            environment_id,
            variable_id,
            value: fields.remove(&format!("value_{index}")).unwrap_or_default(),
            value_source: fields
                .remove(&format!("value_source_{index}"))
                .ok_or(AppError::InvalidRequest)?,
            description: fields
                .remove(&format!("description_{index}"))
                .filter(|value| !value.trim().is_empty()),
        });
    }
    requests::create_shared_inline_edit(
        &state.pool,
        &state.crypto,
        &session,
        requests::SharedInlineEditInput {
            service_id,
            current_key,
            new_key,
            visibility,
            value_type,
            reason,
            values,
        },
    )
    .await?;
    Ok(Redirect::to("/change-requests").into_response())
}

async fn environment_create(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<MetadataForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    environments::create(
        &state.pool,
        &state.crypto,
        &session,
        &service_id,
        environments::EnvironmentInput {
            name: form.name,
            description: form.description,
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/services/{service_id}/environments")).into_response())
}

async fn environment_update(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<MetadataForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    let service_id = environments::update(
        &state.pool,
        &session,
        &environment_id,
        environments::EnvironmentInput {
            name: form.name,
            description: form.description,
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/services/{service_id}/environments")).into_response())
}

async fn environment_archive(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    set_environment_archived(&state, &headers, &form.csrf_token, &environment_id, true).await
}

async fn environment_restore(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    set_environment_archived(&state, &headers, &form.csrf_token, &environment_id, false).await
}

async fn set_environment_archived(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
    environment_id: &str,
    archived: bool,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(state, headers).await?;
    state.sessions.verify_csrf(&session, csrf)?;
    let service_id =
        environments::set_archived(&state.pool, &session, environment_id, archived).await?;
    Ok(Redirect::to(&format!("/services/{service_id}/environments")).into_response())
}

async fn variable_list(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    Query(query): Query<VariableQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    let (environment, records) = variables::list_for_environment_filtered(
        &state.pool,
        &state.crypto,
        &session,
        &environment_id,
        &variables::VariableFilter {
            query: query.q.clone(),
            visibility: query.visibility.clone(),
        },
    )
    .await?;
    let html = VariablesTemplate {
        chrome: app_chrome(&state, &session, &csrf, "configurations"),
        can_apply: session
            .user
            .role
            .allows(crate::users::Capability::ApplyRequest),
        can_reveal_restricted: session
            .user
            .role
            .allows(crate::users::Capability::ReadRestrictedValue),
        can_create_request: session.user.role.allows(Capability::CreateChangeRequest),
        environment: &environment,
        variables: &records,
        query: &query.q,
        visibility: &query.visibility,
    }
    .render()?;
    Ok(Html(html).into_response())
}

async fn change_request_new(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    if !session.user.role.allows(Capability::CreateChangeRequest) {
        return Err(AppError::Forbidden);
    }
    let environment =
        variables::environment_context(&state.pool, &session, &environment_id).await?;
    variables::ensure_mutable(&environment)?;
    Ok(Html(
        ChangeRequestNewTemplate {
            chrome: app_chrome(&state, &session, &csrf, "changes"),
            environment: &environment,
        }
        .render()?,
    )
    .into_response())
}

async fn request_import_page(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    if !session.user.role.allows(Capability::CreateChangeRequest) {
        return Err(AppError::Forbidden);
    }
    let environment =
        variables::environment_context(&state.pool, &session, &environment_id).await?;
    variables::ensure_mutable(&environment)?;
    Ok(Html(
        RequestImportTemplate {
            chrome: app_chrome(&state, &session, &csrf, "changes"),
            environment: &environment,
            issues: &[],
        }
        .render()?,
    )
    .into_response())
}

async fn request_import_preview(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ImportSourceForm>,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    if !session.user.role.allows(Capability::CreateChangeRequest) {
        return Err(AppError::Forbidden);
    }
    let environment =
        variables::environment_context(&state.pool, &session, &environment_id).await?;
    variables::ensure_mutable(&environment)?;
    let mut report = crate::dotenv::parse(&form.dotenv);
    if report.entries.len() > REQUEST_IMPORT_MAX_ENTRIES {
        report.issues.push(crate::dotenv::ParseIssue {
            line: 0,
            message: "a request can contain at most 50 variables",
        });
    }
    if !report.issues.is_empty() {
        let html = RequestImportTemplate {
            chrome: app_chrome(&state, &session, &csrf, "changes"),
            environment: &environment,
            issues: &report.issues,
        }
        .render()?;
        return Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response());
    }
    let existing = active_environment_keys(&state.pool, &environment_id).await?;
    let entries = report
        .entries
        .into_iter()
        .map(|entry| RequestImportPayloadEntry {
            action: if existing.contains(&entry.key) {
                "UPDATE".to_owned()
            } else {
                "ADD".to_owned()
            },
            entry,
        })
        .collect::<Vec<_>>();
    let payload = RequestImportPreviewPayload {
        purpose: "CHANGE_REQUEST_IMPORT".to_owned(),
        expires_at: time::OffsetDateTime::now_utc().unix_timestamp() + 30 * 60,
        entries,
    };
    let serialized = Zeroizing::new(
        serde_json::to_vec(&payload)
            .map_err(|error| AppError::Internal(anyhow::Error::new(error)))?,
    );
    let preview_token = state
        .crypto
        .seal_import_preview(&session.user.id, &session.id, &environment_id, &serialized)
        .map_err(|_| AppError::Crypto)?;
    let mut previous_group = None;
    let preview_entries = payload
        .entries
        .iter()
        .map(|payload_entry| {
            let entry = &payload_entry.entry;
            let starts_group = entry.group.is_some() && entry.group != previous_group;
            previous_group.clone_from(&entry.group);
            RequestImportPreviewEntry {
                action: payload_entry.action.clone(),
                key: entry.key.clone(),
                group_name: entry.group.clone(),
                description: entry.description.clone(),
                starts_group,
                suggested_type: variables::suggest_value_type(&entry.value),
            }
        })
        .collect::<Vec<_>>();
    let requires_reason = payload.entries.iter().any(|entry| entry.action == "UPDATE");
    Ok(Html(
        RequestImportPreviewTemplate {
            chrome: app_chrome(&state, &session, &csrf, "changes"),
            environment: &environment,
            preview_token: &preview_token,
            entries: &preview_entries,
            requires_reason,
        }
        .render()?,
    )
    .into_response())
}

async fn request_import_commit(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
    Form(mut fields): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    let csrf = fields
        .remove("csrf_token")
        .ok_or(AppError::InvalidRequest)?;
    state.sessions.verify_csrf(&session, &csrf)?;
    if !session.user.role.allows(Capability::CreateChangeRequest) {
        return Err(AppError::Forbidden);
    }
    let token = fields
        .remove("preview_token")
        .ok_or(AppError::InvalidRequest)?;
    let plaintext = state
        .crypto
        .open_import_preview(&session.user.id, &session.id, &environment_id, &token)
        .map_err(|_| AppError::InvalidRequest)?;
    let payload: RequestImportPreviewPayload =
        serde_json::from_slice(&plaintext).map_err(|_| AppError::InvalidRequest)?;
    if payload.purpose != "CHANGE_REQUEST_IMPORT"
        || payload.expires_at < time::OffsetDateTime::now_utc().unix_timestamp()
        || payload.entries.is_empty()
        || payload.entries.len() > REQUEST_IMPORT_MAX_ENTRIES
    {
        return Err(AppError::InvalidRequest);
    }
    let title = fields.remove("title");
    let reason = fields.remove("reason").unwrap_or_default();
    let mut items = Vec::with_capacity(payload.entries.len());
    for (index, mut payload_entry) in payload.entries.into_iter().enumerate() {
        let visibility = fields
            .remove(&format!("visibility_{index}"))
            .ok_or(AppError::InvalidRequest)?;
        let value_type = fields
            .remove(&format!("value_type_{index}"))
            .ok_or(AppError::InvalidRequest)?;
        items.push(requests::ChangeRequestItemInput {
            action: payload_entry.action,
            key: std::mem::take(&mut payload_entry.entry.key),
            value: Some(std::mem::take(&mut payload_entry.entry.value)),
            value_source: Some("REQUESTER_PROVIDED".to_owned()),
            visibility: Some(visibility),
            value_type: Some(value_type),
            description: fields.remove(&format!("description_{index}")),
            group_name: fields.remove(&format!("group_name_{index}")),
            display_order: Some(payload_entry.entry.position),
        });
    }
    let id = requests::create(
        &state.pool,
        &state.crypto,
        &session,
        requests::ChangeRequestInput {
            environment_id,
            title,
            reason,
            items,
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/change-requests/{id}")).into_response())
}

async fn active_environment_keys(
    pool: &sqlx::SqlitePool,
    environment_id: &str,
) -> Result<HashSet<String>, AppError> {
    Ok(sqlx::query_scalar::<_, String>(
        "SELECT key FROM variables WHERE environment_id = ? AND lifecycle_status = 'ACTIVE'",
    )
    .bind(environment_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect())
}

async fn change_request_create(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    let csrf = form.get("csrf_token").ok_or(AppError::Forbidden)?;
    state.sessions.verify_csrf(&session, csrf)?;
    let input = request_input_from_form(&environment_id, &form);
    let id = requests::create(&state.pool, &state.crypto, &session, input).await?;
    Ok(Redirect::to(&format!("/change-requests/{id}")).into_response())
}

async fn change_request_list(
    State(state): State<AppState>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    let page = requests::list_visible_page(&state.pool, &session, query.page.min(100_000)).await?;
    let groups = group_change_requests(page.records.clone());
    Ok(Html(
        ChangeRequestsTemplate {
            chrome: app_chrome(&state, &session, &csrf, "changes"),
            groups: &groups,
            page: &page,
            can_review: session.user.role.allows(Capability::ReviewRequest),
        }
        .render()?,
    )
    .into_response())
}

fn group_change_requests(records: Vec<requests::ChangeRequestSummary>) -> Vec<ChangeRequestGroup> {
    let mut groups = Vec::<ChangeRequestGroup>::new();
    for record in records {
        if let Some(group) = groups
            .iter_mut()
            .find(|group| group.environment_id == record.environment_id)
        {
            group.requests.push(record);
        } else {
            groups.push(ChangeRequestGroup {
                environment_id: record.environment_id.clone(),
                service_name: record.service_name.clone(),
                environment_name: record.environment_name.clone(),
                requests: vec![record],
            });
        }
    }
    groups
}

async fn change_request_detail(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    let (request, items) =
        requests::detail(&state.pool, &state.crypto, &session, &request_id).await?;
    Ok(Html(
        ChangeRequestDetailTemplate {
            chrome: app_chrome(&state, &session, &csrf, "changes"),
            request: &request,
            items: &items,
            can_fulfill: session.user.role.allows(Capability::FulfillValue),
            can_review: session.user.role.allows(Capability::ReviewRequest),
            can_apply: session.user.role.allows(Capability::ApplyRequest),
        }
        .render()?,
    )
    .into_response())
}

async fn change_request_approve(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    requests::approve(&state.pool, &session, &request_id).await?;
    Ok(Redirect::to(&format!("/change-requests/{request_id}")).into_response())
}

async fn change_request_reject(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<RejectRequestForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    requests::reject(&state.pool, &session, &request_id, &form.reason).await?;
    Ok(Redirect::to(&format!("/change-requests/{request_id}")).into_response())
}

async fn change_request_preview_one(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    change_request_preview(state, headers, form.csrf_token, vec![request_id]).await
}

async fn change_request_preview_selected(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(mut form): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let csrf = form.remove("csrf_token").ok_or(AppError::Forbidden)?;
    let request_ids = form
        .into_iter()
        .filter_map(|(key, value)| key.starts_with("request_").then_some(value))
        .collect();
    change_request_preview(state, headers, csrf, request_ids).await
}

async fn change_request_preview(
    state: AppState,
    headers: HeaderMap,
    csrf: String,
    request_ids: Vec<String>,
) -> Result<Response, AppError> {
    let (_, session, render_csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &csrf)?;
    let preview = requests::preview_resulting(
        &state.pool,
        &state.crypto,
        &state.sessions,
        &session,
        request_ids,
    )
    .await?;
    let request_ids = preview.request_ids.join(",");
    let html = ChangeRequestPreviewTemplate {
        chrome: app_chrome(&state, &session, &render_csrf, "changes"),
        environment: &preview.environment,
        dotenv: preview.dotenv.as_str(),
        fingerprint: &preview.fingerprint,
        request_ids: &request_ids,
        item_count: preview.item_count,
    }
    .render()?;
    Ok(Html(html).into_response())
}

async fn change_request_apply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ApplyRequestForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    let request_ids = form.request_ids.split(',').map(str::to_owned).collect();
    let environment_id = requests::mark_applied(
        &state.pool,
        &state.crypto,
        &state.sessions,
        &session,
        request_ids,
        &form.fingerprint,
    )
    .await?;
    Ok(Redirect::to(&format!("/environments/{environment_id}/variables")).into_response())
}

async fn change_request_fulfill(
    State(state): State<AppState>,
    Path(item_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<FulfillValueForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    let request_id = requests::fulfill_value(
        &state.pool,
        &state.crypto,
        &state.sessions,
        &session,
        &item_id,
        form.value,
    )
    .await?;
    Ok(Redirect::to(&format!("/change-requests/{request_id}")).into_response())
}

async fn api_change_request_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<requests::ChangeRequestInput>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Forbidden)?;
    state.sessions.verify_csrf(&session, csrf)?;
    let id = requests::create(&state.pool, &state.crypto, &session, input).await?;
    Ok((StatusCode::CREATED, Json(serde_json::json!({"id": id}))))
}

fn request_input_from_form(
    environment_id: &str,
    form: &HashMap<String, String>,
) -> requests::ChangeRequestInput {
    let mut items = Vec::new();
    for index in 0..REQUEST_IMPORT_MAX_ENTRIES {
        let action = form
            .get(&format!("action_{index}"))
            .map_or("", String::as_str);
        let key = form.get(&format!("key_{index}")).map_or("", String::as_str);
        if action.is_empty() && key.trim().is_empty() {
            continue;
        }
        items.push(requests::ChangeRequestItemInput {
            action: action.to_owned(),
            key: key.to_owned(),
            value: form.get(&format!("value_{index}")).cloned(),
            value_source: form.get(&format!("value_source_{index}")).cloned(),
            visibility: form.get(&format!("visibility_{index}")).cloned(),
            value_type: form.get(&format!("value_type_{index}")).cloned(),
            description: form.get(&format!("description_{index}")).cloned(),
            group_name: form.get(&format!("group_name_{index}")).cloned(),
            display_order: form
                .get(&format!("display_order_{index}"))
                .and_then(|value| value.parse().ok()),
        });
    }
    requests::ChangeRequestInput {
        environment_id: environment_id.to_owned(),
        title: form.get("title").cloned(),
        reason: form.get("reason").cloned().unwrap_or_default(),
        items,
    }
}

async fn variable_delete_applied(
    State(state): State<AppState>,
    Path(variable_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<AppliedDeleteForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    let environment_id = variables::delete_applied(
        &state.pool,
        &state.crypto,
        &session,
        &variable_id,
        &form.reason,
    )
    .await?;
    Ok(Redirect::to(&format!("/environments/{environment_id}/variables")).into_response())
}

async fn api_service_list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<services::ServiceRecord>>, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    Ok(Json(
        services::list_accessible(&state.pool, &session).await?,
    ))
}

async fn api_key_search(
    State(state): State<AppState>,
    Query(query): Query<KeySearchQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<environments::KeySearchResult>>, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    Ok(Json(
        environments::search_accessible_keys(&state.pool, &session, &query.q).await?,
    ))
}

async fn api_environment_list(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvironments>, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    let (service, environments) =
        environments::list_for_service(&state.pool, &session, &service_id).await?;
    Ok(Json(ApiEnvironments {
        service,
        environments,
    }))
}

async fn api_variable_list(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    Query(query): Query<VariableQuery>,
    headers: HeaderMap,
) -> Result<Json<ApiVariables>, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    let (environment, variables) = variables::list_for_environment_filtered(
        &state.pool,
        &state.crypto,
        &session,
        &environment_id,
        &variables::VariableFilter {
            query: query.q,
            visibility: query.visibility,
        },
    )
    .await?;
    Ok(Json(ApiVariables {
        environment,
        variables,
    }))
}

async fn api_environment_export(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    let (_, dotenv) = variables::export_environment(
        &state.pool,
        &state.crypto,
        &state.sessions,
        &session,
        &environment_id,
    )
    .await?;
    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        dotenv.to_string(),
    )
        .into_response())
}

async fn variable_record_applied(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<AppliedVariableForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    variables::record_applied(
        &state.pool,
        &state.crypto,
        &session,
        &environment_id,
        variables::AppliedVariableInput {
            key: form.key,
            value: form.value,
            visibility: form.visibility,
            value_type: form.value_type,
            description: form.description,
            group_name: form.group_name,
            display_order: 0,
            reason: form.reason,
        },
    )
    .await?;
    Ok(Redirect::to(&format!("/environments/{environment_id}/variables")).into_response())
}

async fn import_page(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    if !session.user.role.allows(Capability::ApplyRequest) {
        return Err(AppError::Forbidden);
    }
    if !state
        .sessions
        .has_recent_auth(&session, PrivilegedAuthLevel::Standard)
    {
        return Ok(Redirect::to(&format!(
            "/auth/recent?return_to=/environments/{environment_id}/import"
        ))
        .into_response());
    }
    require_recent_import(&state, &session)?;
    let (environment, _) =
        variables::list_for_environment(&state.pool, &state.crypto, &session, &environment_id)
            .await?;
    let html = ImportTemplate {
        chrome: app_chrome(&state, &session, &csrf, "configurations"),
        environment: &environment,
        issues: &[],
    }
    .render()?;
    Ok(Html(html).into_response())
}

async fn import_preview(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<ImportSourceForm>,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    require_recent_import(&state, &session)?;
    let (environment, _) =
        variables::list_for_environment(&state.pool, &state.crypto, &session, &environment_id)
            .await?;
    let report = crate::dotenv::parse(&form.dotenv);
    if !report.issues.is_empty() {
        let html = ImportTemplate {
            chrome: app_chrome(&state, &session, &csrf, "configurations"),
            environment: &environment,
            issues: &report.issues,
        }
        .render()?;
        return Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response());
    }
    let payload = ImportPreviewPayload {
        purpose: "APPLIED_IMPORT".to_owned(),
        expires_at: time::OffsetDateTime::now_utc().unix_timestamp() + 30 * 60,
        entries: report.entries,
    };
    let serialized = Zeroizing::new(
        serde_json::to_vec(&payload)
            .map_err(|error| AppError::Internal(anyhow::Error::new(error)))?,
    );
    let preview_token = state
        .crypto
        .seal_import_preview(&session.user.id, &session.id, &environment_id, &serialized)
        .map_err(|_| AppError::Crypto)?;
    let mut previous_group = None;
    let preview_entries = payload
        .entries
        .iter()
        .map(|entry| {
            let starts_group = entry.group.is_some() && entry.group != previous_group;
            previous_group.clone_from(&entry.group);
            ImportPreviewEntry {
                key: entry.key.clone(),
                group_name: entry.group.clone(),
                description: entry.description.clone(),
                starts_group,
                suggested_type: variables::suggest_value_type(&entry.value),
            }
        })
        .collect::<Vec<_>>();
    let html = ImportPreviewTemplate {
        chrome: app_chrome(&state, &session, &csrf, "configurations"),
        environment: &environment,
        preview_token: &preview_token,
        entries: &preview_entries,
    }
    .render()?;
    Ok(Html(html).into_response())
}

async fn import_commit(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
    Form(mut fields): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    let csrf = fields
        .remove("csrf_token")
        .ok_or(AppError::InvalidRequest)?;
    state.sessions.verify_csrf(&session, &csrf)?;
    require_recent_import(&state, &session)?;
    let token = fields
        .remove("preview_token")
        .ok_or(AppError::InvalidRequest)?;
    let reason = fields.remove("reason").ok_or(AppError::InvalidRequest)?;
    let plaintext = state
        .crypto
        .open_import_preview(&session.user.id, &session.id, &environment_id, &token)
        .map_err(|_| AppError::InvalidRequest)?;
    let payload: ImportPreviewPayload =
        serde_json::from_slice(&plaintext).map_err(|_| AppError::InvalidRequest)?;
    if payload.purpose != "APPLIED_IMPORT"
        || payload.expires_at < time::OffsetDateTime::now_utc().unix_timestamp()
        || payload.entries.is_empty()
        || payload.entries.len() > crate::dotenv::MAX_ENTRIES
    {
        return Err(AppError::InvalidRequest);
    }
    let mut inputs = Vec::with_capacity(payload.entries.len());
    for (index, mut entry) in payload.entries.into_iter().enumerate() {
        let visibility = fields
            .remove(&format!("visibility_{index}"))
            .ok_or(AppError::InvalidRequest)?;
        let value_type = fields
            .remove(&format!("value_type_{index}"))
            .ok_or(AppError::InvalidRequest)?;
        let group_name = fields.remove(&format!("group_name_{index}"));
        let description = fields.remove(&format!("description_{index}"));
        inputs.push(variables::AppliedVariableInput {
            key: std::mem::take(&mut entry.key),
            value: std::mem::take(&mut entry.value),
            visibility,
            value_type,
            description,
            group_name,
            display_order: entry.position,
            reason: reason.clone(),
        });
    }
    variables::import_applied(
        &state.pool,
        &state.crypto,
        &session,
        &environment_id,
        inputs,
    )
    .await?;
    Ok(Redirect::to(&format!("/environments/{environment_id}/variables")).into_response())
}

async fn environment_export(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    if !session.user.role.allows(Capability::ExportEnvironment) {
        return Err(AppError::Forbidden);
    }
    if !state
        .sessions
        .has_recent_auth(&session, PrivilegedAuthLevel::Standard)
    {
        return Ok(Redirect::to(&format!(
            "/auth/recent?return_to=/environments/{environment_id}/export"
        ))
        .into_response());
    }
    let (environment, dotenv) = variables::export_environment(
        &state.pool,
        &state.crypto,
        &state.sessions,
        &session,
        &environment_id,
    )
    .await?;
    let keys = dotenv
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| line.split_once('=').map(|(key, _)| key.to_owned()))
        .collect::<Vec<_>>();
    let html = ExportTemplate {
        chrome: app_chrome(&state, &session, &csrf, "configurations"),
        environment: &environment,
        dotenv: &dotenv,
        keys: &keys,
    }
    .render()?;
    Ok(Html(html).into_response())
}

async fn environment_export_download(
    State(state): State<AppState>,
    Path(environment_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    let (_, dotenv) = variables::export_environment(
        &state.pool,
        &state.crypto,
        &state.sessions,
        &session,
        &environment_id,
    )
    .await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"environment.env\"",
            ),
        ],
        dotenv.to_string(),
    )
        .into_response())
}

async fn variable_reveal(
    State(state): State<AppState>,
    Path(variable_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    let (key, value) = variables::reveal_current(
        &state.pool,
        &state.crypto,
        &state.sessions,
        &session,
        &variable_id,
    )
    .await?;
    let html = VariableRevealTemplate {
        key: &key,
        value: &value,
        version: None,
    }
    .render()?;
    Ok(Html(html).into_response())
}

async fn variable_copy(
    State(state): State<AppState>,
    Path(variable_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    let value = variables::copy_current(
        &state.pool,
        &state.crypto,
        &state.sessions,
        &session,
        &variable_id,
    )
    .await?;
    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        value.to_string(),
    )
        .into_response())
}

async fn variable_history(
    State(state): State<AppState>,
    Path(variable_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_, session, csrf) = authenticated_full_with_csrf(&state, &headers).await?;
    let (key, history) =
        variables::history(&state.pool, &state.crypto, &session, &variable_id).await?;
    let html = VariableHistoryTemplate {
        chrome: app_chrome(&state, &session, &csrf, "configurations"),
        variable_id: &variable_id,
        key: &key,
        can_reveal_restricted: session
            .user
            .role
            .allows(crate::users::Capability::ReadRestrictedValue),
        history: &history,
    }
    .render()?;
    Ok(Html(html).into_response())
}

async fn variable_version_reveal(
    State(state): State<AppState>,
    Path(version_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    let (key, version, value) = variables::reveal_version(
        &state.pool,
        &state.crypto,
        &state.sessions,
        &session,
        &version_id,
    )
    .await?;
    let html = VariableRevealTemplate {
        key: &key,
        value: &value,
        version: Some(version),
    }
    .render()?;
    Ok(Html(html).into_response())
}

async fn totp_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (raw, session) = authenticated_raw(&state, &headers).await?;
    let csrf = state
        .crypto
        .csrf_token(&raw)
        .map_err(|_| AppError::Crypto)?;
    state.sessions.verify_csrf(&session, &csrf)?;
    let enrollment = state.auth.enrollment_data(&session).await?;
    let qr_code_data_uri = totp_qr_code_data_uri(&enrollment.provisioning_uri)?;
    let html = TotpSetupTemplate {
        encoded_secret: &enrollment.encoded_secret,
        provisioning_uri: &enrollment.provisioning_uri,
        qr_code_data_uri: &qr_code_data_uri,
        csrf_token: &csrf,
    }
    .render()?;
    Ok(Html(html).into_response())
}

fn totp_qr_code_data_uri(provisioning_uri: &str) -> Result<String, AppError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use qrcode::{QrCode, render::svg};

    let qr_code = QrCode::new(provisioning_uri.as_bytes())
        .map_err(|_| AppError::Internal(anyhow::anyhow!("unable to encode TOTP QR code")))?;
    let svg = qr_code
        .render()
        .min_dimensions(256, 256)
        .dark_color(svg::Color("#0f172a"))
        .light_color(svg::Color("#ffffff"))
        .build();
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        STANDARD.encode(svg.as_bytes())
    ))
}

async fn totp_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TotpConfirmForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated_raw(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    let tokens = state.auth.confirm_totp(&session, &form.code).await?;
    let destination = if session.user.must_change_password {
        "/account/password"
    } else {
        "/dashboard"
    };
    let mut response = Redirect::to(destination).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        session_cookie(&state, &tokens.session_token)?,
    );
    Ok(response)
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    let (raw, session) = authenticated_raw(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    state.sessions.revoke(&raw, "logout").await?;
    sqlx::query(
        "INSERT INTO audit_logs(occurred_at, actor_user_id, action) VALUES(?, ?, 'LOGOUT')",
    )
    .bind(db::now_rfc3339().map_err(AppError::Internal)?)
    .bind(&session.user.id)
    .execute(&state.pool)
    .await?;
    let mut response = Redirect::to("/login").into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        expire_cookie(
            &state.settings.session.cookie_name,
            state.settings.session.secure_cookie,
        )?,
    );
    Ok(response)
}

async fn recent_auth_page(
    State(state): State<AppState>,
    Query(query): Query<RecentAuthQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (raw, session) = authenticated(&state, &headers).await?;
    session.require_full()?;
    let csrf = state
        .crypto
        .csrf_token(&raw)
        .map_err(|_| AppError::Crypto)?;
    state.sessions.verify_csrf(&session, &csrf)?;
    let return_to = safe_return_to(&query.return_to);
    Ok(Html(
        RecentAuthTemplate {
            csrf_token: &csrf,
            return_to: &return_to,
            high_impact: query.level == "high",
        }
        .render()?,
    )
    .into_response())
}

async fn recent_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RecentAuthForm>,
) -> Result<Response, AppError> {
    let (_, session) = authenticated(&state, &headers).await?;
    state.sessions.verify_csrf(&session, &form.csrf_token)?;
    let level = if form.level == "high" {
        PrivilegedAuthLevel::HighImpact
    } else {
        PrivilegedAuthLevel::Standard
    };
    let tokens = state
        .auth
        .recent_authenticate(
            &session,
            Zeroizing::new(form.password),
            form.totp_code.as_deref().filter(|value| !value.is_empty()),
            level,
        )
        .await?;
    let return_to = safe_return_to(&form.return_to);
    let mut response = Redirect::to(&return_to).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        session_cookie(&state, &tokens.session_token)?,
    );
    Ok(response)
}

fn safe_return_to(value: &str) -> String {
    let value = value.trim();
    let valid = !value.is_empty()
        && value.len() <= 2_048
        && value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains(['\r', '\n', '\\']);
    if valid {
        value.to_owned()
    } else {
        "/dashboard".to_owned()
    }
}

async fn authenticated(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, AuthenticatedSession), AppError> {
    let authenticated = authenticated_raw(state, headers).await?;
    if authenticated.1.authentication_state == crate::auth::AuthenticationState::Full
        && authenticated.1.user.must_change_password
    {
        return Err(AppError::PasswordChangeRequired);
    }
    if authenticated.1.authentication_state == crate::auth::AuthenticationState::Full
        && !organization::is_onboarding_complete(&state.pool, &authenticated.1).await?
    {
        return Err(AppError::OrganizationSetupRequired);
    }
    Ok(authenticated)
}

async fn authenticated_raw(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, AuthenticatedSession), AppError> {
    let raw =
        cookie_value(headers, &state.settings.session.cookie_name).ok_or(AppError::Unauthorized)?;
    let session = state.sessions.load(&raw).await?;
    Ok((raw, session))
}

async fn authenticated_full_with_csrf(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, AuthenticatedSession, String), AppError> {
    let (raw, session) = authenticated(state, headers).await?;
    session.require_full()?;
    if !organization::is_onboarding_complete(&state.pool, &session).await? {
        return Err(AppError::OrganizationSetupRequired);
    }
    let csrf = state
        .crypto
        .csrf_token(&raw)
        .map_err(|_| AppError::Crypto)?;
    state.sessions.verify_csrf(&session, &csrf)?;
    Ok((raw, session, csrf))
}

fn app_chrome<'a>(
    state: &AppState,
    session: &'a AuthenticatedSession,
    csrf_token: &'a str,
    active_nav: &'a str,
) -> AppChrome<'a> {
    AppChrome {
        csrf_token,
        active_nav,
        user_email: &session.user.email,
        user_role: session.user.role.as_str(),
        section_label: match active_nav {
            "overview" => "Overview",
            "configurations" => "Configurations",
            "changes" => "Changes",
            "users" => "Users & Access",
            "audit" => "Audit log",
            "maintenance" => "Maintenance",
            _ => "Workspace",
        },
        recent_active: state
            .sessions
            .has_recent_auth(session, PrivilegedAuthLevel::Standard),
        permissions: AppPermissions {
            can_manage_users: session.user.role.allows(Capability::ManageUsers),
            can_view_audit: session.user.role.allows(Capability::ViewAudit),
            can_manage_system: session.user.role.allows(Capability::ManageSystem),
        },
    }
}

fn require_recent_import(state: &AppState, session: &AuthenticatedSession) -> Result<(), AppError> {
    if session
        .user
        .role
        .allows(crate::users::Capability::ApplyRequest)
        && state
            .sessions
            .has_recent_auth(session, PrivilegedAuthLevel::Standard)
    {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

async fn friendly_error_pages(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    let status = response.status();
    let json_error = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if path.starts_with("/api/")
        || !status.is_client_error() && !status.is_server_error()
        || !json_error
    {
        return response;
    }
    let (title, message) = friendly_error_copy(status, &path);
    let (back_href, back_label) = if status == StatusCode::UNAUTHORIZED || path == "/login" {
        ("/login", "Back to sign in")
    } else {
        ("/dashboard", "Back to overview")
    };
    let Ok(html) = (ErrorPageTemplate {
        code: status.as_u16(),
        title,
        message,
        back_href,
        back_label,
    })
    .render() else {
        return response;
    };
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().remove(header::CONTENT_LENGTH);
    *response.body_mut() = Body::from(html);
    response
}

fn friendly_error_copy(status: StatusCode, path: &str) -> (&'static str, &'static str) {
    if status == StatusCode::BAD_REQUEST && path == "/login" {
        return (
            "Sign-in unsuccessful",
            "Check your email, password, and six-digit authenticator code, then try again.",
        );
    }
    match status {
        StatusCode::BAD_REQUEST => (
            "We couldn't process that",
            "Review the highlighted action and check that every required field uses the expected format.",
        ),
        StatusCode::UNAUTHORIZED => (
            "Sign in required",
            "Your session may have expired. Sign in again to continue safely.",
        ),
        StatusCode::FORBIDDEN => (
            "Action unavailable",
            "Your account does not have permission for this action, or additional identity confirmation is required.",
        ),
        StatusCode::NOT_FOUND => (
            "Page not found",
            "The item may have been removed, archived, or is outside your assigned access.",
        ),
        StatusCode::CONFLICT => (
            "Changes could not be saved",
            "Another item already uses this name or the underlying state changed. Refresh and try again.",
        ),
        StatusCode::TOO_MANY_REQUESTS => (
            "Please wait a moment",
            "Too many attempts were received. Wait briefly before trying again.",
        ),
        _ => (
            "Something went wrong",
            "ConfigDeck could not complete this action. No sensitive details were exposed; try again or check the application logs.",
        ),
    }
}

async fn request_context(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let request_id = Uuid::new_v4().to_string();
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0.ip());
    let forwarded = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());
    let client_ip = resolve_client_ip(peer, forwarded, &state.settings.trusted_proxies)
        .map_or_else(|| "unknown".to_owned(), |ip| ip.to_string());
    request
        .extensions_mut()
        .insert(ClientIdentity(client_ip.clone()));
    let mut response = next.run(request).await;
    let status = response.status();
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    tracing::info!(
        request_id,
        method = %method,
        path,
        status = status.as_u16(),
        duration_ms = started.elapsed().as_millis(),
        client_ip,
        "request completed"
    );
    response
}

async fn security_headers(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let static_asset = request.uri().path().starts_with("/static/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if state.settings.environment.is_production() {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    if !static_asset {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert("pragma", HeaderValue::from_static("no-cache"));
    }
    response
}

fn resolve_client_ip(
    peer: Option<IpAddr>,
    forwarded_for: Option<&str>,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr> {
    let peer = peer?;
    if !trusted_proxies
        .iter()
        .any(|network| network.contains(&peer))
    {
        return Some(peer);
    }
    let Some(forwarded) = forwarded_for else {
        return Some(peer);
    };
    let parsed: Option<Vec<IpAddr>> = forwarded
        .split(',')
        .map(|value| value.trim().parse().ok())
        .collect();
    let Some(chain) = parsed else {
        return Some(peer);
    };
    chain
        .iter()
        .rev()
        .copied()
        .find(|ip| !trusted_proxies.iter().any(|network| network.contains(ip)))
        .or_else(|| chain.first().copied())
        .or(Some(peer))
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_owned()))
}

fn login_csrf_cookie_name(state: &AppState) -> String {
    if state.settings.session.secure_cookie {
        "__Host-configdeck_login_csrf".to_owned()
    } else {
        "configdeck_login_csrf".to_owned()
    }
}

fn session_cookie(state: &AppState, token: &str) -> Result<HeaderValue, AppError> {
    cookie_header(
        &state.settings.session.cookie_name,
        token,
        state.settings.session.secure_cookie,
        state.settings.session.absolute_timeout.whole_seconds(),
    )
}

fn cookie_header(
    name: &str,
    value: &str,
    secure: bool,
    max_age: i64,
) -> Result<HeaderValue, AppError> {
    let secure_attribute = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure_attribute}"
    ))
    .map_err(|_| AppError::Internal(anyhow::anyhow!("unable to construct cookie")))
}

fn expire_cookie(name: &str, secure: bool) -> Result<HeaderValue, AppError> {
    cookie_header(name, "", secure, 0)
}

fn random_web_token() -> Result<String, AppError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut token = [0_u8; 32];
    getrandom::fill(&mut token).map_err(|_| AppError::Crypto)?;
    Ok(URL_SAFE_NO_PAD.encode(token))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
        time::Duration as StdDuration,
    };

    use askama::Template as _;
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use ipnet::IpNet;
    use time::Duration;
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    use crate::{
        AppState,
        auth::{
            AuthService, AuthenticatedSession, AuthenticationState, PasswordService,
            SessionManager, SessionUser,
        },
        config::{
            BootstrapSettings, DatabaseSettings, Environment, OperationsSettings, SessionSettings,
            Settings,
        },
        crypto::CryptoManager,
        db::{initialize_and_validate_key_registry, test_pool},
        environments::{self, EnvironmentInput},
        services::{self, ServiceInput},
        users::Role,
        variables::{self, AppliedVariableInput},
    };

    use super::{
        AppChrome, AppPermissions, ImportPreviewEntry, ImportPreviewTemplate,
        RequestImportPreviewEntry, RequestImportPreviewTemplate, TotpSetupTemplate,
        resolve_client_ip, router, safe_return_to, totp_qr_code_data_uri,
    };

    #[test]
    fn recent_auth_return_target_accepts_only_local_paths() {
        assert_eq!(
            safe_return_to("/environments/env/export"),
            "/environments/env/export"
        );
        for unsafe_target in [
            "",
            "https://evil.example",
            "//evil.example/path",
            "/safe\\redirect",
            "/safe\r\nlocation:https://evil.example",
        ] {
            assert_eq!(safe_return_to(unsafe_target), "/dashboard");
        }
    }

    #[test]
    fn builds_totp_qr_code_as_an_inline_svg_data_uri() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let provisioning_uri = "otpauth://totp/ConfigDeck%3Aadmin%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=ConfigDeck&algorithm=SHA1&digits=6&period=30";
        let data_uri = totp_qr_code_data_uri(provisioning_uri).unwrap();
        let encoded_svg = data_uri.strip_prefix("data:image/svg+xml;base64,").unwrap();
        let svg = STANDARD.decode(encoded_svg).unwrap();
        let svg = String::from_utf8(svg).unwrap();

        assert!(svg.contains("<svg"));
        assert!(svg.contains("xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(!svg.contains("<image"));
        assert!(!svg.contains("<script"));
        assert!(!svg.contains("href="));
        assert!(!svg.contains(provisioning_uri));

        let html = TotpSetupTemplate {
            encoded_secret: "JBSWY3DPEHPK3PXP",
            provisioning_uri,
            qr_code_data_uri: &data_uri,
            csrf_token: "test-csrf-token",
        }
        .render()
        .unwrap();
        assert!(html.contains("QR code for ConfigDeck TOTP enrollment"));
        assert!(html.contains(&data_uri));
    }

    #[test]
    fn import_preview_omits_values_and_only_embeds_encrypted_token() {
        let environment = variables::EnvironmentContext {
            id: "env".into(),
            name: "staging".into(),
            service_id: "service".into(),
            service_name: "Payments".into(),
            archived_at: None,
            service_archived_at: None,
        };
        let entries = vec![ImportPreviewEntry {
            key: "DATABASE_URL".into(),
            group_name: Some("Database".into()),
            description: Some("Primary connection string".into()),
            starts_group: true,
            suggested_type: "string",
        }];
        let html = ImportPreviewTemplate {
            chrome: AppChrome {
                csrf_token: "csrf",
                active_nav: "configurations",
                section_label: "Configurations",
                user_email: "operator@example.test",
                user_role: "OPERATOR",
                recent_active: true,
                permissions: AppPermissions {
                    can_manage_users: false,
                    can_view_audit: true,
                    can_manage_system: false,
                },
            },
            environment: &environment,
            preview_token: "authenticated-ciphertext-token",
            entries: &entries,
        }
        .render()
        .unwrap();
        assert!(html.contains("DATABASE_URL"));
        assert!(html.contains("Database"));
        assert!(html.contains("Primary connection string"));
        assert!(html.contains("Values remain encrypted"));
        assert!(html.contains("authenticated-ciphertext-token"));
        assert!(html.contains("Suggested: string"));
        assert!(html.contains("value=\"string\" selected"));
        assert!(!html.contains("postgres://"));
    }

    #[test]
    fn request_import_preview_omits_values_and_labels_updates() {
        let environment = variables::EnvironmentContext {
            id: "env".into(),
            name: "staging".into(),
            service_id: "service".into(),
            service_name: "Payments".into(),
            archived_at: None,
            service_archived_at: None,
        };
        let entries = vec![RequestImportPreviewEntry {
            action: "UPDATE".into(),
            key: "DATABASE_URL".into(),
            group_name: Some("Database".into()),
            description: Some("Primary connection string".into()),
            starts_group: true,
            suggested_type: "string",
        }];
        let html = RequestImportPreviewTemplate {
            chrome: AppChrome {
                csrf_token: "csrf",
                active_nav: "changes",
                section_label: "Changes",
                user_email: "contributor@example.test",
                user_role: "CONTRIBUTOR",
                recent_active: false,
                permissions: AppPermissions {
                    can_manage_users: false,
                    can_view_audit: false,
                    can_manage_system: false,
                },
            },
            environment: &environment,
            preview_token: "authenticated-ciphertext-token",
            entries: &entries,
            requires_reason: true,
        }
        .render()
        .unwrap();
        assert!(html.contains("DATABASE_URL"));
        assert!(html.contains("UPDATE"));
        assert!(html.contains("Change reason"));
        assert!(html.contains("authenticated-ciphertext-token"));
        assert!(!html.contains("postgres://"));
    }

    #[test]
    fn ignores_forwarded_header_from_untrusted_peer() {
        let peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let result = resolve_client_ip(Some(peer), Some("198.51.100.2"), &[]);
        assert_eq!(result, Some(peer));
    }

    #[test]
    fn uses_rightmost_untrusted_address_from_trusted_proxy_chain() {
        let trusted: IpNet = "10.0.0.0/8".parse().unwrap();
        let peer = "10.0.0.2".parse().unwrap();
        let result = resolve_client_ip(Some(peer), Some("198.51.100.4, 10.0.0.1"), &[trusted]);
        assert_eq!(result, Some("198.51.100.4".parse().unwrap()));
    }

    #[test]
    fn malformed_forwarded_chain_falls_back_to_peer() {
        let trusted: IpNet = "10.0.0.0/8".parse().unwrap();
        let peer = "10.0.0.2".parse().unwrap();
        let result = resolve_client_ip(Some(peer), Some("not-an-ip"), &[trusted]);
        assert_eq!(result, Some(peer));
    }

    #[tokio::test]
    async fn health_response_has_security_and_request_id_headers() {
        let state = response_state().await;
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert!(response.headers().contains_key("content-security-policy"));
        assert!(response.headers().contains_key("strict-transport-security"));
        assert!(response.headers().contains_key("x-request-id"));
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");

        let login = router(state)
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookie = login.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.starts_with("__Host-configdeck_login_csrf="));
    }

    #[tokio::test]
    async fn browser_errors_are_html_while_api_errors_remain_json() {
        let state = response_state().await;
        let browser_error = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "email=user%40example.test&password=wrong&csrf_token=missing-cookie",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(browser_error.status(), StatusCode::FORBIDDEN);
        assert!(
            browser_error
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let html = axum::body::to_bytes(browser_error.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert!(
            String::from_utf8(html.to_vec())
                .unwrap()
                .contains("Action unavailable")
        );

        let api_error = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/services")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(api_error.status(), StatusCode::UNAUTHORIZED);
        assert!(
            api_error
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("application/json")
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn contributor_api_response_never_contains_restricted_plaintext() {
        let state = response_state().await;
        seed_registry_identities(&state.pool).await;
        initialize_and_validate_key_registry(&state.pool, &state.crypto)
            .await
            .unwrap();
        let admin = test_session("admin", Role::Administrator);
        let operator = test_session("operator", Role::Operator);
        let service_id = services::create(
            &state.pool,
            &admin,
            ServiceInput {
                name: "Payments".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        let environment_id = environments::create(
            &state.pool,
            &state.crypto,
            &admin,
            &service_id,
            EnvironmentInput {
                name: "staging".into(),
                description: None,
            },
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_service_access(user_id, service_id, granted_at, granted_by) \
             VALUES('contributor', ?, '2026-08-14T00:00:00Z', 'admin')",
        )
        .bind(&service_id)
        .execute(&state.pool)
        .await
        .unwrap();
        for (key, value, visibility) in [
            ("API_URL", "https://staging.example.test", "public"),
            (
                "DATABASE_URL",
                "postgres://user:do-not-leak@example.test/db",
                "restricted",
            ),
        ] {
            variables::record_applied(
                &state.pool,
                &state.crypto,
                &operator,
                &environment_id,
                AppliedVariableInput {
                    key: key.into(),
                    value: value.into(),
                    visibility: visibility.into(),
                    value_type: if key == "API_URL" { "url" } else { "string" }.into(),
                    description: None,
                    group_name: None,
                    display_order: 0,
                    reason: "Confirmed applied".into(),
                },
            )
            .await
            .unwrap();
        }
        let contributor = SessionUser {
            id: "contributor".into(),
            organization_id: "org".into(),
            email: "contributor@example.test".into(),
            role: Role::Contributor,
            auth_version: 1,
            totp_enabled: false,
            must_change_password: false,
        };
        let tokens = state
            .sessions
            .create(
                &contributor,
                AuthenticationState::Full,
                Some("127.0.0.1"),
                Some("test"),
            )
            .await
            .unwrap();
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/api/environments/{environment_id}/variables"))
                    .header(
                        "cookie",
                        format!("__Host-configdeck_session={}", tokens.session_token),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("https://staging.example.test"));
        assert!(body.contains("\"key\":\"DATABASE_URL\",\"value\":null"));
        assert!(!body.contains("do-not-leak"));

        let export = router(state.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/api/environments/{environment_id}/export"))
                    .header(
                        "cookie",
                        format!("__Host-configdeck_session={}", tokens.session_token),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(export.status(), StatusCode::FORBIDDEN);
        let export_body = axum::body::to_bytes(export.into_body(), 4096)
            .await
            .unwrap();
        assert!(
            !String::from_utf8(export_body.to_vec())
                .unwrap()
                .contains("do-not-leak")
        );

        let reveal_get = router(state)
            .oneshot(
                Request::builder()
                    .uri("/variables/missing/reveal")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reveal_get.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn incomplete_onboarding_blocks_normal_application_routes() {
        let state = response_state().await;
        seed_registry_identities(&state.pool).await;
        sqlx::query("UPDATE organizations SET onboarding_completed_at = NULL WHERE id = 'org'")
            .execute(&state.pool)
            .await
            .unwrap();
        let tokens = state
            .sessions
            .create(
                &test_session("admin", Role::Administrator).user,
                AuthenticationState::Full,
                Some("127.0.0.1"),
                Some("test"),
            )
            .await
            .unwrap();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/services")
                    .header(
                        "cookie",
                        format!("__Host-configdeck_session={}", tokens.session_token),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "/setup/organization"
        );
    }

    #[tokio::test]
    async fn initial_password_blocks_dashboard_until_changed() {
        let state = response_state().await;
        seed_registry_identities(&state.pool).await;
        sqlx::query("UPDATE users SET must_change_password = 1 WHERE id = 'admin'")
            .execute(&state.pool)
            .await
            .unwrap();
        let mut admin = test_session("admin", Role::Administrator).user;
        admin.must_change_password = true;
        let tokens = state
            .sessions
            .create(
                &admin,
                AuthenticationState::Full,
                Some("127.0.0.1"),
                Some("test"),
            )
            .await
            .unwrap();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/dashboard")
                    .header(
                        "cookie",
                        format!("__Host-configdeck_session={}", tokens.session_token),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "/account/password"
        );
    }

    #[tokio::test]
    async fn user_admin_action_redirects_to_just_in_time_reauthentication() {
        let state = response_state().await;
        seed_registry_identities(&state.pool).await;
        let tokens = state
            .sessions
            .create(
                &test_session("admin", Role::Administrator).user,
                AuthenticationState::Full,
                Some("127.0.0.1"),
                Some("test"),
            )
            .await
            .unwrap();
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/users/operator/role")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(
                        "cookie",
                        format!("__Host-configdeck_session={}", tokens.session_token),
                    )
                    .body(Body::from(format!(
                        "csrf_token={}&role=CONTRIBUTOR",
                        tokens.csrf_token
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "/auth/recent?return_to=/users"
        );
        let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = 'operator'")
            .fetch_one(&state.pool)
            .await
            .unwrap();
        assert_eq!(role, "OPERATOR");
    }

    #[tokio::test]
    async fn operator_is_denied_backup_before_recent_auth_redirect() {
        let state = response_state().await;
        seed_registry_identities(&state.pool).await;
        let tokens = state
            .sessions
            .create(
                &test_session("operator", Role::Operator).user,
                AuthenticationState::Full,
                Some("127.0.0.1"),
                Some("test"),
            )
            .await
            .unwrap();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/maintenance/backups")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(
                        "cookie",
                        format!("__Host-configdeck_session={}", tokens.session_token),
                    )
                    .body(Body::from(format!("csrf_token={}", tokens.csrf_token)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get("location").is_none());
    }

    async fn response_state() -> AppState {
        let pool = test_pool().await;
        let crypto = CryptoManager::new(Zeroizing::new([13; 32]));
        crate::db::initialize_and_validate_key_registry(&pool, &crypto)
            .await
            .unwrap();
        let session_settings = SessionSettings {
            cookie_name: "__Host-configdeck_session".into(),
            secure_cookie: true,
            idle_timeout: Duration::minutes(30),
            absolute_timeout: Duration::hours(12),
            recent_auth_timeout: Duration::minutes(5),
        };
        let passwords = PasswordService::for_tests();
        let sessions = SessionManager::new(pool.clone(), crypto.clone(), session_settings.clone());
        let auth = AuthService::new(
            pool.clone(),
            crypto.clone(),
            passwords.clone(),
            sessions.clone(),
        )
        .await
        .unwrap();
        AppState {
            settings: Arc::new(Settings {
                environment: Environment::Production,
                bind_address: "127.0.0.1:3000".parse().unwrap(),
                database: DatabaseSettings {
                    url: "sqlite::memory:".into(),
                    max_connections: 1,
                    busy_timeout: StdDuration::from_secs(1),
                },
                master_key: Some(Zeroizing::new([13; 32])),
                previous_master_key: None,
                session: session_settings,
                operations: OperationsSettings {
                    backup_dir: "/backup".into(),
                    restore_intent_path: "/data/restore-intent.json".into(),
                },
                trusted_proxies: vec![],
                bootstrap: BootstrapSettings::default(),
            }),
            pool,
            crypto,
            passwords,
            sessions,
            auth,
            readiness: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    fn test_session(id: &str, role: Role) -> AuthenticatedSession {
        AuthenticatedSession {
            id: format!("session-{id}"),
            token_hash: vec![1; 32],
            csrf_token_hash: vec![2; 32],
            user: SessionUser {
                id: id.into(),
                organization_id: "org".into(),
                email: format!("{id}@example.test"),
                role,
                auth_version: 1,
                totp_enabled: role.requires_totp(),
                must_change_password: false,
            },
            authentication_state: AuthenticationState::Full,
            privileged_authenticated_at: None,
            privileged_auth_level: None,
        }
    }

    async fn seed_registry_identities(pool: &sqlx::SqlitePool) {
        let now = "2026-08-14T00:00:00Z";
        sqlx::query(
            "INSERT INTO organizations(id, name, onboarding_completed_at, created_at, updated_at) \
             VALUES('org', 'ConfigDeck', ?, ?, ?)",
        )
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await
        .unwrap();
        for (id, email, role) in [
            ("admin", "admin@example.test", "ADMINISTRATOR"),
            ("operator", "operator@example.test", "OPERATOR"),
            ("contributor", "contributor@example.test", "CONTRIBUTOR"),
        ] {
            sqlx::query(
                "INSERT INTO users(\
                    id, organization_id, email, email_normalized, password_hash, role, \
                    password_changed_at, created_at, updated_at\
                 ) VALUES(?, 'org', ?, ?, 'hash', ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(email)
            .bind(email)
            .bind(role)
            .bind(now)
            .bind(now)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
        }
    }
}
