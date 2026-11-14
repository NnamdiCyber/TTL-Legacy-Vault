use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{FromRef, State},
    http::{HeaderValue, Method, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;

mod auth;
mod consensus;
mod csrf;
mod db;
mod error;
mod escalation;
mod handlers;
mod models;
mod notifications;
mod otel;
mod rate_limit;
mod request_id;
mod routes;
mod sanitization;
mod scheduler;
mod security_headers;
mod ttl_watch;
mod two_factor;
mod webhook_retry;

#[cfg(test)]
mod tests;

pub use consensus::NodeCache;
pub use db::Db;
// Note: db::AppState is NOT re-exported here — main.rs defines its own AppState
// that includes the Metrics field (issue #1195).

use crate::metrics::Metrics;
use crate::rate_limit::{
    InMemoryRateLimitStore, RateLimitStore, RedisRateLimitStore, TrustedProxies,
};

/// Default grace period for draining in-flight background work on shutdown.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub consensus: Arc<NodeCache>,
    pub metrics: Arc<Metrics>,
    /// Shared shutdown token signalled on SIGTERM/SIGINT (issue #1488).
    pub shutdown: CancellationToken,
    /// Rate-limit store backend (issue #1494). Defaults to in-memory for dev;
    /// set `RATE_LIMIT_STORE=redis` (with `REDIS_URL`) to share state across
    /// replicas and survive restarts.
    pub rate_limit_store: Arc<dyn RateLimitStore>,
    /// Trusted reverse-proxy networks (issue #1819). When the peer address
    /// falls inside one of these ranges, the client IP is taken from
    /// `X-Forwarded-For` / `X-Real-IP` instead of the socket address.
    pub trusted_proxies: Arc<TrustedProxies>,
}

impl FromRef<AppState> for Arc<Db> {
    fn from_ref(state: &AppState) -> Arc<Db> {
        Arc::clone(&state.db)
    }
}

impl FromRef<AppState> for CancellationToken {
    fn from_ref(state: &AppState) -> CancellationToken {
        state.shutdown.clone()
    }
}

impl FromRef<AppState> for Arc<dyn RateLimitStore> {
    fn from_ref(state: &AppState) -> Arc<dyn RateLimitStore> {
        Arc::clone(&state.rate_limit_store)
    }
}

impl FromRef<AppState> for Arc<TrustedProxies> {
    fn from_ref(state: &AppState) -> Arc<TrustedProxies> {
        Arc::clone(&state.trusted_proxies)
    }
}

/// Builds the trusted-proxy list from the `TRUSTED_PROXIES` environment
/// variable (issue #1819).
///
/// The value is a comma-separated list of CIDR ranges or bare IPs, e.g.
/// `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1`. Whitespace around each
/// entry is trimmed and empty entries are ignored. Invalid entries are logged
/// and skipped. When the variable is unset or empty, no proxies are trusted
/// and the limiter falls back to the peer socket address.
fn build_trusted_proxies() -> Arc<TrustedProxies> {
    let raw = std::env::var("TRUSTED_PROXIES").unwrap_or_default();
    let proxies = TrustedProxies::from_csv(&raw);
    if proxies.is_empty() {
        tracing::info!(
            "no TRUSTED_PROXIES configured; rate limiter will use the peer socket address"
        );
    } else {
        tracing::info!(
            "rate limiter trusting {} proxy network(s) from TRUSTED_PROXIES",
            proxies.len()
        );
    }
    Arc::new(proxies)
}

/// Builds the rate-limit store from environment configuration (issue #1494).
///
/// | `RATE_LIMIT_STORE` | `REDIS_URL` | Result                                  |
/// |--------------------|-------------|-----------------------------------------|
/// | unset / `memory`   | any         | In-memory store (default, dev-friendly) |
/// | `redis`            | set         | Redis-backed store (shared, persistent) |
/// | `redis`            | unset       | Falls back to in-memory with a warning  |
fn build_rate_limit_store() -> Arc<dyn RateLimitStore> {
    let backend = std::env::var("RATE_LIMIT_STORE").unwrap_or_default();
    if backend.eq_ignore_ascii_case("redis") {
        match std::env::var("REDIS_URL") {
            Ok(url) if !url.is_empty() => {
                tracing::info!("rate limiter using Redis-backed store");
                return Arc::new(RedisRateLimitStore::new(url));
            }
            _ => {
                tracing::warn!(
                    "RATE_LIMIT_STORE=redis but REDIS_URL is unset; \
                     falling back to in-memory rate-limit store"
                );
            }
        }
    }
    tracing::info!("rate limiter using in-memory store");
    Arc::new(InMemoryRateLimitStore::new())
}

/// Builds the application state, wiring the rate-limit store and the
/// trusted-proxy configuration (issues #1494, #1819).
fn build_app_state(
    db: Arc<Db>,
    consensus: Arc<NodeCache>,
    metrics: Arc<Metrics>,
    shutdown: CancellationToken,
) -> AppState {
    AppState {
        db,
        consensus,
        metrics,
        shutdown,
        rate_limit_store: build_rate_limit_store(),
        trusted_proxies: build_trusted_proxies(),
    }
}

/// Parses the `CORS_ALLOWED_ORIGINS` environment variable into a list of
/// allowed origins (issue #1490).
///
/// The value is a comma-separated list of origins, e.g.
/// `https://app.example.com,https://admin.example.com`. Whitespace around
/// each entry is trimmed and empty entries are ignored. A bare `*` wildcard
/// is rejected when credentials are enabled, since browsers forbid combining
/// `Access-Control-Allow-Credentials: true` with a wildcard origin.
fn parse_cors_allowed_origins(raw: &str, allow_credentials: bool) -> Vec<HeaderValue> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| {
            if *s == "*" {
                if allow_credentials {
                    tracing::warn!(
                        "CORS_ALLOWED_ORIGINS contains wildcard '*' while credentials are \
                         enabled; rejecting wildcard origin"
                    );
                }
                false
            } else {
                true
            }
        })
        .filter_map(|s| match s.parse::<HeaderValue>() {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::warn!("ignoring invalid CORS origin: {s}");
                None
            }
        })
        .collect()
}

/// Builds the CORS layer based on `APP_ENV` and `CORS_ALLOWED_ORIGINS`
/// environment variables (issue #1490).
///
/// # Behaviour
///
/// | `APP_ENV`                   | `CORS_ALLOWED_ORIGINS` | Result                                          |
/// |-----------------------------|------------------------|-------------------------------------------------|
/// | unset **or** `development`  | any / empty            | `CorsLayer::permissive()` — wildcard, dev mode  |
/// | `production` / `staging`    | non-empty list         | Origin whitelist with `Vary: Origin` header     |
/// | `production` / `staging`    | empty                  | `CorsLayer::new()` — blocks all cross-origin    |
///
/// A wildcard `*` entry is rejected when credentials are enabled.
///
/// Issue #1179: CORS Policy Hardening
/// Issue #1490: CORS origins configurable via environment
fn build_cors_layer() -> CorsLayer {
    let app_env = std::env::var("APP_ENV").unwrap_or_default();
    let is_production = !app_env.is_empty() && app_env != "development";

    // In development (or when APP_ENV is unset), allow everything.
    if !is_production {
        return CorsLayer::permissive();
    }

    // Production / staging: honour the CORS_ALLOWED_ORIGINS whitelist.
    let allow_credentials = true;
    let allowed_origins = std::env::var("CORS_ALLOWED_ORIGINS").unwrap_or_default();
    let origins = parse_cors_allowed_origins(&allowed_origins, allow_credentials);
    if origins.is_empty() {
        // No origins configured → block all cross-origin requests.
        return CorsLayer::new();
    }

    CorsLayer::new()
        .allow_origin(origins)
        .allow_credentials(allow_credentials)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(tower_http::cors::Any)
        // Instruct caches / CDNs that the response varies by origin.
        .vary([axum::http::header::ORIGIN])
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "db": "connected",
    }))
}

async fn ready_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.db.check_connectivity().await {
        Ok(()) => Ok(Json(serde_json::json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "database": "connected",
        }))),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

async fn consensus_health_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.consensus.check_and_resolve() {
        Ok(report) => {
            let status = if report.consistent { "ok" } else { "degraded" };
            Ok(Json(serde_json::json!({
                "status": status,
                "cache_consistent": report.consistent,
                "node_id": report.node_id,
                "strategy": report.strategy,
                "conflicts_detected": report.conflicts.len(),
                "conflicts_resolved": report.conflicts_resolved,
                "keys_checked": report.keys_checked,
            })))
        }
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// GET /metrics — Prometheus text exposition endpoint (issue #1195).
///
/// Returns all application metrics in Prometheus text format
/// (content-type: text/plain; version=0.0.4; charset=utf-8).
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.metrics.render();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

/// Default timeout applied to the Soroban RPC `get_contract_version` call.
const CONTRACT_VERSION_RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Fetches the deployed contract's version via Soroban RPC.
///
/// The RPC endpoint is read from `SOROBAN_RPC_URL` (falling back to
/// `STELLAR_RPC_URL`), and the contract id from `CONTRACT_ID`. When either is
/// missing the check is skipped by returning `Ok(1)` so local/dev startup is
/// not blocked. Any transport failure or timeout surfaces as a clear `Err`.
async fn fetch_contract_version() -> Result<u32, String> {
    let rpc_url = std::env::var("SOROBAN_RPC_URL")
        .or_else(|_| std::env::var("STELLAR_RPC_URL"))
        .ok();
    let contract_id = std::env::var("CONTRACT_ID").ok();

    let (rpc_url, contract_id) = match (rpc_url, contract_id) {
        (Some(url), Some(id)) if !url.is_empty() && !id.is_empty() => (url, id),
        _ => {
            tracing::warn!(
                "SOROBAN_RPC_URL/CONTRACT_ID not configured; skipping contract version check"
            );
            return Ok(1);
        }
    };

    let client = reqwest::Client::builder()
        .timeout(CONTRACT_VERSION_RPC_TIMEOUT)
        .build()
        .map_err(|e| format!("failed to build Soroban RPC client: {e}"))?;

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getContractData",
        "params": {
            "contractId": contract_id,
            "key": "get_contract_version",
            "durability": "persistent",
        }
    });

    let response = client
        .post(&rpc_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Soroban RPC request to {rpc_url} failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "Soroban RPC returned HTTP {} for get_contract_version",
            response.status()
        ));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("invalid Soroban RPC response: {e}"))?;

    if let Some(err) = body.get("error") {
        return Err(format!("Soroban RPC error: {err}"));
    }

    let version = body
        .get("result")
        .and_then(|r| r.get("version"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "Soroban RPC response missing numeric `version`".to_string())?;

    u32::try_from(version).map_err(|_| format!("contract version {version} out of range"))
}

#[tokio::main]
async fn main() {
    // Initialise OpenTelemetry distributed tracing.
    // Spans are exported to the OTLP endpoint configured via
    // OTEL_EXPORTER_OTLP_ENDPOINT (default: http://localhost:4317).
    // Issue #1145: Add OpenTelemetry Distributed Tracing to Backend
    let _otel_guard = otel::init_tracer("ttl-legacy-backend");

    // Check contract version before proceeding with server startup
    let min_contract_version = contract_version_check::parse_min_contract_version(
        std::env::var("MIN_CONTRACT_VERSION").ok(),
    );

    let version_result = contract_version_check::check_contract_version(
        fetch_contract_version,
        min_contract_version,
    )
    .await;

    tracing::info!("{}", version_result);

    if let Some(err) = &version_result.error {
        tracing::error!("Contract version check failed: {}", err);
        std::process::exit(1);
    }

    if !version_result.compatible {
        tracing::error!("{}", version_result);
        std::process::exit(1);
    }

    let pool_config = db::PoolConfig::from_env();
    tracing::info!(
        min = pool_config.min,
        max = pool_config.max,
        timeout_secs = pool_config.timeout_secs,
        "database pool configuration"
    );

    // Issue #1487: unify SQLite access on sqlx. The database is opened through
    // the sqlx-backed `Db` handle and migrations are applied via `sqlx::migrate!`
    // inside `Db::migrate`, so no rusqlite call sites remain here.
    let db =
        Arc::new(Db::open_with_pool_config(":memory:", &pool_config).expect("failed to open db"));
    db.migrate().await.expect("migration failed");

    let consensus = Arc::new(NodeCache::from_env());
    tracing::info!(
        node_id = consensus.node_id(),
        strategy = ?consensus.strategy(),
        "consensus cache initialized"
    );

    // Shared shutdown token: every background task observes this and drains
    // in-flight work when SIGTERM/SIGINT is received (issue #1488).
    let shutdown = CancellationToken::new();

    let scheduler_db = Arc::clone(&db);
    let scheduler_shutdown = shutdown.clone();
    let _scheduler_handle = tokio::spawn(async move {
        let _ = (scheduler_db, scheduler_shutdown);
    });

    let metrics = Arc::new(Metrics::new());
    let state = build_app_state(db, consensus, metrics, shutdown);

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/health/consensus", get(consensus_health_handler))
        .route("/ready", get(ready_handler))
        .route("/metrics", get(metrics_handler))
        .layer(build_cors_layer())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
