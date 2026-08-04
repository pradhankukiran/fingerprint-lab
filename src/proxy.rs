use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::StreamExt;
use http_body::Body as _;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use crate::sessions::{PersistentJar, SessionDb};
use crate::transport::{TransportOptions, wreq_proxy_client};

const SESSION_COOKIE: &str = "flab_session";
const SESSION_LIMIT: usize = 256;
const SESSION_IDLE_LIMIT: Duration = Duration::from_secs(1800);
const REQUEST_BODY_LIMIT: usize = 1024 * 1024;

#[derive(Clone)]
pub struct ProxyConfig {
    pub session_db: Option<PathBuf>,
    pub session_limit: usize,
    pub session_idle_limit: Duration,
    pub request_body_limit: usize,
    pub max_in_flight: usize,
    pub websocket_message_limit: usize,
    pub shutdown: CancellationToken,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            session_db: None,
            session_limit: SESSION_LIMIT,
            session_idle_limit: SESSION_IDLE_LIMIT,
            request_body_limit: REQUEST_BODY_LIMIT,
            max_in_flight: 64,
            websocket_message_limit: REQUEST_BODY_LIMIT,
            shutdown: CancellationToken::new(),
        }
    }
}

#[derive(Default)]
struct Metrics {
    requests: AtomicU64,
    active: AtomicU64,
    upstream_errors: AtomicU64,
    rejected: AtomicU64,
    uploaded: AtomicU64,
    downloaded: AtomicU64,
    session_errors: AtomicU64,
}

struct RequestGuard {
    metrics: Arc<Metrics>,
    _permit: OwnedSemaphorePermit,
}
impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.metrics.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
struct ProxyState {
    upstream: Url,
    options: TransportOptions,
    config: ProxyConfig,
    db: Arc<SessionDb>,
    scope: String,
    sessions: Arc<Mutex<HashMap<Uuid, Session>>>,
    concurrency: Arc<Semaphore>,
    metrics: Arc<Metrics>,
}

struct Session {
    client: wreq::Client,
    jar: Arc<PersistentJar>,
    touched: Instant,
}

struct SessionLease {
    client: wreq::Client,
    jar: Arc<PersistentJar>,
    cookie: Option<String>,
}

impl ProxyState {
    async fn session(&self, headers: &HeaderMap) -> Result<SessionLease> {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, session| session.touched.elapsed() < self.config.session_idle_limit);
        if let Some(id) =
            cookie_value(headers, SESSION_COOKIE).and_then(|value| Uuid::parse_str(value).ok())
            && let Some(session) = sessions.get_mut(&id)
        {
            let db = self.db.clone();
            let scope = self.scope.clone();
            tokio::task::spawn_blocking(move || db.touch(&scope, id)).await??;
            session.touched = Instant::now();
            return Ok(SessionLease {
                client: session.client.clone(),
                jar: session.jar.clone(),
                cookie: Some(session_cookie(id, self.config.session_idle_limit)),
            });
        }
        let requested =
            cookie_value(headers, SESSION_COOKIE).and_then(|value| Uuid::parse_str(value).ok());
        let db = self.db.clone();
        let scope = self.scope.clone();
        let lifetime = self.config.session_idle_limit;
        let capacity = self.config.session_limit;
        let (id, jar) = tokio::task::spawn_blocking(move || -> Result<_> {
            if let Some(id) = requested
                && let Some(jar) = db.load(&scope, id, lifetime)?
            {
                return Ok((id, jar));
            }
            let id = Uuid::new_v4();
            Ok((id, db.create(&scope, id, lifetime, capacity)?))
        })
        .await??;
        let client = wreq_proxy_client(&self.options, jar.clone())?;
        sessions.insert(
            id,
            Session {
                client: client.clone(),
                jar: jar.clone(),
                touched: Instant::now(),
            },
        );
        Ok(SessionLease {
            client,
            jar,
            cookie: Some(session_cookie(id, lifetime)),
        })
    }
}

/// A reverse proxy pinned to one upstream origin, with an isolated cookie jar per browser session.
pub fn router(upstream: Url, options: TransportOptions) -> Result<Router> {
    router_with_config(upstream, options, ProxyConfig::default())
}

pub fn router_with_config(
    upstream: Url,
    options: TransportOptions,
    config: ProxyConfig,
) -> Result<Router> {
    if !matches!(upstream.scheme(), "http" | "https")
        || !upstream.username().is_empty()
        || upstream.password().is_some()
        || upstream.fragment().is_some()
    {
        bail!("proxy upstream must be an HTTP/HTTPS origin without credentials or fragments");
    }
    if upstream.path() != "/" || upstream.query().is_some() {
        bail!(
            "proxy upstream must be an origin URL, such as https://example.com (no path or query)"
        );
    }
    // Validate transport configuration before opening the listener.
    if config.session_limit == 0
        || config.max_in_flight == 0
        || config.request_body_limit == 0
        || config.websocket_message_limit == 0
        || config.session_idle_limit.as_secs() == 0
    {
        bail!("proxy capacities and session lifetime must be positive");
    }
    if options.headers.contains_key(header::COOKIE) {
        bail!(
            "global Cookie overrides are not allowed in proxy mode; each session uses its own cookie jar"
        );
    }
    let _ = wreq_proxy_client(&options, Arc::new(wreq::cookie::Jar::default()))?;
    let db = match &config.session_db {
        Some(path) => SessionDb::open(path)?,
        None => SessionDb::in_memory()?,
    };
    let proxy_origin = options
        .network_proxy
        .as_deref()
        .map(crate::transport::validate_network_proxy)
        .transpose()?
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|| "direct".into());
    let scope = format!(
        "{}|{}|{}|{}",
        upstream.origin().ascii_serialization(),
        options.profile,
        options.platform,
        proxy_origin
    );
    let concurrency = Arc::new(Semaphore::new(config.max_in_flight));
    let state = ProxyState {
        upstream,
        options,
        config,
        db,
        scope,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        concurrency,
        metrics: Arc::new(Metrics::default()),
    };
    Ok(Router::new()
        .route("/_fingerprint-lab/health", get(health))
        .route("/_fingerprint-lab/metrics", get(metrics))
        .fallback(forward)
        .with_state(state))
}

async fn health(State(state): State<ProxyState>) -> Json<serde_json::Value> {
    Json(
        serde_json::json!({"service":"fingerprint-lab","version":env!("CARGO_PKG_VERSION"),"upstream":state.upstream.origin().ascii_serialization(),"persistent_sessions":state.config.session_db.is_some(),"active_requests":state.metrics.active.load(Ordering::Relaxed),"available_slots":state.concurrency.available_permits(),"shutting_down":state.config.shutdown.is_cancelled()}),
    )
}

async fn metrics(State(state): State<ProxyState>) -> Response {
    let m = &state.metrics;
    let values = [
        ("requests_total", m.requests.load(Ordering::Relaxed)),
        ("active_requests", m.active.load(Ordering::Relaxed)),
        (
            "upstream_errors_total",
            m.upstream_errors.load(Ordering::Relaxed),
        ),
        (
            "rejected_requests_total",
            m.rejected.load(Ordering::Relaxed),
        ),
        ("uploaded_bytes_total", m.uploaded.load(Ordering::Relaxed)),
        (
            "downloaded_bytes_total",
            m.downloaded.load(Ordering::Relaxed),
        ),
        (
            "session_errors_total",
            m.session_errors.load(Ordering::Relaxed),
        ),
    ];
    let text: String = values
        .into_iter()
        .map(|(name, value)| format!("fingerprint_lab_{name} {value}\n"))
        .collect();
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        text,
    )
        .into_response()
}

async fn forward(State(state): State<ProxyState>, request: Request<Body>) -> Response {
    let started = Instant::now();
    if state.config.shutdown.is_cancelled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "Proxy is shutting down").into_response();
    }
    state.metrics.requests.fetch_add(1, Ordering::Relaxed);
    let permit = match state.concurrency.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            state.metrics.rejected.fetch_add(1, Ordering::Relaxed);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, "1")],
                "Proxy concurrency limit reached",
            )
                .into_response();
        }
    };
    state.metrics.active.fetch_add(1, Ordering::Relaxed);
    let guard = RequestGuard {
        metrics: state.metrics.clone(),
        _permit: permit,
    };
    let (mut parts, body) = request.into_parts();
    if parts.uri.scheme().is_some() || parts.method == http::Method::CONNECT {
        return (
            StatusCode::BAD_REQUEST,
            "This is a reverse proxy. Request a path on the configured upstream.",
        )
            .into_response();
    }
    let target = target_url(&state.upstream, &parts.uri);
    if let Some(length) = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        && length > state.config.request_body_limit as u64
    {
        state.metrics.rejected.fetch_add(1, Ordering::Relaxed);
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "Request exceeds the configured body limit",
        )
            .into_response();
    }
    let session = match state.session(&parts.headers).await {
        Ok(session) => session,
        Err(error) => {
            state.metrics.session_errors.fetch_add(1, Ordering::Relaxed);
            tracing::error!(error = %error, "creating proxy session");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Unable to create upstream session",
            )
                .into_response();
        }
    };
    let websocket = parts
        .headers
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    if websocket {
        return forward_websocket(&state, session, target, guard, &mut parts).await;
    }
    let headers = outgoing_headers(&parts.headers, &state.upstream, false);
    let exceeded = Arc::new(AtomicBool::new(false));
    let has_body = !body.is_end_stream();
    let read_timeout = state.options.timeout;
    let maximum = state.config.request_body_limit;
    let m = state.metrics.clone();
    let exceeded_stream = exceeded.clone();
    let body = futures_util::stream::try_unfold(
        (body.into_data_stream(), 0usize),
        move |(mut stream, total)| {
            let m = m.clone();
            let exceeded = exceeded_stream.clone();
            async move {
                match tokio::time::timeout(read_timeout, stream.next()).await {
                    Ok(Some(Ok(chunk))) => {
                        if chunk.len() > maximum.saturating_sub(total) {
                            exceeded.store(true, Ordering::Relaxed);
                            return Err(std::io::Error::other("request body limit exceeded"));
                        }
                        m.uploaded.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                        let length = chunk.len();
                        Ok(Some((chunk, (stream, total + length))))
                    }
                    Ok(Some(Err(error))) => Err(std::io::Error::other(error)),
                    Ok(None) => Ok(None),
                    Err(_) => Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "request upload idle timeout",
                    )),
                }
            }
        },
    );
    let method = parts.method.clone();
    let request = session
        .client
        .request(parts.method, target.as_str())
        .headers(headers);
    let request = if has_body {
        request.body(wreq::Body::wrap_stream(body))
    } else {
        request
    };
    let result = tokio::select! {
        result=request.send()=>result,
        _=state.config.shutdown.cancelled()=>return (StatusCode::SERVICE_UNAVAILABLE,"Proxy is shutting down").into_response(),
    };
    let upstream = match result {
        Ok(response) => response,
        Err(error) => {
            if exceeded.load(Ordering::Relaxed) {
                state.metrics.rejected.fetch_add(1, Ordering::Relaxed);
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request exceeds the configured body limit",
                )
                    .into_response();
            }
            state
                .metrics
                .upstream_errors
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(error = %error.without_uri(), "upstream request failed");
            return (StatusCode::BAD_GATEWAY, "Upstream request failed").into_response();
        }
    };
    let status = upstream.status();
    let mut headers = response_headers(upstream.headers(), &target);
    add_session_cookie(&mut headers, session.cookie);
    mark_session_error(&state, &session.jar, &mut headers);
    let mut response = Response::new(if method == http::Method::HEAD {
        Body::empty()
    } else {
        stream_response(
            upstream,
            guard,
            state.metrics.clone(),
            state.config.shutdown.clone(),
        )
    });
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    tracing::info!(%method, status = status.as_u16(), elapsed_ms = started.elapsed().as_millis() as u64, "proxy response headers ready");
    response
}

fn mark_session_error(state: &ProxyState, jar: &PersistentJar, headers: &mut HeaderMap) {
    if jar.persistence_error().is_some() {
        state.metrics.session_errors.fetch_add(1, Ordering::Relaxed);
        headers.insert(
            "x-fingerprint-lab-session-storage",
            HeaderValue::from_static("error"),
        );
    }
}

fn stream_response(
    upstream: wreq::Response,
    guard: RequestGuard,
    metrics: Arc<Metrics>,
    shutdown: CancellationToken,
) -> Body {
    let stream = upstream.bytes_stream().boxed();
    Body::from_stream(futures_util::stream::unfold(
        Some((stream, guard, metrics, shutdown)),
        |state| async move {
            let (mut stream, guard, metrics, shutdown) = state?;
            let chunk = tokio::select! {
                chunk=stream.next()=>chunk,
                _=shutdown.cancelled()=>return Some((Err(std::io::Error::new(std::io::ErrorKind::Interrupted,"proxy is shutting down")),None)),
            };
            match chunk {
                Some(Ok(chunk)) => {
                    metrics
                        .downloaded
                        .fetch_add(chunk.len() as u64, Ordering::Relaxed);
                    Some((Ok(chunk), Some((stream, guard, metrics, shutdown))))
                }
                Some(Err(error)) => {
                    metrics.upstream_errors.fetch_add(1, Ordering::Relaxed);
                    Some((Err(std::io::Error::other(error.without_uri())), None))
                }
                None => None,
            }
        },
    ))
}

fn target_url(upstream: &Url, uri: &Uri) -> Url {
    // Setting fields on an existing URL prevents //other-host and absolute-path
    // inputs from changing the configured destination origin.
    let mut target = upstream.clone();
    target.set_path(uri.path());
    target.set_query(uri.query());
    target
}

fn connection_headers(headers: &HeaderMap) -> HashSet<String> {
    let mut excluded: HashSet<String> = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    for connection in headers.get_all(header::CONNECTION) {
        if let Ok(connection) = connection.to_str() {
            excluded.extend(
                connection
                    .split(',')
                    .map(|token| token.trim().to_ascii_lowercase()),
            );
        }
    }
    excluded
}

fn outgoing_headers(incoming: &HeaderMap, upstream: &Url, websocket: bool) -> HeaderMap {
    let mut excluded = connection_headers(incoming);
    excluded.extend(
        [
            "host",
            "content-length",
            "cookie",
            "user-agent",
            "sec-ch-ua",
            "sec-ch-ua-platform",
            "sec-ch-ua-mobile",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-protocol",
        ]
        .into_iter()
        .map(str::to_string),
    );
    let mut headers = HeaderMap::new();
    for (name, value) in incoming {
        if !excluded.contains(name.as_str()) {
            headers.append(name.clone(), value.clone());
        }
    }
    let local_host = incoming
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    for name in [header::ORIGIN, header::REFERER] {
        if let Some(value) = headers.get(&name).and_then(|value| value.to_str().ok())
            && let Ok(mut url) = Url::parse(value)
            && local_host == Some(&url[url::Position::BeforeHost..url::Position::AfterPort])
        {
            let original_path = url.path().to_owned();
            let original_query = url.query().map(str::to_owned);
            url = upstream.clone();
            if name == header::REFERER {
                url.set_path(&original_path);
                url.set_query(original_query.as_deref());
            }
            let rewritten = if name == header::ORIGIN {
                url.origin().ascii_serialization()
            } else {
                url.to_string()
            };
            if let Ok(value) = HeaderValue::from_str(&rewritten) {
                headers.insert(name, value);
            }
        }
    }
    if websocket {
        headers.remove(header::ACCEPT_ENCODING);
    }
    headers
}

fn response_headers(upstream_headers: &HeaderMap, upstream: &Url) -> HeaderMap {
    let mut excluded = connection_headers(upstream_headers);
    excluded.insert("set-cookie".into());
    let mut headers = HeaderMap::new();
    for (name, value) in upstream_headers {
        if !excluded.contains(name.as_str()) {
            headers.append(name.clone(), value.clone());
        }
    }
    if let Some(location) = headers
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        && let Ok(url) = upstream.join(location)
        && url.origin() == upstream.origin()
    {
        let mut local = url.path().to_owned();
        if let Some(query) = url.query() {
            local.push('?');
            local.push_str(query);
        }
        if let Some(fragment) = url.fragment() {
            local.push('#');
            local.push_str(fragment);
        }
        if let Ok(location) = HeaderValue::from_str(&local) {
            headers.insert(header::LOCATION, location);
        }
    }
    headers
}

fn add_session_cookie(headers: &mut HeaderMap, cookie: Option<String>) {
    if let Some(cookie) = cookie
        && let Ok(value) = HeaderValue::from_str(&cookie)
    {
        headers.append(header::SET_COOKIE, value);
    }
}

fn session_cookie(id: Uuid, lifetime: Duration) -> String {
    format!(
        "{SESSION_COOKIE}={id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        lifetime.as_secs()
    )
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

async fn forward_websocket(
    state: &ProxyState,
    session: SessionLease,
    mut target: Url,
    guard: RequestGuard,
    parts: &mut http::request::Parts,
) -> Response {
    let upgrade = match WebSocketUpgrade::from_request_parts(parts, state).await {
        Ok(upgrade) => upgrade
            .max_message_size(state.config.websocket_message_limit)
            .max_frame_size(state.config.websocket_message_limit),
        Err(rejection) => return rejection.into_response(),
    };
    let response_target = target.clone();
    let _ = target.set_scheme(if target.scheme() == "https" {
        "wss"
    } else {
        "ws"
    });
    let protocols: Vec<String> = parts
        .headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(|protocol| protocol.trim().to_owned())
                .filter(|protocol| !protocol.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let mut builder = session
        .client
        .websocket(target.as_str())
        .headers(outgoing_headers(&parts.headers, &state.upstream, true))
        .version(http::Version::HTTP_11)
        .max_message_size(state.config.websocket_message_limit)
        .max_frame_size(state.config.websocket_message_limit);
    if !protocols.is_empty() {
        builder = builder.protocols(protocols);
    }
    let mut response = match builder.send().await {
        Ok(response) => response,
        Err(error) => {
            state
                .metrics
                .upstream_errors
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(error = %error.without_uri(), "upstream websocket request failed");
            return (StatusCode::BAD_GATEWAY, "Upstream WebSocket request failed").into_response();
        }
    };
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        let status = response.status();
        let mut headers = response_headers(response.headers(), &response_target);
        add_session_cookie(&mut headers, session.cookie);
        mark_session_error(state, &session.jar, &mut headers);
        // Take the wrapped HTTP response so the actual rejection body is streamed.
        let inner = std::mem::replace(&mut *response, http::Response::new(Vec::<u8>::new()).into());
        let mut downstream = Response::new(stream_response(
            inner,
            guard,
            state.metrics.clone(),
            state.config.shutdown.clone(),
        ));
        *downstream.status_mut() = status;
        *downstream.headers_mut() = headers;
        return downstream;
    }
    let selected_protocol = response
        .headers()
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let upstream = match response
        .into_websocket()
        .await
        .context("upgrading upstream websocket")
    {
        Ok(upstream) => upstream,
        Err(error) => {
            tracing::warn!(error = %error, "invalid upstream websocket handshake");
            return (
                StatusCode::BAD_GATEWAY,
                "Invalid upstream WebSocket handshake",
            )
                .into_response();
        }
    };
    let upgrade = if let Some(protocol) = selected_protocol {
        upgrade.protocols([protocol])
    } else {
        upgrade
    };
    let metrics = state.metrics.clone();
    let shutdown = state.config.shutdown.clone();
    let idle = state.options.timeout;
    let mut downstream = upgrade.on_upgrade(move |socket| {
        bridge_websockets(socket, upstream, guard, metrics, shutdown, idle)
    });
    add_session_cookie(downstream.headers_mut(), session.cookie);
    mark_session_error(state, &session.jar, downstream.headers_mut());
    downstream
}

async fn bridge_websockets(
    mut downstream: WebSocket,
    mut upstream: wreq::ws::WebSocket,
    _guard: RequestGuard,
    metrics: Arc<Metrics>,
    shutdown: CancellationToken,
    idle: Duration,
) {
    loop {
        tokio::select! {
            _=shutdown.cancelled()=> {
                let _=tokio::time::timeout(Duration::from_secs(1),downstream.send(Message::Close(Some(CloseFrame{code:1001,reason:"proxy shutting down".into()})))).await;
                let _=tokio::time::timeout(Duration::from_secs(1),upstream.close(1001u16,"proxy shutting down")).await;
                break;
            }
            _=tokio::time::sleep(idle)=> {
                let _=tokio::time::timeout(Duration::from_secs(1),downstream.send(Message::Close(Some(CloseFrame{code:1001,reason:"idle timeout".into()})))).await;
                let _=tokio::time::timeout(Duration::from_secs(1),upstream.close(1001u16,"idle timeout")).await;
                break;
            }
            message = downstream.next() => {
                let Some(Ok(message)) = message else { break; };
                let close = matches!(message, Message::Close(_));
                let size = match &message { Message::Text(text)=>text.len(),Message::Binary(bytes)=>bytes.len(),_=>0 };
                metrics.uploaded.fetch_add(size as u64,Ordering::Relaxed);
                let message = match message {
                    Message::Text(text) => wreq::ws::message::Message::Text(text.to_string().into()),
                    Message::Binary(bytes) => wreq::ws::message::Message::Binary(bytes),
                    Message::Close(frame) => wreq::ws::message::Message::Close(frame.map(|frame| wreq::ws::message::CloseFrame { code: frame.code.into(), reason: frame.reason.to_string().into() })),
                    // Ping/pong are managed independently by each WebSocket connection.
                    Message::Ping(_) | Message::Pong(_) => continue,
                };
                if !matches!(tokio::time::timeout(idle,upstream.send(message)).await,Ok(Ok(()))) || close { break; }
            }
            message = upstream.next() => {
                let Some(Ok(message)) = message else { break; };
                let close = matches!(message, wreq::ws::message::Message::Close(_));
                let size = match &message { wreq::ws::message::Message::Text(text)=>text.len(),wreq::ws::message::Message::Binary(bytes)=>bytes.len(),_=>0 };
                metrics.downloaded.fetch_add(size as u64,Ordering::Relaxed);
                let message = match message {
                    wreq::ws::message::Message::Text(text) => Message::Text(text.to_string().into()),
                    wreq::ws::message::Message::Binary(bytes) => Message::Binary(bytes),
                    wreq::ws::message::Message::Close(frame) => Message::Close(frame.map(|frame| CloseFrame { code: frame.code.into(), reason: frame.reason.to_string().into() })),
                    wreq::ws::message::Message::Ping(_) | wreq::ws::message::Message::Pong(_) => continue,
                };
                if !matches!(tokio::time::timeout(idle,downstream.send(message)).await,Ok(Ok(()))) || close { break; }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarding_cannot_change_upstream_origin() {
        let upstream = Url::parse("https://example.com/").unwrap();
        let target = target_url(&upstream, &Uri::from_static("//evil.example/path?q=1"));
        assert_eq!(target.host_str(), Some("example.com"));
        assert_eq!(target.path(), "//evil.example/path");
        assert_eq!(target.query(), Some("q=1"));
    }

    #[test]
    fn connection_nominated_headers_and_private_cookies_are_removed() {
        let mut incoming = HeaderMap::new();
        incoming.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-secret"),
        );
        incoming.insert("x-secret", HeaderValue::from_static("remove-me"));
        incoming.insert(
            header::COOKIE,
            HeaderValue::from_static("flab_session=private"),
        );
        incoming.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer legitimate-upstream-token"),
        );
        let headers = outgoing_headers(
            &incoming,
            &Url::parse("https://example.com/").unwrap(),
            false,
        );
        assert!(!headers.contains_key("x-secret"));
        assert!(!headers.contains_key(header::COOKIE));
        assert!(headers.contains_key(header::AUTHORIZATION));
    }

    #[test]
    fn upstream_redirect_stays_on_the_proxy() {
        let upstream = Url::parse("https://example.com/").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::LOCATION,
            HeaderValue::from_static("https://example.com/login?q=1#next"),
        );
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static("session=upstream-secret"),
        );
        let rewritten = response_headers(&headers, &upstream);
        assert_eq!(rewritten[header::LOCATION], "/login?q=1#next");
        assert!(!rewritten.contains_key(header::SET_COOKIE));
    }

    #[test]
    fn relative_redirects_resolve_from_the_requested_path() {
        let target = Url::parse("https://example.com/account/flow/start").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::LOCATION, HeaderValue::from_static("next?step=2"));
        let rewritten = response_headers(&headers, &target);
        assert_eq!(rewritten[header::LOCATION], "/account/flow/next?step=2");
    }
}
