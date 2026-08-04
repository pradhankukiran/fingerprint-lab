use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    sync::Arc,
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{
        Request, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{any, get, post},
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use uuid::Uuid;

const BODY_LIMIT: usize = 1024 * 1024;
const SESSION_LIMIT: usize = 256;
const SESSION_COOKIE: &str = "demo_session";

#[derive(Default)]
struct Sessions {
    users: HashMap<String, String>,
    order: VecDeque<String>,
}

impl Sessions {
    fn remove(&mut self, token: &str) {
        self.users.remove(token);
        self.order.retain(|existing| existing != token);
    }

    fn insert(&mut self, token: String, user: String) {
        while self.users.len() >= SESSION_LIMIT {
            if let Some(oldest) = self.order.pop_front() {
                self.users.remove(&oldest);
            }
        }
        self.order.push_back(token.clone());
        self.users.insert(token, user);
    }
}

type FixtureState = Arc<Mutex<Sessions>>;

/// A local HTTP test origin. It simulates response types, not Cloudflare or TLS detection.
pub fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/login", post(login))
        .route("/session", get(session))
        .route("/logout", post(logout))
        .route(
            "/redirect",
            get(|| async { Redirect::to("/echo?via=redirect") }),
        )
        .route("/echo", any(echo))
        .route("/health", get(health))
        .route("/challenge", get(challenge))
        .route("/blocked", get(blocked))
        .route("/rate-limit", get(rate_limit))
        .route("/stream", get(stream))
        .route("/ws", get(websocket))
        .with_state(Arc::new(Mutex::new(Sessions::default())))
}

async fn index() -> Html<&'static str> {
    Html(include_str!("fixture.html"))
}

#[derive(Deserialize)]
struct LoginInput {
    user: Option<String>,
}

async fn login(State(state): State<FixtureState>, request: Request) -> Response {
    let previous = session_cookie(request.headers()).map(str::to_owned);
    let bytes = match to_bytes(request.into_body(), BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(_) => return body_limit_error(),
    };
    let input = if bytes.is_empty() {
        LoginInput { user: None }
    } else {
        match serde_json::from_slice::<LoginInput>(&bytes) {
            Ok(input) => input,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "Expected JSON with an optional user string"})),
                )
                    .into_response();
            }
        }
    };
    let user = input.user.unwrap_or_else(|| "guest".to_owned());
    let user = user.trim();
    if user.is_empty() || user.chars().count() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "User must contain 1 to 128 characters"})),
        )
            .into_response();
    }

    let token = Uuid::new_v4().to_string();
    let mut sessions = state.lock().await;
    if let Some(previous) = previous {
        sessions.remove(&previous);
    }
    sessions.insert(token.clone(), user.to_owned());
    drop(sessions);

    let mut response = Json(json!({"authenticated": true, "user": user})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax"
        ))
        .expect("UUID session cookie is a valid header"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn session(State(state): State<FixtureState>, headers: HeaderMap) -> Response {
    let user = match session_cookie(&headers) {
        Some(token) => state.lock().await.users.get(token).cloned(),
        None => None,
    };
    let mut response = match user {
        Some(user) => Json(json!({"authenticated": true, "user": user})).into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"authenticated": false})),
        )
            .into_response(),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn logout(State(state): State<FixtureState>, headers: HeaderMap) -> Response {
    if let Some(token) = session_cookie(&headers) {
        state.lock().await.remove(token);
    }
    let mut response = Json(json!({"authenticated": false})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("demo_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(name, value)| (name.trim() == SESSION_COOKIE).then_some(value.trim()))
}

async fn echo(request: Request) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().map(str::to_owned);
    let version = format!("{:?}", request.version());
    let safe_headers = [
        "accept",
        "accept-encoding",
        "content-type",
        "user-agent",
        "origin",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "x-request-id",
    ];
    let headers: serde_json::Map<String, serde_json::Value> = safe_headers
        .into_iter()
        .filter_map(|name| {
            request
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(|value| (name.to_owned(), json!(value)))
        })
        .collect();
    let bytes = match to_bytes(request.into_body(), BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(_) => return body_limit_error(),
    };
    Json(json!({
        "method": method,
        "path": path,
        "query": query,
        "http_version": version,
        "headers": headers,
        "body": String::from_utf8_lossy(&bytes),
        "body_bytes": bytes.len(),
        "fixture": true,
        "tls_fingerprints": "not measured: local HTTP fixture",
    }))
    .into_response()
}

fn body_limit_error() -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({"error": "Request body exceeds 1 MiB or could not be read"})),
    )
        .into_response()
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok", "fixture": true, "tls_fingerprints": "not measured"}))
}

async fn challenge() -> Response {
    let mut response = (StatusCode::FORBIDDEN, Json(json!({
        "error": "simulated_challenge",
        "message": "Simulated Cloudflare-style challenge. This fixture does not run Cloudflare or measure TLS fingerprints.",
        "fixture": true,
    }))).into_response();
    response
        .headers_mut()
        .insert("cf-mitigated", HeaderValue::from_static("challenge"));
    response
        .headers_mut()
        .insert(header::SERVER, HeaderValue::from_static("cloudflare"));
    response.headers_mut().insert(
        "x-lab-fixture",
        HeaderValue::from_static("simulated-challenge"),
    );
    response
}

async fn blocked() -> impl IntoResponse {
    (
        StatusCode::FORBIDDEN,
        [("x-lab-fixture", "generic-block")],
        "Generic forbidden response from the local test fixture.\n",
    )
}

async fn rate_limit() -> impl IntoResponse {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("retry-after", "5"), ("x-lab-fixture", "rate-limit")],
        "Simulated rate limit. Retry after 5 seconds.\n",
    )
}

async fn stream() -> Response {
    let chunks = futures_util::stream::unfold(0usize, |index| async move {
        const CHUNKS: [&str; 3] = [
            "chunk 1: stream opened\n",
            "chunk 2: still streaming\n",
            "chunk 3: stream complete\n",
        ];
        if index >= CHUNKS.len() {
            return None;
        }
        if index > 0 {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Some((Ok::<_, Infallible>(CHUNKS[index]), index + 1))
    });
    let mut response = Response::new(Body::from_stream(chunks));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("x-lab-fixture", HeaderValue::from_static("stream"));
    response
}

async fn websocket(upgrade: WebSocketUpgrade) -> Response {
    upgrade
        .max_message_size(BODY_LIMIT)
        .max_frame_size(BODY_LIMIT)
        .on_upgrade(echo_socket)
}

async fn echo_socket(mut socket: WebSocket) {
    while let Some(Ok(message)) = socket.recv().await {
        let response = match message {
            Message::Text(text) => Message::Text(text),
            Message::Binary(bytes) => Message::Binary(bytes),
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break,
        };
        if socket.send(response).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_cookie_across_multiple_headers() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("not_demo_session=wrong; other=1"),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("demo_session = correct; final=2"),
        );
        assert_eq!(session_cookie(&headers), Some("correct"));
    }

    #[test]
    fn evicts_oldest_session_and_bounds_both_collections() {
        let mut sessions = Sessions::default();
        for index in 0..=SESSION_LIMIT {
            sessions.insert(index.to_string(), format!("user-{index}"));
        }
        assert_eq!(sessions.users.len(), SESSION_LIMIT);
        assert_eq!(sessions.order.len(), SESSION_LIMIT);
        assert!(!sessions.users.contains_key("0"));
        assert_eq!(
            sessions.users.get(&SESSION_LIMIT.to_string()).unwrap(),
            &format!("user-{SESSION_LIMIT}")
        );
        sessions.remove("1");
        assert_eq!(sessions.order.len(), SESSION_LIMIT - 1);
    }
}
