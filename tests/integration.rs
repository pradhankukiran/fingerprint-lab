use std::time::Duration;

use axum::Router;
use axum::extract::ws::{Message as AxumMessage, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use fingerprint_lab::proxy::ProxyConfig;
use fingerprint_lab::report::{Observation, Outcome};
use fingerprint_lab::transport::{TransportOptions, probe_reqwest, probe_wreq};
use futures_util::{SinkExt, StreamExt};
use reqwest::Client;
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
use url::Url;

struct RunningServer {
    url: Url,
    task: JoinHandle<()>,
}

impl RunningServer {
    async fn start(router: Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self { url, task }
    }

    async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn proxy(origin: &RunningServer) -> RunningServer {
    RunningServer::start(
        fingerprint_lab::proxy::router(origin.url.clone(), TransportOptions::default()).unwrap(),
    )
    .await
}

fn client() -> Client {
    Client::builder()
        .cookie_store(true)
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

async fn session(client: &Client, proxy: &RunningServer) -> Value {
    client
        .get(proxy.url.join("session").unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn proxy_preserves_and_isolates_login_sessions_and_logout() {
    let origin = RunningServer::start(fingerprint_lab::fixture::router()).await;
    let proxy = proxy(&origin).await;
    let alice = client();
    let bob = client();
    let response = alice
        .post(proxy.url.join("login").unwrap())
        .json(&json!({"user":"Alice"}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cookie.starts_with("flab_session="));
    assert!(!cookie.contains("demo_session="));
    bob.post(proxy.url.join("login").unwrap())
        .json(&json!({"user":"Bob"}))
        .send()
        .await
        .unwrap();
    assert_eq!(session(&alice, &proxy).await["user"], "Alice");
    assert_eq!(session(&bob, &proxy).await["user"], "Bob");
    alice
        .post(proxy.url.join("logout").unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(
        alice
            .get(proxy.url.join("session").unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(session(&bob, &proxy).await["user"], "Bob");
}

#[tokio::test]
async fn proxy_forwards_methods_queries_and_redirects() {
    let origin = RunningServer::start(fingerprint_lab::fixture::router()).await;
    let proxy = proxy(&origin).await;
    let client = client();
    let echo: Value = client
        .post(proxy.url.join("echo?q=hello%20world").unwrap())
        .header("x-lab-test", "forwarded")
        .body("request body")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(echo["method"], "POST");
    assert_eq!(echo["body"], "request body");
    assert_eq!(echo["query"], "q=hello%20world");
    let redirect_client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();
    let redirect = redirect_client
        .get(proxy.url.join("redirect").unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(redirect.status(), 303);
    assert_eq!(redirect.headers()["location"], "/echo?via=redirect");
    let final_response: Value = client
        .get(proxy.url.join("redirect").unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(final_response["query"], "via=redirect");
}

#[tokio::test]
async fn empty_get_does_not_gain_chunked_request_framing() {
    let origin = RunningServer::start(Router::new().route(
        "/",
        get(|headers: HeaderMap| async move {
            axum::Json(json!({
                "chunked": headers.contains_key("transfer-encoding"),
                "length": headers.get("content-length").and_then(|value| value.to_str().ok()),
            }))
        }),
    ))
    .await;
    let proxy = proxy(&origin).await;
    let response: Value = client()
        .get(proxy.url.clone())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(response["chunked"], false);
    assert!(response["length"].is_null() || response["length"] == "0");
}

#[tokio::test]
async fn shutdown_terminates_active_http_streams_and_rejects_new_requests() {
    let origin = RunningServer::start(fingerprint_lab::fixture::router()).await;
    let config = ProxyConfig::default();
    let shutdown = config.shutdown.clone();
    let proxy = RunningServer::start(
        fingerprint_lab::proxy::router_with_config(
            origin.url.clone(),
            TransportOptions::default(),
            config,
        )
        .unwrap(),
    )
    .await;
    let client = client();
    let mut stream = client
        .get(proxy.url.join("stream").unwrap())
        .send()
        .await
        .unwrap()
        .bytes_stream();
    assert!(stream.next().await.unwrap().is_ok());
    shutdown.cancel();
    let next = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap();
    assert!(next.is_none_or(|chunk| chunk.is_err()));
    assert_eq!(
        client.get(proxy.url.clone()).send().await.unwrap().status(),
        503
    );
}

#[tokio::test]
async fn proxy_streams_without_collecting_the_whole_response() {
    let origin = RunningServer::start(fingerprint_lab::fixture::router()).await;
    let proxy = proxy(&origin).await;
    let response = client()
        .get(proxy.url.join("stream").unwrap())
        .send()
        .await
        .unwrap();
    let mut stream = response.bytes_stream();
    let first = stream.next().await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(&first).contains("chunk 1"));
    assert!(!String::from_utf8_lossy(&first).contains("chunk 3"));
    let mut body = first.to_vec();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk.unwrap());
    }
    assert!(String::from_utf8_lossy(&body).contains("chunk 3"));
}

async fn authenticated_websocket(headers: HeaderMap, upgrade: WebSocketUpgrade) -> Response {
    if !headers
        .get("cookie")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|cookie| cookie.contains("demo_session="))
    {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            "missing session cookie",
        )
            .into_response();
    }
    upgrade
        .protocols(["lab-echo"])
        .on_upgrade(async |mut socket| {
            while let Some(Ok(message)) = socket.next().await {
                match message {
                    AxumMessage::Text(_) | AxumMessage::Binary(_) => {
                        if socket.send(message).await.is_err() {
                            break;
                        }
                    }
                    AxumMessage::Close(_) => break,
                    _ => {}
                }
            }
        })
}

#[tokio::test]
async fn proxy_websocket_uses_session_cookies_and_negotiates_subprotocol() {
    let router = fingerprint_lab::fixture::router().route("/auth-ws", get(authenticated_websocket));
    let origin = RunningServer::start(router).await;
    let proxy = proxy(&origin).await;
    let client = client();
    let response = client
        .post(proxy.url.join("login").unwrap())
        .json(&json!({"user":"Alice"}))
        .send()
        .await
        .unwrap();
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut url = proxy.url.join("auth-ws").unwrap();
    url.set_scheme("ws").unwrap();
    let mut request = url.as_str().into_client_request().unwrap();
    request
        .headers_mut()
        .insert("cookie", cookie.parse().unwrap());
    request
        .headers_mut()
        .insert("sec-websocket-protocol", "lab-echo".parse().unwrap());
    let (mut socket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(response.headers()["sec-websocket-protocol"], "lab-echo");
    socket
        .send(Message::Text("hello through proxy".into()))
        .await
        .unwrap();
    let echo = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echo, Message::Text("hello through proxy".into()));
    socket
        .send(Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Message::Binary(vec![1, 2, 3].into())
    );
    socket.close(None).await.unwrap();
}

#[tokio::test]
async fn probes_classify_mock_challenges_without_inventing_fingerprints() {
    let origin = RunningServer::start(fingerprint_lab::fixture::router()).await;
    let options = TransportOptions::default();
    let challenge = probe_wreq(&origin.url.join("challenge").unwrap(), &options).await;
    assert_eq!(challenge.outcome, Outcome::Challenge);
    assert!(challenge.fingerprints.ja4.is_none());
    assert_eq!(
        probe_reqwest(&origin.url.join("blocked").unwrap(), &options)
            .await
            .outcome,
        Outcome::Denied
    );
    assert_eq!(
        probe_wreq(&origin.url.join("rate-limit").unwrap(), &options)
            .await
            .outcome,
        Outcome::RateLimited
    );
    let observations: [Observation; 2] = [
        probe_reqwest(&origin.url.join("redirect").unwrap(), &options).await,
        probe_wreq(&origin.url.join("redirect").unwrap(), &options).await,
    ];
    for observation in observations {
        assert_eq!(observation.status, Some(200));
        assert!(
            observation
                .final_url
                .unwrap()
                .ends_with("/echo?via=redirect")
        );
    }
}

#[tokio::test]
async fn proxy_limits_request_bodies() {
    let origin = RunningServer::start(fingerprint_lab::fixture::router()).await;
    let proxy = proxy(&origin).await;
    let response = client()
        .post(proxy.url.join("echo").unwrap())
        .body(vec![b'x'; 1024 * 1024 + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
}

#[tokio::test]
async fn persistent_proxy_sessions_survive_restart_without_sharing_users() {
    let origin = RunningServer::start(fingerprint_lab::fixture::router()).await;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sessions.sqlite");
    let config = ProxyConfig {
        session_db: Some(path.clone()),
        ..Default::default()
    };
    let first = RunningServer::start(
        fingerprint_lab::proxy::router_with_config(
            origin.url.clone(),
            TransportOptions::default(),
            config.clone(),
        )
        .unwrap(),
    )
    .await;
    let alice = client();
    let bob = client();
    alice
        .post(first.url.join("login").unwrap())
        .json(&json!({"user":"Alice"}))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    bob.post(first.url.join("login").unwrap())
        .json(&json!({"user":"Bob"}))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(session(&alice, &first).await["user"], "Alice");
    first.stop().await;
    let second = RunningServer::start(
        fingerprint_lab::proxy::router_with_config(
            origin.url.clone(),
            TransportOptions::default(),
            config,
        )
        .unwrap(),
    )
    .await;
    assert_eq!(session(&alice, &second).await["user"], "Alice");
    assert_eq!(session(&bob, &second).await["user"], "Bob");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[tokio::test]
async fn session_capacity_preserves_existing_logins() {
    let origin = RunningServer::start(fingerprint_lab::fixture::router()).await;
    let config = ProxyConfig {
        session_limit: 1,
        ..Default::default()
    };
    let proxy = RunningServer::start(
        fingerprint_lab::proxy::router_with_config(
            origin.url.clone(),
            TransportOptions::default(),
            config,
        )
        .unwrap(),
    )
    .await;
    let alice = client();
    alice
        .post(proxy.url.join("login").unwrap())
        .json(&json!({"user":"Alice"}))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let rejected = client()
        .get(proxy.url.join("session").unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 503);
    assert_eq!(session(&alice, &proxy).await["user"], "Alice");
}

#[tokio::test]
async fn active_stream_outlives_the_idle_deadline() {
    let origin = RunningServer::start(Router::new().route(
        "/",
        get(|| async {
            let chunks = futures_util::stream::unfold(0, |index| async move {
                if index >= 6 {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(120)).await;
                Some((
                    Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"part\n")),
                    index + 1,
                ))
            });
            Response::new(axum::body::Body::from_stream(chunks))
        }),
    ))
    .await;
    let options = TransportOptions {
        timeout: Duration::from_millis(450),
        ..Default::default()
    };
    let proxy =
        RunningServer::start(fingerprint_lab::proxy::router(origin.url.clone(), options).unwrap())
            .await;
    let response = client().get(proxy.url.clone()).send().await.unwrap();
    assert_eq!(
        response.bytes().await.unwrap(),
        bytes::Bytes::from("part\n".repeat(6))
    );
}

#[tokio::test]
async fn concurrent_stream_limit_is_reported_and_slots_are_released() {
    let origin = RunningServer::start(Router::new().route(
        "/",
        get(|| async {
            let chunks = futures_util::stream::once(async {
                Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"open\n"))
            })
            .chain(futures_util::stream::pending());
            Response::new(axum::body::Body::from_stream(chunks))
        }),
    ))
    .await;
    let config = ProxyConfig {
        max_in_flight: 1,
        ..Default::default()
    };
    let proxy = RunningServer::start(
        fingerprint_lab::proxy::router_with_config(
            origin.url.clone(),
            TransportOptions::default(),
            config,
        )
        .unwrap(),
    )
    .await;
    let client = client();
    let first = client.get(proxy.url.clone()).send().await.unwrap();
    let rejected = client.get(proxy.url.clone()).send().await.unwrap();
    assert_eq!(rejected.status(), 503);
    assert_eq!(rejected.headers()["retry-after"], "1");
    let health: Value = client
        .get(proxy.url.join("_fingerprint-lab/health").unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["active_requests"], 1);
    drop(first);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let health: Value = client
                .get(proxy.url.join("_fingerprint-lab/health").unwrap())
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if health["active_requests"] == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    let metrics = client
        .get(proxy.url.join("_fingerprint-lab/metrics").unwrap())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("fingerprint_lab_rejected_requests_total 1"));
}

#[tokio::test]
async fn proxy_preserves_compressed_bytes_headers_etags_and_head_lengths() {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"original response bytes").unwrap();
    let compressed = encoder.finish().unwrap();
    let expected = compressed.clone();
    let origin = RunningServer::start(Router::new().route(
        "/",
        get(move || {
            let compressed = compressed.clone();
            async move {
                let length = compressed.len();
                let mut response = Response::new(axum::body::Body::from(compressed));
                response
                    .headers_mut()
                    .insert("content-encoding", "gzip".parse().unwrap());
                response
                    .headers_mut()
                    .insert("content-length", length.to_string().parse().unwrap());
                response
                    .headers_mut()
                    .insert("etag", "\"original-compressed\"".parse().unwrap());
                response
            }
        }),
    ))
    .await;
    let proxy = proxy(&origin).await;
    let client = Client::builder()
        .gzip(false)
        .brotli(false)
        .deflate(false)
        .zstd(false)
        .no_proxy()
        .build()
        .unwrap();
    let response = client.get(proxy.url.clone()).send().await.unwrap();
    assert_eq!(response.headers()["content-encoding"], "gzip");
    assert_eq!(
        response.headers()["content-length"],
        expected.len().to_string()
    );
    assert_eq!(response.headers()["etag"], "\"original-compressed\"");
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        expected.as_slice()
    );
    let head = client.head(proxy.url.clone()).send().await.unwrap();
    assert_eq!(head.headers()["content-length"], expected.len().to_string());
    assert!(head.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn proxy_streams_chunked_uploads_and_enforces_the_configured_limit() {
    let origin = RunningServer::start(Router::new().route(
        "/",
        axum::routing::post(|request: axum::extract::Request| async {
            let body = axum::body::to_bytes(request.into_body(), 4 * 1024 * 1024)
                .await
                .unwrap();
            axum::Json(json!({"received":body.len()}))
        }),
    ))
    .await;
    let config = ProxyConfig {
        request_body_limit: 2 * 1024 * 1024,
        ..Default::default()
    };
    let proxy = RunningServer::start(
        fingerprint_lab::proxy::router_with_config(
            origin.url.clone(),
            TransportOptions::default(),
            config,
        )
        .unwrap(),
    )
    .await;
    let chunks = futures_util::stream::iter(
        (0..3).map(|_| Ok::<_, std::io::Error>(bytes::Bytes::from(vec![b'x'; 512 * 1024]))),
    );
    let response = client()
        .post(proxy.url.clone())
        .body(reqwest::Body::wrap_stream(chunks))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.json::<Value>().await.unwrap()["received"],
        3 * 512 * 1024
    );
    let too_large = client()
        .post(proxy.url.clone())
        .body(vec![b'x'; 2 * 1024 * 1024 + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(too_large.status(), 413);
}

#[tokio::test]
async fn shutdown_closes_websockets_and_releases_connections() {
    let origin = RunningServer::start(fingerprint_lab::fixture::router()).await;
    let config = ProxyConfig::default();
    let shutdown = config.shutdown.clone();
    let proxy = RunningServer::start(
        fingerprint_lab::proxy::router_with_config(
            origin.url.clone(),
            TransportOptions::default(),
            config,
        )
        .unwrap(),
    )
    .await;
    let mut url = proxy.url.join("ws").unwrap();
    url.set_scheme("ws").unwrap();
    let (mut socket, _) = tokio_tungstenite::connect_async(url.as_str())
        .await
        .unwrap();
    socket
        .send(Message::Text("before shutdown".into()))
        .await
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap(),
        Message::Text("before shutdown".into())
    );
    shutdown.cancel();
    let close = tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    match close {
        Message::Close(Some(frame)) => assert_eq!(u16::from(frame.code), 1001),
        _ => panic!("expected a GoingAway close frame"),
    }
}
