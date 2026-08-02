use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http::{HeaderMap, HeaderName, HeaderValue};
use url::Url;

use crate::report::{Observation, ResponseSnapshot};

pub const PROBE_BODY_LIMIT: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct TransportOptions {
    pub profile: String,
    pub platform: String,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub network_proxy: Option<String>,
    pub headers: HeaderMap,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            profile: "chrome_149".into(),
            platform: "linux".into(),
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            network_proxy: None,
            headers: HeaderMap::new(),
        }
    }
}

/// Parse an experimental request header without permitting overrides of
/// routing or framing. Never include values in errors.
pub fn parse_header(input: &str) -> Result<(HeaderName, HeaderValue)> {
    let (name, value) = input
        .split_once(':')
        .context("headers must use NAME: VALUE syntax")?;
    let name = HeaderName::from_bytes(name.trim().as_bytes()).context("invalid header name")?;
    validate_header_name(&name)?;
    let value = HeaderValue::from_str(value.trim()).context("invalid header value")?;
    Ok((name, value))
}

fn validate_header_name(name: &HeaderName) -> Result<()> {
    if matches!(
        name.as_str(),
        "host"
            | "connection"
            | "proxy-connection"
            | "content-length"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-authorization"
    ) {
        bail!("header '{name}' is managed by the transport and cannot be overridden");
    }
    Ok(())
}

/// Validate without echoing a proxy URL, which may contain credentials.
pub fn validate_network_proxy(input: &str) -> Result<Url> {
    let proxy = Url::parse(input).context("expected an absolute network proxy URL")?;
    if !matches!(proxy.scheme(), "http" | "https") || proxy.host_str().is_none() {
        bail!("network proxy must use HTTP or HTTPS with a hostname");
    }
    if proxy.fragment().is_some() || proxy.query().is_some() || !matches!(proxy.path(), "" | "/") {
        bail!("network proxy URL cannot contain a path, query, or fragment");
    }
    Ok(proxy)
}

fn validate_options(options: &TransportOptions) -> Result<()> {
    if options.timeout.is_zero() || options.connect_timeout.is_zero() {
        bail!("request and connect timeouts must be greater than zero");
    }
    for name in options.headers.keys() {
        validate_header_name(name)?;
    }
    if let Some(proxy) = &options.network_proxy {
        validate_network_proxy(proxy)?;
    }
    Ok(())
}

/// Versions are embedded from the lockfile used to compile this executable.
pub fn compiled_dependency_version(name: &str) -> Option<&'static str> {
    let lock = include_str!("../Cargo.lock");
    lock.split("[[package]]").find_map(|package| {
        let mut package_name = None;
        let mut version = None;
        for line in package.lines() {
            if let Some(value) = line.strip_prefix("name = \"") {
                package_name = value.strip_suffix('"');
            } else if let Some(value) = line.strip_prefix("version = \"") {
                version = value.strip_suffix('"');
            }
        }
        (package_name == Some(name)).then_some(version).flatten()
    })
}

pub fn validate_url(input: &str) -> Result<Url> {
    let url = Url::parse(input).context("expected an absolute HTTP or HTTPS URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("only absolute HTTP and HTTPS URLs are supported");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("URLs containing credentials are not supported");
    }
    if url.fragment().is_some() {
        bail!("remove the URL fragment; fragments are not sent to HTTP servers");
    }
    Ok(url)
}

pub fn profiles() -> Vec<String> {
    wreq_util::Profile::VARIANTS
        .iter()
        .filter_map(|profile| {
            serde_json::to_value(profile)
                .ok()?
                .as_str()
                .map(str::to_owned)
        })
        .collect()
}

fn wreq_builder(options: &TransportOptions) -> Result<wreq::ClientBuilder> {
    validate_options(options)?;
    let profile: wreq_util::Profile = serde_json::from_value(options.profile.clone().into())
        .with_context(|| {
            format!(
                "unknown profile '{}'; run fingerprint-lab profiles",
                options.profile
            )
        })?;
    let platform: wreq_util::Platform = serde_json::from_value(options.platform.clone().into())
        .context("platform must be linux, windows, macos, android, or ios")?;
    let emulation = wreq_util::Emulation::builder()
        .profile(profile)
        .platform(platform)
        .build();
    let mut builder = wreq::Client::builder()
        .emulation(emulation)
        .default_headers(options.headers.clone())
        .connect_timeout(options.connect_timeout)
        .read_timeout(options.timeout)
        .retry(wreq::retry::Policy::never())
        .no_proxy()
        .redirect(wreq::redirect::Policy::none());
    if let Some(proxy) = &options.network_proxy {
        builder = builder.proxy(wreq::Proxy::all(proxy).context("invalid network proxy URL")?);
    }
    Ok(builder)
}

pub fn wreq_client(options: &TransportOptions, follow_redirects: bool) -> Result<wreq::Client> {
    wreq_builder(options)?
        .cookie_store(true)
        .timeout(options.timeout)
        .redirect(if follow_redirects {
            wreq::redirect::Policy::custom(|attempt| {
                if !matches!(attempt.uri.scheme_str(), Some("http" | "https")) {
                    attempt.error("redirect target must use HTTP or HTTPS")
                } else if attempt.previous.len() > 10 {
                    attempt.error("redirect limit of 10 exceeded")
                } else {
                    attempt.follow()
                }
            })
        } else {
            wreq::redirect::Policy::none()
        })
        .build()
        .context("building wreq browser transport")
}

/// Preserve encoded response bodies and session cookies. The read timeout
/// resets after each chunk; an active stream has no overall lifetime limit.
pub fn wreq_proxy_client(
    options: &TransportOptions,
    jar: Arc<dyn wreq::cookie::CookieStore>,
) -> Result<wreq::Client> {
    wreq_builder(options)?
        .cookie_provider(jar)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
        .context("building wreq proxy transport")
}

fn reqwest_builder(options: &TransportOptions) -> Result<reqwest::ClientBuilder> {
    validate_options(options)?;
    let mut builder = reqwest::Client::builder()
        .user_agent(concat!(
            "fingerprint-lab/",
            env!("CARGO_PKG_VERSION"),
            " reqwest"
        ))
        .default_headers(options.headers.clone())
        .cookie_store(true)
        .timeout(options.timeout)
        .connect_timeout(options.connect_timeout)
        .read_timeout(options.timeout)
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if !matches!(attempt.url().scheme(), "http" | "https") {
                attempt.error("redirect target must use HTTP or HTTPS")
            } else if attempt.previous().len() > 10 {
                attempt.error("redirect limit of 10 exceeded")
            } else {
                attempt.follow()
            }
        }))
        .no_proxy();
    if let Some(proxy) = &options.network_proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy).context("invalid network proxy URL")?);
    }
    Ok(builder)
}

pub fn reqwest_client(options: &TransportOptions) -> Result<reqwest::Client> {
    reqwest_builder(options)?
        .build()
        .context("building baseline HTTP transport")
}

pub async fn read_limited<S, E>(stream: S, limit: usize) -> Result<Vec<u8>>
where
    S: Stream<Item = std::result::Result<Bytes, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    futures_util::pin_mut!(stream);
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading response body")?;
        if chunk.len() > limit.saturating_sub(body.len()) {
            bail!("response exceeded the {} byte probe limit", limit);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub fn header_strings(headers: &http::HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_owned())))
        .collect()
}

pub fn http_version(version: http::Version) -> String {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2",
        http::Version::HTTP_3 => "HTTP/3",
        _ => "unknown",
    }
    .into()
}

pub async fn probe_reqwest(url: &Url, options: &TransportOptions) -> Observation {
    let started = Instant::now();
    let mut redirect_statuses = Vec::new();
    let result = tokio::time::timeout(options.timeout, async {
        validate_options(options)?;
        validate_url(url.as_str())?;
        let mut clean_options = options.clone();
        clean_options.headers.clear();
        let client = reqwest_builder(&clean_options)?
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building baseline HTTP transport")?;
        let mut current = url.clone();
        let response = loop {
            let mut request = client.get(current.clone());
            if current.origin() == url.origin() {
                request = request.headers(options.headers.clone());
            }
            let response = request.send().await?;
            match redirect_target(
                &current,
                response.status().as_u16(),
                response.headers(),
                redirect_statuses.len(),
            )? {
                Some(next) => {
                    redirect_statuses.push(response.status().as_u16());
                    current = next;
                }
                None => break response,
            }
        };
        let status = response.status().as_u16();
        let version = http_version(response.version());
        let final_url = response.url().to_string();
        let headers = header_strings(response.headers());
        let body = read_limited(response.bytes_stream(), PROBE_BODY_LIMIT).await?;
        Ok::<_, anyhow::Error>(ResponseSnapshot {
            status,
            http_version: version,
            final_url,
            headers,
            body,
            duration_ms: started.elapsed().as_millis() as u64,
        })
    })
    .await
    .context("baseline probe timed out")
    .and_then(|result| result);
    let mut result = observation("reqwest", None, result, started);
    result.client_version = Some(format!(
        "reqwest {} / rustls",
        compiled_dependency_version("reqwest").unwrap_or("unknown")
    ));
    add_transport_notes(&mut result, url, options);
    add_redirect_notes(&mut result, &redirect_statuses);
    result
}

pub async fn probe_wreq(url: &Url, options: &TransportOptions) -> Observation {
    let started = Instant::now();
    let mut redirect_statuses = Vec::new();
    let result = tokio::time::timeout(options.timeout, async {
        validate_options(options)?;
        validate_url(url.as_str())?;
        let mut clean_options = options.clone();
        clean_options.headers.clear();
        let client = wreq_client(&clean_options, false)?;
        let mut current = url.clone();
        let response = loop {
            let mut request = client.get(current.as_str());
            if current.origin() == url.origin() {
                request = request.headers(options.headers.clone());
            }
            let response = request.send().await?;
            match redirect_target(
                &current,
                response.status().as_u16(),
                response.headers(),
                redirect_statuses.len(),
            )? {
                Some(next) => {
                    redirect_statuses.push(response.status().as_u16());
                    current = next;
                }
                None => break response,
            }
        };
        let status = response.status().as_u16();
        let version = http_version(response.version());
        let final_url = response.uri().to_string();
        let headers = header_strings(response.headers());
        let body = read_limited(response.bytes_stream(), PROBE_BODY_LIMIT).await?;
        Ok::<_, anyhow::Error>(ResponseSnapshot {
            status,
            http_version: version,
            final_url,
            headers,
            body,
            duration_ms: started.elapsed().as_millis() as u64,
        })
    })
    .await
    .context("wreq probe timed out")
    .and_then(|result| result);
    let mut result = observation("wreq", Some(options.profile.clone()), result, started);
    result.client_version = Some(format!(
        "wreq {} / wreq-util {}",
        compiled_dependency_version("wreq").unwrap_or("unknown"),
        compiled_dependency_version("wreq-util").unwrap_or("unknown")
    ));
    add_transport_notes(&mut result, url, options);
    add_redirect_notes(&mut result, &redirect_statuses);
    result
}

fn redirect_target(
    current: &Url,
    status: u16,
    headers: &HeaderMap,
    count: usize,
) -> Result<Option<Url>> {
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return Ok(None);
    }
    let Some(location) = headers.get(http::header::LOCATION) else {
        return Ok(None);
    };
    if count >= 10 {
        bail!("redirect limit of 10 exceeded");
    }
    let mut next = current
        .join(
            location
                .to_str()
                .context("redirect Location is not valid text")?,
        )
        .context("invalid redirect target URL")?;
    next.set_fragment(None);
    validate_url(next.as_str()).context("unsafe redirect target")?;
    Ok(Some(next))
}

fn add_redirect_notes(observation: &mut Observation, statuses: &[u16]) {
    if !statuses.is_empty() {
        observation.notes.push(format!(
            "Followed {} redirect(s), with response statuses: {}. Custom headers were sent only to the original target origin.",
            statuses.len(),
            statuses.iter().map(u16::to_string).collect::<Vec<_>>().join(" -> "),
        ));
    }
}

fn add_transport_notes(observation: &mut Observation, url: &Url, options: &TransportOptions) {
    if observation
        .final_url
        .as_deref()
        .unwrap_or(url.as_str())
        .starts_with("http://")
    {
        observation.notes.push(
            "The final request used plain HTTP; its connection has no TLS JA3/JA4 fingerprint."
                .into(),
        );
    }
    if options.network_proxy.is_some() {
        observation.notes.push(
            "A network proxy was configured. Any returned fingerprint describes the connection observed by the destination, which may differ from the client's direct connection.".into(),
        );
    }
    if options.headers.contains_key(http::header::USER_AGENT) {
        observation.notes.push(
            "User-Agent was explicitly overridden; this does not change the TLS or HTTP/2 emulation profile.".into(),
        );
    }
}

fn observation(
    client: &str,
    profile: Option<String>,
    result: Result<ResponseSnapshot>,
    started: Instant,
) -> Observation {
    match result {
        Ok(snapshot) => Observation::from_response(client, profile, snapshot),
        Err(error) => Observation::failed(
            client,
            profile,
            format!("{error:#}"),
            started.elapsed().as_millis() as u64,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use tokio::sync::Mutex;

    #[test]
    fn urls_reject_credentials_and_non_http_schemes() {
        assert!(validate_url("file:///etc/passwd").is_err());
        assert!(validate_url("https://user:password@example.com/").is_err());
        assert!(validate_url("https://example.com/#fragment").is_err());
        assert!(validate_url("https://example.com/path?q=1").is_ok());
    }

    #[tokio::test]
    async fn body_limit_is_enforced_across_chunks() {
        let stream = futures_util::stream::iter([
            Ok::<_, std::io::Error>(Bytes::from_static(b"123")),
            Ok(Bytes::from_static(b"456")),
        ]);
        assert!(read_limited(stream, 5).await.is_err());
    }

    #[test]
    fn custom_headers_allow_auth_but_reject_framing_and_invalid_values() {
        for input in [
            "Host: example.com",
            "cOnNeCtIoN: close",
            "Content-Length: 0",
            "Transfer-Encoding: chunked",
            "Proxy-Authorization: secret",
            "Upgrade: websocket",
            "TE: trailers",
        ] {
            assert!(parse_header(input).is_err(), "accepted {input}");
        }
        for input in [
            "User-Agent: experimental agent",
            "Authorization: Bearer secret",
            "Cookie: session=secret",
            "X-Experiment: a:b",
        ] {
            assert!(parse_header(input).is_ok(), "rejected {input}");
        }
        assert!(parse_header("missing colon").is_err());
        let error = parse_header("X-Experiment: secret\r\nInjected: yes").unwrap_err();
        assert!(!format!("{error:#}").contains("secret"));
    }

    #[test]
    fn proxy_validation_rejects_non_http_and_does_not_echo_credentials() {
        let proxy = validate_network_proxy("http://user:secret@localhost:8080/").unwrap();
        assert_eq!(proxy.host_str(), Some("localhost"));
        for input in [
            "socks5://user:secret@localhost:1080",
            "file:///etc/passwd",
            "http://user:secret@localhost:8080/path",
            "http://user:secret@localhost:8080/?query=1",
        ] {
            let error = validate_network_proxy(input).unwrap_err();
            assert!(!format!("{error:#}").contains("secret"));
        }
    }

    #[test]
    fn invalid_transport_configuration_fails_before_network_requests() {
        let options = TransportOptions {
            profile: "missing-profile".into(),
            ..TransportOptions::default()
        };
        assert!(wreq_client(&options, false).is_err());
        let options = TransportOptions {
            platform: "missing-platform".into(),
            ..TransportOptions::default()
        };
        assert!(wreq_client(&options, false).is_err());
        let options = TransportOptions {
            connect_timeout: Duration::ZERO,
            ..TransportOptions::default()
        };
        assert!(wreq_client(&options, false).is_err());
        assert!(reqwest_client(&options).is_err());
        let mut options = TransportOptions::default();
        options
            .headers
            .insert(http::header::HOST, HeaderValue::from_static("example.com"));
        assert!(reqwest_client(&options).is_err());
    }

    #[test]
    fn redirects_are_bounded_and_cannot_add_credentials_or_change_scheme() {
        let current = Url::parse("https://example.com/start").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::LOCATION,
            HeaderValue::from_static("/next#fragment"),
        );
        let next = redirect_target(&current, 302, &headers, 9)
            .unwrap()
            .unwrap();
        assert_eq!(next.as_str(), "https://example.com/next");
        assert!(redirect_target(&current, 302, &headers, 10).is_err());
        assert!(
            redirect_target(&current, 304, &headers, 0)
                .unwrap()
                .is_none()
        );
        for location in ["file:///etc/passwd", "https://user:secret@example.com/"] {
            headers.insert(
                http::header::LOCATION,
                HeaderValue::from_str(location).unwrap(),
            );
            assert!(redirect_target(&current, 302, &headers, 0).is_err());
        }
    }

    async fn test_server(router: Router) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (url, task)
    }

    #[tokio::test]
    async fn probes_scope_custom_headers_to_original_origin_across_redirects() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let destination = Router::new().route(
            "/",
            get({
                let seen = seen.clone();
                move |headers: HeaderMap| {
                    let seen = seen.clone();
                    async move {
                        seen.lock().await.push(("destination", headers));
                        "complete"
                    }
                }
            }),
        );
        let (destination, destination_task) = test_server(destination).await;
        let origin = Router::new()
            .route(
                "/",
                get({
                    let seen = seen.clone();
                    move |headers: HeaderMap| {
                        let seen = seen.clone();
                        async move {
                            seen.lock().await.push(("origin", headers));
                            (
                                http::StatusCode::FOUND,
                                [
                                    ("location", "/same"),
                                    ("set-cookie", "server_session=ok; Path=/"),
                                ],
                            )
                        }
                    }
                }),
            )
            .route(
                "/same",
                get({
                    let seen = seen.clone();
                    let destination = destination.to_string();
                    move |headers: HeaderMap| {
                        let seen = seen.clone();
                        let destination = destination.clone();
                        async move {
                            seen.lock().await.push(("same", headers));
                            (http::StatusCode::FOUND, [("location", destination)])
                        }
                    }
                }),
            );
        let (origin, origin_task) = test_server(origin).await;
        let mut options = TransportOptions::default();
        for header in [
            "X-Api-Key: secret",
            "Authorization: Bearer secret",
            "Cookie: manual=secret",
        ] {
            let (name, value) = parse_header(header).unwrap();
            options.headers.insert(name, value);
        }
        for observation in [
            probe_reqwest(&origin, &options).await,
            probe_wreq(&origin, &options).await,
        ] {
            assert_eq!(observation.status, Some(200), "{:?}", observation.error);
            assert!(
                observation
                    .notes
                    .iter()
                    .any(|note| note.contains("2 redirect(s)"))
            );
        }
        let seen = seen.lock().await;
        assert_eq!(seen.len(), 6);
        for (endpoint, headers) in seen.iter() {
            if *endpoint == "destination" {
                assert!(!headers.contains_key("x-api-key"));
                assert!(!headers.contains_key(http::header::AUTHORIZATION));
                assert!(
                    !headers
                        .get(http::header::COOKIE)
                        .is_some_and(|value| value.to_str().unwrap().contains("manual=secret"))
                );
            } else {
                assert_eq!(headers.get("x-api-key").unwrap(), "secret");
                assert_eq!(headers.get(http::header::COOKIE).unwrap(), "manual=secret");
            }
        }
        origin_task.abort();
        destination_task.abort();
    }

    #[tokio::test]
    async fn probes_enforce_wall_clock_timeout_and_body_limit() {
        let router = Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    "late"
                }),
            )
            .route("/large", get(|| async { vec![b'x'; PROBE_BODY_LIMIT + 1] }));
        let (origin, task) = test_server(router).await;
        let options = TransportOptions {
            timeout: Duration::from_millis(50),
            ..TransportOptions::default()
        };
        for observation in [
            probe_reqwest(&origin.join("slow").unwrap(), &options).await,
            probe_wreq(&origin.join("slow").unwrap(), &options).await,
        ] {
            assert!(
                observation
                    .error
                    .as_ref()
                    .is_some_and(|error| error.contains("timed out"))
            );
            assert!(observation.duration_ms < 1000);
        }
        for observation in [
            probe_reqwest(&origin.join("large").unwrap(), &TransportOptions::default()).await,
            probe_wreq(&origin.join("large").unwrap(), &TransportOptions::default()).await,
        ] {
            assert!(
                observation
                    .error
                    .as_ref()
                    .is_some_and(|error| error.contains("probe limit"))
            );
        }
        task.abort();
    }

    #[tokio::test]
    async fn proxy_idle_timeout_preserves_long_active_streams() {
        let router = Router::new()
            .route(
                "/active",
                get(|| async {
                    Body::from_stream(futures_util::stream::unfold(0, |count| async move {
                        if count >= 6 {
                            return None;
                        }
                        tokio::time::sleep(Duration::from_millis(40)).await;
                        Some((Ok::<_, std::io::Error>(Bytes::from_static(b"x")), count + 1))
                    }))
                }),
            )
            .route(
                "/idle",
                get(|| async {
                    Body::from_stream(futures_util::stream::once(async {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        Ok::<_, std::io::Error>(Bytes::from_static(b"late"))
                    }))
                }),
            );
        let (origin, task) = test_server(router).await;
        let options = TransportOptions {
            timeout: Duration::from_millis(150),
            ..TransportOptions::default()
        };
        let client = wreq_proxy_client(&options, Arc::new(wreq::cookie::Jar::default())).unwrap();
        let started = Instant::now();
        let active = client
            .get(origin.join("active").unwrap().as_str())
            .send()
            .await
            .unwrap();
        assert_eq!(
            read_limited(active.bytes_stream(), 16).await.unwrap(),
            b"xxxxxx"
        );
        assert!(started.elapsed() > options.timeout);
        let idle = client
            .get(origin.join("idle").unwrap().as_str())
            .send()
            .await;
        assert!(match idle {
            Ok(response) => read_limited(response.bytes_stream(), 16).await.is_err(),
            Err(error) => error.is_timeout(),
        });
        task.abort();
    }

    #[tokio::test]
    async fn proxy_client_preserves_encoding_and_uses_the_supplied_cookie_jar() {
        const GZIP_HELLO: &[u8] = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xcb\x48\xcd\xc9\xc9\x07\x00\x86\xa6\x10\x36\x05\x00\x00\x00";
        let router = Router::new()
            .route(
                "/encoded",
                get(|| async {
                    (
                        [
                            ("content-encoding", "gzip"),
                            ("set-cookie", "upstream_session=works; Path=/"),
                        ],
                        GZIP_HELLO,
                    )
                }),
            )
            .route(
                "/cookies",
                get(|headers: HeaderMap| async move {
                    headers
                        .get(http::header::COOKIE)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("")
                        .to_owned()
                }),
            );
        let (origin, task) = test_server(router).await;
        let jar = Arc::new(wreq::cookie::Jar::default());
        let client = wreq_proxy_client(&TransportOptions::default(), jar.clone()).unwrap();
        let response = client
            .get(origin.join("encoded").unwrap().as_str())
            .send()
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_ENCODING)
                .unwrap(),
            "gzip"
        );
        assert_eq!(response.content_length(), Some(GZIP_HELLO.len() as u64));
        assert_eq!(
            read_limited(response.bytes_stream(), 1024).await.unwrap(),
            GZIP_HELLO
        );
        // A second client using the same supplied jar must see the stored cookie.
        let client = wreq_proxy_client(&TransportOptions::default(), jar).unwrap();
        let response = client
            .get(origin.join("cookies").unwrap().as_str())
            .send()
            .await
            .unwrap();
        assert_eq!(
            read_limited(response.bytes_stream(), 1024).await.unwrap(),
            b"upstream_session=works",
        );
        task.abort();
    }
}
