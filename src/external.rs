use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use url::Url;

use crate::report::{BrowserNavigation, Observation, ResponseSnapshot, redact_url};
use crate::transport::{
    PROBE_BODY_LIMIT, TransportOptions, parse_header, validate_network_proxy, validate_url,
};

const BROWSER_OUTPUT_LIMIT: usize = PROBE_BODY_LIMIT * 6 + 256 * 1024;
const METADATA_LIMIT: usize = 256 * 1024;
const ERROR_LIMIT: usize = 64 * 1024;
const COOKIE_LIMIT: u64 = 256 * 1024;

#[derive(Deserialize)]
struct BrowserSnapshot {
    status: u16,
    http_version: String,
    final_url: String,
    headers: BTreeMap<String, String>,
    body: String,
    duration_ms: u64,
    client_version: String,
    #[serde(default)]
    initial_status: Option<u16>,
    #[serde(default)]
    initial_url: Option<String>,
    #[serde(default)]
    redirect_chain: Vec<String>,
    #[serde(default)]
    initial_observed_at_ms: Option<u64>,
    #[serde(default)]
    final_observed_at_ms: Option<u64>,
}

pub fn browser_runner() -> PathBuf {
    std::env::var_os("FINGERPRINT_LAB_BROWSER_RUNNER")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("browser/probe.mjs"))
}

pub async fn probe_browser(
    url: &Url,
    options: &TransportOptions,
    executable: Option<&Path>,
    wait: Duration,
) -> Observation {
    let started = Instant::now();
    let result = async {
        validate_external_options(url, options)?;
        let mut command = Command::new("node");
        command
            .arg(browser_runner())
            .args(["--url", url.as_str(), "--timeout-ms"])
            .arg(options.timeout.as_millis().max(1).to_string())
            .arg("--wait-seconds")
            .arg(wait.as_secs_f64().to_string())
            .env("FINGERPRINT_LAB_MONITOR_PARENT", "1")
            .stdin(Stdio::piped());
        if let Some(executable) = executable {
            command.arg("--executable").arg(executable);
        }
        if let Some(proxy) = &options.network_proxy {
            command.arg("--network-proxy").arg(proxy);
        }
        for (name, value) in &options.headers {
            command.arg("--header").arg(format!(
                "{name}: {}",
                value
                    .to_str()
                    .context("browser header values must contain valid text")?
            ));
        }
        let output = run_command(
            &mut command,
            options.timeout + Duration::from_secs(2),
            BROWSER_OUTPUT_LIMIT,
            ERROR_LIMIT,
        )
        .await
        .context("running browser probe; install its dependency with npm ci --prefix browser")?;
        if !output.status.success() {
            bail!(
                "browser runner failed: {}",
                sanitized_error(&output.stderr, options)
            );
        }
        let raw: BrowserSnapshot = serde_json::from_slice(&output.stdout)
            .context("browser runner returned invalid or oversized JSON")?;
        if raw.body.len() > PROBE_BODY_LIMIT {
            bail!("browser response exceeded probe body limit");
        }
        if !(100..=599).contains(&raw.status) || raw.redirect_chain.len() > 32 {
            bail!("browser runner returned invalid response metadata");
        }
        validate_url(&raw.final_url).context("browser returned an unsupported final URL")?;
        let navigation = BrowserNavigation {
            initial_status: raw.initial_status,
            initial_url: raw.initial_url.as_deref().map(redact_url),
            initial_observed_at_ms: raw.initial_observed_at_ms,
            final_observed_at_ms: raw.final_observed_at_ms,
            redirect_chain: raw
                .redirect_chain
                .iter()
                .map(|url| redact_url(url))
                .collect(),
        };
        let mut observation = Observation::from_response(
            "browser",
            None,
            ResponseSnapshot {
                status: raw.status,
                http_version: raw.http_version,
                final_url: raw.final_url,
                headers: raw.headers,
                body: raw.body.into_bytes(),
                duration_ms: raw.duration_ms,
            },
        );
        observation.client_version = Some(raw.client_version);
        observation.browser_navigation = Some(navigation);
        Ok::<_, anyhow::Error>(observation)
    }
    .await;
    match result {
        Ok(observation) => observation,
        Err(error) => Observation::failed(
            "browser",
            None,
            sanitize_text(&format!("{error:#}"), options),
            started.elapsed().as_millis() as u64,
        ),
    }
}

/// Curl writes the body to stdout and bounded JSON metadata to stderr. No body or
/// header capture files can grow unchecked. Redirects are followed here so custom
/// credentials are never forwarded to another origin.
pub async fn probe_curl(
    url: &Url,
    options: &TransportOptions,
    executable: &Path,
    profile: Option<&str>,
) -> Observation {
    let started = Instant::now();
    let result = async {
        validate_external_options(url, options)?;
        let cookies = tempfile::NamedTempFile::new().context("creating isolated curl cookie jar")?;
        let marker = format!("\nFINGERPRINT_LAB_{}\n", uuid::Uuid::new_v4());
        let write_out = format!("%{{stderr}}{marker}{{\"meta\":%{{json}},\"headers\":%{{header_json}}}}");
        let mut current = url.clone();
        let mut redirects = Vec::new();
        loop {
            let remaining = options.timeout.checked_sub(started.elapsed()).context("curl exceeded the whole-probe timeout")?;
            let mut command = Command::new(executable);
            command
                // This must be the first argument to disable every curlrc file.
                .arg("--disable")
                .args(["--silent", "--show-error", "--compressed", "--proto", "=http,https", "--proto-redir", "=http,https", "--max-time"])
                .arg(remaining.as_secs_f64().to_string())
                .arg("--connect-timeout").arg(options.connect_timeout.min(remaining).as_secs_f64().to_string())
                .arg("--max-filesize").arg(PROBE_BODY_LIMIT.to_string())
                .args(["--output", "-", "--write-out"]).arg(&write_out)
                .arg("--cookie").arg(cookies.path())
                .arg("--cookie-jar").arg(cookies.path())
                .stdin(Stdio::null());
            for name in ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"] {
                command.env_remove(name);
            }
            if let Some(profile) = profile { command.arg("--impersonate").arg(profile); }
            if let Some(proxy) = &options.network_proxy {
                command.args(["--noproxy", ""]).arg("--proxy").arg(proxy);
            } else { command.args(["--noproxy", "*"]); }
            if current.origin() == url.origin() {
                for (name, value) in &options.headers {
                    command.arg("--header").arg(format!("{name}: {}", value.to_str().context("curl header values must contain valid text")?));
                }
            }
            command.arg("--url").arg(current.as_str());
            let output = run_command(&mut command, remaining, PROBE_BODY_LIMIT, METADATA_LIMIT)
                .await.context("running curl; use --curl-executable to select an installed curl or curl-impersonate binary")?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let message = stderr.lines().find(|line| line.starts_with("curl:"))
                    .map(|line| sanitize_text(line, options))
                    .unwrap_or_else(|| format!("curl exited with {}", output.status));
                bail!("curl failed: {message}");
            }
            if tokio::fs::metadata(cookies.path()).await?.len() > COOKIE_LIMIT {
                bail!("curl cookie jar exceeded its capture limit");
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            let (_, json) = stderr.rsplit_once(&marker).context("curl must support --write-out %{json}, %{header_json}, and %{stderr}")?;
            let raw: serde_json::Value = serde_json::from_str(json)
                .context("curl returned invalid metadata; %{header_json} requires curl 7.83 or later")?;
            let meta = &raw["meta"];
            let status = meta["http_code"].as_u64().filter(|status| (100..=599).contains(status)).context("missing curl HTTP response status")? as u16;
            let headers = curl_headers(&raw["headers"])?;
            let final_url = validate_url(meta["url_effective"].as_str().unwrap_or(current.as_str()))?;
            if matches!(status, 301 | 302 | 303 | 307 | 308)
                && let Some(location) = headers.get("location") {
                    if redirects.len() >= 10 { bail!("curl exceeded 10 redirects"); }
                    let next = current.join(location).context("invalid curl redirect URL")?;
                    validate_url(next.as_str()).context("curl redirect must use HTTP or HTTPS without credentials")?;
                    redirects.push(format!("HTTP {status}: {} -> {}", redact_url(current.as_str()), redact_url(next.as_str())));
                    current = next;
                    continue;
                }
            let version = match meta["http_version"].as_str().unwrap_or("unknown") {
                "1" | "1.0" => "HTTP/1.0", "1.1" => "HTTP/1.1", "2" | "2.0" => "HTTP/2", "3" => "HTTP/3", _ => "unknown",
            }.to_owned();
            let mut observation = Observation::from_response("curl", profile.map(str::to_owned), ResponseSnapshot {
                status, http_version: version, final_url: final_url.into(), headers,
                body: output.stdout, duration_ms: started.elapsed().as_millis() as u64,
            });
            observation.client_version = meta["curl_version"].as_str().map(str::to_owned);
            observation.notes.extend(redirects);
            return Ok::<_, anyhow::Error>(observation);
        }
    }.await;
    match result {
        Ok(observation) => observation,
        Err(error) => Observation::failed(
            "curl",
            profile.map(str::to_owned),
            sanitize_text(&format!("{error:#}"), options),
            started.elapsed().as_millis() as u64,
        ),
    }
}

fn validate_external_options(url: &Url, options: &TransportOptions) -> Result<()> {
    validate_url(url.as_str())?;
    if options.timeout.is_zero() || options.connect_timeout.is_zero() {
        bail!("request and connect timeouts must be positive");
    }
    if let Some(proxy) = &options.network_proxy {
        validate_network_proxy(proxy)?;
    }
    for (name, value) in &options.headers {
        parse_header(&format!(
            "{name}: {}",
            value
                .to_str()
                .context("header values must contain valid text")?
        ))?;
    }
    Ok(())
}

fn curl_headers(value: &serde_json::Value) -> Result<BTreeMap<String, String>> {
    let object = value
        .as_object()
        .context("curl returned invalid header metadata")?;
    object
        .iter()
        .map(|(name, values)| {
            let values = values
                .as_array()
                .context("curl returned invalid header values")?;
            let values: Result<Vec<_>> = values
                .iter()
                .map(|value| value.as_str().context("curl returned a non-text header"))
                .collect();
            Ok((name.to_ascii_lowercase(), values?.join("\n")))
        })
        .collect()
}

#[derive(Debug)]
struct CapturedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn read_bounded(
    mut reader: impl AsyncRead + Unpin,
    limit: usize,
    label: &str,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let count = reader
            .read(&mut chunk)
            .await
            .context("reading external probe output")?;
        if count == 0 {
            return Ok(output);
        }
        if output.len() + count > limit {
            bail!("{label} exceeded its {limit}-byte capture limit");
        }
        output.extend_from_slice(&chunk[..count]);
    }
}

#[cfg(unix)]
struct ProcessGroup(u32);
#[cfg(unix)]
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        // A cancelled future still gives Node an opportunity to close Chromium.
        unsafe {
            libc::kill(-(self.0 as i32), libc::SIGTERM);
        }
    }
}

async fn run_command(
    command: &mut Command,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<CapturedOutput> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn().context("starting external probe process")?;
    #[cfg(unix)]
    let group = ProcessGroup(child.id().context("missing probe process ID")?);
    let stdout = child.stdout.take().context("missing probe stdout")?;
    let stderr = child.stderr.take().context("missing probe stderr")?;
    // Child::wait closes stdin automatically; retain it until after completion so
    // the browser can notice an actual parent interruption rather than normal wait.
    let parent_pipe = child.stdin.take();
    let result = tokio::select! {
        result = async {
            let (status, stdout, stderr) = tokio::try_join!(
                async { child.wait().await.context("waiting for external probe") },
                read_bounded(stdout, stdout_limit, "probe stdout"),
                read_bounded(stderr, stderr_limit, "probe stderr"),
            )?;
            Ok::<_, anyhow::Error>(CapturedOutput { status, stdout, stderr })
        } => result,
        _ = tokio::time::sleep(timeout) => Err(anyhow::anyhow!("external probe exceeded its timeout")),
        result = interrupted() => Err(anyhow::anyhow!("external probe interrupted{}", if result.is_err() { " (signal listener failed)" } else { "" })),
    };
    drop(parent_pipe);
    if result.is_err() {
        #[cfg(unix)]
        unsafe {
            libc::kill(-(group.0 as i32), libc::SIGTERM);
        }
        if tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .is_err()
        {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(group.0 as i32), libc::SIGKILL);
            }
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }
    result
}

async fn interrupted() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result, _ = terminate.recv() => Ok(()) }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

fn sanitized_error(stderr: &[u8], options: &TransportOptions) -> String {
    let text = String::from_utf8_lossy(stderr);
    let first_line = text
        .lines()
        .next()
        .unwrap_or("no error message was returned");
    sanitize_text(first_line, options)
}

fn sanitize_text(text: &str, options: &TransportOptions) -> String {
    let mut safe = text.to_owned();
    if let Some(input) = &options.network_proxy {
        safe = safe.replace(input, "[network proxy]");
        if let Ok(proxy) = Url::parse(input) {
            for secret in [Some(proxy.username()), proxy.password()] {
                if let Some(secret) = secret.filter(|value| !value.is_empty()) {
                    safe = safe.replace(secret, "[redacted]");
                    let encoded = format!("secret={}", secret.replace('+', "%2B"));
                    if let Some((_, decoded)) =
                        url::form_urlencoded::parse(encoded.as_bytes()).next()
                    {
                        safe = safe.replace(decoded.as_ref(), "[redacted]");
                    }
                }
            }
        }
    }
    safe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curl_headers_keep_repeated_values_without_mixing_responses() {
        let raw = serde_json::json!({"content-type": ["application/json"], "set-cookie": ["a=one", "b=two"]});
        let headers = curl_headers(&raw).unwrap();
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(headers["set-cookie"], "a=one\nb=two");
        assert!(curl_headers(&serde_json::json!({"invalid": "not-an-array"})).is_err());
    }

    #[tokio::test]
    async fn capture_limits_stop_unbounded_external_output() {
        assert_eq!(
            read_bounded(&b"small"[..], 5, "test").await.unwrap(),
            b"small"
        );
        assert!(read_bounded(&b"too large"[..], 5, "test").await.is_err());
    }

    #[test]
    fn proxy_error_text_does_not_echo_credentials() {
        let options = TransportOptions {
            network_proxy: Some("http://user:secret@proxy.example:8080".into()),
            ..Default::default()
        };
        let text = sanitize_text(
            "failed http://user:secret@proxy.example:8080 secret user",
            &options,
        );
        assert!(!text.contains("secret"));
        assert!(!text.contains("user"));
    }

    #[tokio::test]
    async fn curl_follows_http_redirects_and_scopes_credentials() {
        use axum::{Router, extract::State, http::HeaderMap, response::IntoResponse, routing::get};
        use std::sync::{Arc, Mutex};
        if !Command::new("curl")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .is_ok_and(|status| status.success())
        {
            eprintln!("Skipping optional curl integration: curl is not installed");
            return;
        }
        async fn record_headers(
            State(headers): State<Arc<Mutex<Vec<HeaderMap>>>>,
            request: HeaderMap,
        ) -> impl IntoResponse {
            headers.lock().unwrap().push(request);
            (axum::http::StatusCode::FORBIDDEN, "denied")
        }
        let observed = Arc::new(Mutex::new(Vec::<HeaderMap>::new()));
        let destination = Router::new()
            .route("/final", get(record_headers))
            .with_state(observed.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!("http://{}/final", listener.local_addr().unwrap());
        let destination_task = tokio::spawn(async move {
            axum::serve(listener, destination).await.unwrap();
        });
        let source = Router::new()
            .route(
                "/cross",
                get(move || {
                    let target = target.clone();
                    async move {
                        (axum::http::StatusCode::FOUND, [("location", target)]).into_response()
                    }
                }),
            )
            .route(
                "/unsafe",
                get(|| async {
                    (
                        axum::http::StatusCode::FOUND,
                        [("location", "file:///etc/passwd")],
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source_url = format!("http://{}", listener.local_addr().unwrap());
        let source_task = tokio::spawn(async move {
            axum::serve(listener, source).await.unwrap();
        });
        let mut options = TransportOptions::default();
        options
            .headers
            .insert("authorization", "Bearer fixture".parse().unwrap());
        options
            .headers
            .insert("x-api-key", "fixture-key".parse().unwrap());
        options
            .headers
            .insert("cookie", "session=fixture".parse().unwrap());
        let response = probe_curl(
            &Url::parse(&format!("{source_url}/cross")).unwrap(),
            &options,
            Path::new("curl"),
            None,
        )
        .await;
        assert_eq!(response.status, Some(403), "{:?}", response.error);
        assert_eq!(response.outcome, crate::report::Outcome::Denied);
        {
            let headers = observed.lock().unwrap();
            assert_eq!(headers.len(), 1);
            assert!(!headers[0].contains_key("authorization"));
            assert!(!headers[0].contains_key("x-api-key"));
            assert!(!headers[0].contains_key("cookie"));
        }
        let unsafe_response = probe_curl(
            &Url::parse(&format!("{source_url}/unsafe")).unwrap(),
            &options,
            Path::new("curl"),
            None,
        )
        .await;
        assert_eq!(
            unsafe_response.outcome,
            crate::report::Outcome::TransportError
        );
        assert!(unsafe_response.error.unwrap().contains("HTTP or HTTPS"));
        source_task.abort();
        destination_task.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn external_timeout_terminates_a_process_group() {
        let mut command = Command::new("sh");
        command
            .args(["-c", "trap '' TERM; sleep 30"])
            .stdin(Stdio::null());
        let started = Instant::now();
        let result = run_command(&mut command, Duration::from_millis(50), 64, 64).await;
        assert!(result.unwrap_err().to_string().contains("timeout"));
        assert!(started.elapsed() < Duration::from_secs(4));
    }
}
