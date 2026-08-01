use std::collections::BTreeMap;
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const REPORT_SCHEMA_VERSION: u8 = 1;
pub(crate) const CAVEAT: &str = "JA3 can vary between requests when TLS extension order is randomized. Matching fingerprints do not prove the same browser or Cloudflare bypass.";

#[derive(Debug)]
pub struct ResponseSnapshot {
    pub status: u16,
    pub http_version: String,
    pub final_url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Challenge,
    Denied,
    RateLimited,
    HttpError,
    TransportError,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Challenge => "challenge",
            Self::Denied => "denied",
            Self::RateLimited => "rate_limited",
            Self::HttpError => "http_error",
            Self::TransportError => "transport_error",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Fingerprints {
    pub ja3: Option<String>,
    pub ja3_hash: Option<String>,
    pub ja4: Option<String>,
    pub ja4_r: Option<String>,
    pub http2_fingerprint: Option<String>,
    pub tls_version: Option<String>,
    pub user_agent: Option<String>,
    pub raw_tls: Option<Value>,
    pub raw_http2: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserNavigation {
    pub initial_status: Option<u16>,
    pub initial_url: Option<String>,
    pub redirect_chain: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_observed_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_observed_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub client: String,
    pub profile: Option<String>,
    pub client_version: Option<String>,
    pub status: Option<u16>,
    pub http_version: Option<String>,
    pub final_url: Option<String>,
    pub duration_ms: u64,
    pub outcome: Outcome,
    pub fingerprints: Fingerprints,
    pub response_headers: BTreeMap<String, String>,
    pub notes: Vec<String>,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_navigation: Option<BrowserNavigation>,
}

impl Observation {
    pub fn from_response(
        client: &str,
        profile: Option<String>,
        snapshot: ResponseSnapshot,
    ) -> Self {
        let response_headers = safe_response_headers(&snapshot.headers);
        let confirmed_challenge = response_headers
            .get("cf-mitigated")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("challenge"));
        let outcome = if confirmed_challenge {
            Outcome::Challenge
        } else {
            match snapshot.status {
                200..=399 => Outcome::Success,
                401 | 403 => Outcome::Denied,
                429 => Outcome::RateLimited,
                _ => Outcome::HttpError,
            }
        };
        let mut notes = Vec::new();
        let is_fixture = response_headers.contains_key("x-lab-fixture");
        if is_fixture {
            notes.push("This response is a local simulation and is not evidence of real Cloudflare behavior.".into());
        }
        if confirmed_challenge {
            if is_fixture {
                notes.push("The local fixture simulated a Cloudflare challenge using cf-mitigated: challenge.".into());
            } else {
                notes.push("Cloudflare explicitly marked this response as a challenge (cf-mitigated: challenge).".into());
            }
        } else if suspected_challenge(&snapshot.body, &response_headers) {
            notes.push("HTML contains possible challenge markers. This is suspected, not a confirmed Cloudflare challenge.".into());
        }
        if snapshot.status == 403 && !confirmed_challenge {
            notes.push(
                "HTTP 403 means access was denied; it does not identify Cloudflare or the cause."
                    .into(),
            );
        }
        let fingerprints = measured_fingerprints(&snapshot.body);
        if fingerprints.ja3.is_none()
            && fingerprints.ja3_hash.is_none()
            && fingerprints.ja4.is_none()
            && fingerprints.ja4_r.is_none()
            && fingerprints.http2_fingerprint.is_none()
        {
            notes.push("No server-observed JA3, JA4, or HTTP/2 fingerprint was returned. Use a fingerprint measurement endpoint to obtain these values.".into());
        }
        Self {
            client: client.into(),
            profile,
            client_version: None,
            status: Some(snapshot.status),
            http_version: Some(snapshot.http_version),
            final_url: Some(redact_url(&snapshot.final_url)),
            duration_ms: snapshot.duration_ms,
            outcome,
            fingerprints,
            response_headers,
            notes,
            error: None,
            browser_navigation: None,
        }
    }

    pub fn failed(client: &str, profile: Option<String>, error: String, duration_ms: u64) -> Self {
        Self {
            client: client.into(),
            profile,
            client_version: None,
            status: None,
            http_version: None,
            final_url: None,
            duration_ms,
            outcome: Outcome::TransportError,
            fingerprints: Fingerprints::default(),
            response_headers: BTreeMap::new(),
            notes: vec![
                "The request failed before a response was recorded; no fingerprint was measured."
                    .into(),
            ],
            error: Some(redact_text_urls(&error)),
            browser_navigation: None,
        }
    }

    pub(crate) fn label(&self) -> String {
        match &self.profile {
            Some(profile) => format!("{} ({profile})", self.client),
            None => self.client.clone(),
        }
    }

    fn sanitized(mut self) -> Self {
        self.final_url = self.final_url.as_deref().map(redact_url);
        self.error = self.error.as_deref().map(redact_text_urls);
        self.notes = self
            .notes
            .iter()
            .map(|note| redact_text_urls(note))
            .collect();
        self.response_headers = safe_response_headers(&self.response_headers);
        self.fingerprints.raw_tls = self
            .fingerprints
            .raw_tls
            .as_ref()
            .and_then(|value| sanitize_network_json(value, false));
        self.fingerprints.raw_http2 = self
            .fingerprints
            .raw_http2
            .as_ref()
            .and_then(|value| sanitize_network_json(value, true));
        if let Some(navigation) = &mut self.browser_navigation {
            navigation.initial_url = navigation.initial_url.as_deref().map(redact_url);
            navigation.redirect_chain = navigation
                .redirect_chain
                .iter()
                .map(|url| redact_url(url))
                .collect();
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReport {
    pub schema_version: u8,
    pub generated_at_unix: u64,
    pub target_url: String,
    pub observations: Vec<Observation>,
}

impl ProbeReport {
    pub fn new(target_url: String, observations: Vec<Observation>) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            generated_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or_default(),
            target_url: redact_url(&target_url),
            observations: observations
                .into_iter()
                .map(Observation::sanitized)
                .collect(),
        }
    }

    pub fn to_json(&self) -> anyhow::Result<String> {
        self.validate_schema()?;
        Ok(serde_json::to_string_pretty(&self.sanitized())?)
    }

    pub fn validate_schema(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.schema_version == REPORT_SCHEMA_VERSION,
            "unsupported report schema version {}; supported version is {}",
            self.schema_version,
            REPORT_SCHEMA_VERSION
        );
        Ok(())
    }

    /// Reapply header and URL redaction before storage, including imported reports.
    pub fn sanitized(&self) -> Self {
        Self {
            schema_version: self.schema_version,
            generated_at_unix: self.generated_at_unix,
            target_url: redact_url(&self.target_url),
            observations: self
                .observations
                .clone()
                .into_iter()
                .map(Observation::sanitized)
                .collect(),
        }
    }

    pub fn render_text(&self) -> String {
        let mut text = format!("Fingerprint Lab\nTarget: {}\n\n", self.target_url);
        for observation in &self.observations {
            let status = observation
                .status
                .map(|value| value.to_string())
                .unwrap_or_else(|| "no response".into());
            let _ = writeln!(
                text,
                "{}: {} | HTTP {} | {} ms",
                observation.label(),
                observation.outcome.as_str(),
                status,
                observation.duration_ms
            );
            if let Some(version) = &observation.client_version {
                let _ = writeln!(text, "  Client version: {version}");
            }
            for (label, value) in fingerprint_rows(&observation.fingerprints) {
                let _ = writeln!(
                    text,
                    "  {label}: {}",
                    value.as_deref().unwrap_or("not measured")
                );
            }
            if let Some(navigation) = &observation.browser_navigation {
                let status = navigation
                    .initial_status
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "unknown".into());
                let _ = writeln!(
                    text,
                    "  Initial browser response: {status} | {}",
                    navigation.initial_url.as_deref().unwrap_or("unknown")
                );
                if let Some(elapsed) = navigation.initial_observed_at_ms {
                    let _ = writeln!(
                        text,
                        "  Initial response observed at: {elapsed} ms after probe start"
                    );
                }
                if let Some(elapsed) = navigation.final_observed_at_ms {
                    let _ = writeln!(
                        text,
                        "  Final response observed at: {elapsed} ms after probe start"
                    );
                }
                for url in &navigation.redirect_chain {
                    let _ = writeln!(text, "  Navigation: {url}");
                }
            }
            if let Some(error) = &observation.error {
                let _ = writeln!(text, "  Error: {error}");
            }
            for note in &observation.notes {
                let _ = writeln!(text, "  Note: {note}");
            }
            text.push('\n');
        }
        for line in self.comparisons() {
            let _ = writeln!(text, "{line}");
        }
        let _ = writeln!(text, "\n{CAVEAT}");
        text
    }

    pub fn render_html(&self) -> String {
        let mut html = String::from(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Fingerprint Lab report</title><style>\n:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f3f5f5;color:#172b38;font:16px/1.55 system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:40px 24px}h1{font-size:36px;letter-spacing:-1px;margin:0}h2{font-size:21px;margin:0 0 16px}.eyebrow{color:#17695a;font-weight:700;font-size:12px;letter-spacing:2px}.target{overflow-wrap:anywhere;color:#4d626e;margin:8px 0 28px}.card{background:white;border:1px solid #dce4e7;border-radius:12px;padding:24px;margin:18px 0}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:12px;border-bottom:1px solid #e7edef;vertical-align:top}th{color:#4d626e;font-weight:600}tr:last-child td{border:0}.badge{display:inline-block;border-radius:6px;background:#e8f2ef;color:#17695a;padding:3px 8px;font-size:12px;font-weight:700}.denied,.challenge,.rate_limited{background:#fff0d6;color:#8d5700}.http_error,.transport_error{background:#fde7e5;color:#963b35}dl{display:grid;grid-template-columns:150px 1fr;gap:9px 16px;margin:0;font-size:14px}dt{color:#4d626e}dd{margin:0;overflow-wrap:anywhere;font-family:ui-monospace,monospace}.notes{color:#4d626e;font-size:14px;margin:18px 0 0;padding-left:20px}.caveat{background:#e8efed;border-left:3px solid #17695a;padding:16px 20px;font-size:14px}.comparison{overflow-wrap:anywhere;font-size:14px}small{color:#607480}@media(max-width:600px){main{padding:24px 14px}.card{padding:18px}h1{font-size:29px}dl{grid-template-columns:1fr;gap:3px}dd{margin-bottom:10px}}\n</style></head><body><main><div class=\"eyebrow\">NETWORK OBSERVATIONS</div><h1>Fingerprint Lab</h1>",
        );
        let _ = write!(
            html,
            "<p class=\"target\">{}<br><small>Generated at Unix timestamp {} · Schema {}</small></p>",
            escape_html(&self.target_url),
            self.generated_at_unix,
            self.schema_version
        );
        html.push_str("<section class=\"card\"><h2>Request results</h2><div class=\"table-wrap\"><table><thead><tr><th>Client / profile</th><th>Outcome</th><th>Status</th><th>Protocol</th><th>Duration</th></tr></thead><tbody>");
        for observation in &self.observations {
            let status = observation
                .status
                .map(|value| value.to_string())
                .unwrap_or_else(|| "—".into());
            let _ = write!(
                html,
                "<tr><td>{}</td><td><span class=\"badge {}\">{}</span></td><td>{}</td><td>{}</td><td>{} ms</td></tr>",
                escape_html(&observation.label()),
                observation.outcome.as_str(),
                observation.outcome.as_str(),
                escape_html(&status),
                escape_html(observation.http_version.as_deref().unwrap_or("—")),
                observation.duration_ms
            );
        }
        html.push_str("</tbody></table></div></section>");
        for observation in &self.observations {
            let _ = write!(
                html,
                "<section class=\"card\"><h2>{}</h2><dl>",
                escape_html(&observation.label())
            );
            if let Some(version) = &observation.client_version {
                let _ = write!(
                    html,
                    "<dt>Client version</dt><dd>{}</dd>",
                    escape_html(version)
                );
            }
            if let Some(url) = &observation.final_url {
                let _ = write!(html, "<dt>Final URL</dt><dd>{}</dd>", escape_html(url));
            }
            for (label, value) in fingerprint_rows(&observation.fingerprints) {
                let _ = write!(
                    html,
                    "<dt>{}</dt><dd>{}</dd>",
                    escape_html(label),
                    escape_html(value.as_deref().unwrap_or("not measured"))
                );
            }
            if let Some(navigation) = &observation.browser_navigation {
                let status = navigation
                    .initial_status
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "unknown".into());
                let _ = write!(
                    html,
                    "<dt>Initial browser response</dt><dd>{} · {}</dd>",
                    escape_html(&status),
                    escape_html(navigation.initial_url.as_deref().unwrap_or("unknown"))
                );
                if let Some(elapsed) = navigation.initial_observed_at_ms {
                    let _ = write!(
                        html,
                        "<dt>Initial observation</dt><dd>{elapsed} ms after probe start</dd>"
                    );
                }
                if let Some(elapsed) = navigation.final_observed_at_ms {
                    let _ = write!(
                        html,
                        "<dt>Final observation</dt><dd>{elapsed} ms after probe start</dd>"
                    );
                }
                for url in &navigation.redirect_chain {
                    let _ = write!(html, "<dt>Navigation</dt><dd>{}</dd>", escape_html(url));
                }
            }
            html.push_str("</dl>");
            if observation.error.is_some() || !observation.notes.is_empty() {
                html.push_str("<ul class=\"notes\">");
                if let Some(error) = &observation.error {
                    let _ = write!(html, "<li>Error: {}</li>", escape_html(error));
                }
                for note in &observation.notes {
                    let _ = write!(html, "<li>{}</li>", escape_html(note));
                }
                html.push_str("</ul>");
            }
            html.push_str("</section>");
        }
        let comparisons = self.comparisons();
        if !comparisons.is_empty() {
            html.push_str("<section class=\"card\"><h2>Fingerprint comparison</h2>");
            for line in comparisons {
                let _ = write!(html, "<p class=\"comparison\">{}</p>", escape_html(&line));
            }
            html.push_str("</section>");
        }
        let _ = write!(
            html,
            "<p class=\"caveat\">{}</p></main></body></html>",
            escape_html(CAVEAT)
        );
        html
    }

    pub fn comparisons(&self) -> Vec<String> {
        let mut comparisons = Vec::new();
        for (index, left) in self.observations.iter().enumerate() {
            for right in self.observations.iter().skip(index + 1) {
                comparisons.extend(comparison_notes(left, right));
            }
        }
        comparisons
    }
}

fn fingerprint_rows(fingerprints: &Fingerprints) -> [(&str, Option<String>); 7] {
    [
        ("JA3", fingerprints.ja3.clone()),
        ("JA3 hash", fingerprints.ja3_hash.clone()),
        ("JA4", fingerprints.ja4.clone()),
        ("JA4 raw", fingerprints.ja4_r.clone()),
        ("HTTP/2 fingerprint", fingerprints.http2_fingerprint.clone()),
        (
            "TLS version",
            fingerprints.tls_version.as_deref().map(tls_version_display),
        ),
        ("User agent", fingerprints.user_agent.clone()),
    ]
}

pub(crate) fn comparison_notes(left: &Observation, right: &Observation) -> Vec<String> {
    let mut notes = vec![format!(
        "{} compared with {}: JA3 hash {}; JA4 {}; HTTP/2 {}.",
        right.label(),
        left.label(),
        compare_values(&left.fingerprints.ja3_hash, &right.fingerprints.ja3_hash),
        compare_values(&left.fingerprints.ja4, &right.fingerprints.ja4),
        compare_values(
            &left.fingerprints.http2_fingerprint,
            &right.fingerprints.http2_fingerprint
        )
    )];
    for (kind, a, b) in [
        ("Profile", &left.profile, &right.profile),
        (
            "Client version",
            &left.client_version,
            &right.client_version,
        ),
    ] {
        match (a, b) {
            (Some(a), Some(b)) if a != b => notes.push(format!("{kind} mismatch: {} uses {a}; {} uses {b}. Interpret fingerprint differences with this context.", left.label(), right.label())),
            (None, _) | (_, None) => notes.push(format!("{kind} comparison unknown for {} and {}: {} / {}.", left.label(), right.label(), a.as_deref().unwrap_or("unspecified"), b.as_deref().unwrap_or("unspecified"))),
            _ => {}
        }
    }
    for (browser, emulated) in [(left, right), (right, left)] {
        if browser.client == "browser" {
            let browser_major = browser
                .client_version
                .as_deref()
                .and_then(first_version_number);
            let profile_major = emulated.profile.as_deref().and_then(|profile| {
                profile
                    .strip_prefix("chrome_")
                    .or_else(|| profile.strip_prefix("chrome"))
                    .and_then(first_version_number)
            });
            if let (Some(browser_major), Some(profile_major)) = (browser_major, profile_major)
                && browser_major != profile_major
            {
                notes.push(format!("Browser/profile version mismatch: real Chromium {browser_major} versus selected Chrome profile {profile_major}."));
            }
        }
    }
    notes
}

fn first_version_number(value: &str) -> Option<u32> {
    value
        .split(|character: char| !character.is_ascii_digit())
        .find(|piece| !piece.is_empty())?
        .parse()
        .ok()
}

fn tls_version_display(value: &str) -> String {
    let label = match value {
        "768" | "0x0300" => Some("SSL 3.0"),
        "769" | "0x0301" => Some("TLS 1.0"),
        "770" | "0x0302" => Some("TLS 1.1"),
        "771" | "0x0303" => Some("TLS 1.2"),
        "772" | "0x0304" => Some("TLS 1.3"),
        _ => None,
    };
    label
        .map(|label| format!("{label} ({value})"))
        .unwrap_or_else(|| value.into())
}

fn compare_values(left: &Option<String>, right: &Option<String>) -> &'static str {
    match (left, right) {
        (Some(left), Some(right)) if left == right => "matches",
        (Some(_), Some(_)) => "differs",
        (None, None) => "not measured for both clients",
        _ => "unknown: missing for one client",
    }
}

fn measured_fingerprints(body: &[u8]) -> Fingerprints {
    let Ok(root) = serde_json::from_slice::<Value>(body) else {
        return Fingerprints::default();
    };
    let tls = root.get("tls").filter(|value| value.is_object());
    let http2 = root.get("http2").filter(|value| value.is_object());
    Fingerprints {
        ja3: scalar(tls.and_then(|value| value.get("ja3"))),
        ja3_hash: scalar(tls.and_then(|value| value.get("ja3_hash"))),
        ja4: scalar(tls.and_then(|value| value.get("ja4"))),
        ja4_r: scalar(tls.and_then(|value| value.get("ja4_r"))),
        http2_fingerprint: scalar(http2.and_then(|value| value.get("akamai_fingerprint"))),
        tls_version: tls.and_then(|value| {
            ["version", "tls_version_negotiated", "tls_version_record"]
                .iter()
                .find_map(|key| scalar(value.get(*key)))
        }),
        user_agent: scalar(root.get("user_agent")),
        raw_tls: tls.and_then(|value| sanitize_network_json(value, false)),
        raw_http2: http2.and_then(|value| sanitize_network_json(value, true)),
    }
}

fn scalar(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn safe_response_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            let name = name.to_ascii_lowercase();
            matches!(
                name.as_str(),
                "content-type"
                    | "content-encoding"
                    | "content-length"
                    | "server"
                    | "cf-ray"
                    | "cf-mitigated"
                    | "cache-control"
                    | "date"
                    | "retry-after"
                    | "alt-svc"
                    | "vary"
                    | "strict-transport-security"
                    | "x-content-type-options"
                    | "x-lab-fixture"
            )
            .then(|| (name, value.clone()))
        })
        .collect()
}

fn suspected_challenge(body: &[u8], headers: &BTreeMap<String, String>) -> bool {
    let prefix = String::from_utf8_lossy(&body[..body.len().min(65_536)]).to_ascii_lowercase();
    let is_html = headers
        .get("content-type")
        .is_some_and(|value| value.to_ascii_lowercase().contains("text/html"))
        || prefix.contains("<html")
        || prefix.contains("<!doctype html");
    is_html
        && [
            "cf-chl-",
            "/cdn-cgi/challenge-platform/",
            "just a moment...",
        ]
        .iter()
        .any(|marker| prefix.contains(marker))
}

// Measurement endpoints can echo request headers inside HTTP/2 HEADERS frames.
// Keep transport metadata, but never persist credentials or application bodies.
fn sanitize_network_json(value: &Value, http2: bool) -> Option<Value> {
    match value {
        Value::Object(object) => {
            if http2
                && object
                    .get("frame_type")
                    .or_else(|| object.get("type"))
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("DATA"))
            {
                return None;
            }
            let mut sanitized = serde_json::Map::new();
            for (key, value) in object {
                let name = key.to_ascii_lowercase();
                if sensitive_key(&name) || (http2 && name == "data") {
                    continue;
                }
                let clean = if name == "headers" {
                    sanitize_request_headers(value)
                } else {
                    sanitize_network_json(value, http2)
                };
                if let Some(clean) = clean {
                    sanitized.insert(key.clone(), clean);
                }
            }
            Some(Value::Object(sanitized))
        }
        Value::Array(array) => Some(Value::Array(
            array
                .iter()
                .filter_map(|item| sanitize_network_json(item, http2))
                .collect(),
        )),
        Value::String(text) if header_name(text).is_some_and(|name| sensitive_key(&name)) => None,
        _ => Some(value.clone()),
    }
}

fn sensitive_key(name: &str) -> bool {
    matches!(
        name,
        "cookie"
            | "cookies"
            | "set-cookie"
            | "authorization"
            | "proxy-authorization"
            | "password"
            | "token"
            | "access_token"
            | "refresh_token"
            | "body"
            | "request_body"
            | "response_body"
            | "payload"
    )
}

fn safe_request_header(name: &str) -> bool {
    matches!(
        name,
        ":method"
            | ":scheme"
            | ":authority"
            | ":path"
            | "user-agent"
            | "accept"
            | "accept-encoding"
            | "accept-language"
            | "priority"
    ) || name.starts_with("sec-ch-ua")
        || name.starts_with("sec-fetch-")
}

fn header_name(header: &str) -> Option<String> {
    if let Some(rest) = header.strip_prefix(':') {
        rest.split_once(':')
            .map(|(name, _)| format!(":{}", name.trim().to_ascii_lowercase()))
    } else {
        header
            .split_once(':')
            .map(|(name, _)| name.trim().to_ascii_lowercase())
    }
}

fn sanitize_request_headers(value: &Value) -> Option<Value> {
    match value {
        Value::Array(array) => Some(Value::Array(
            array
                .iter()
                .filter_map(|value| {
                    let header = value.as_str()?;
                    let name = header_name(header)?;
                    if !safe_request_header(&name) {
                        return None;
                    }
                    let header = if name == ":path" {
                        format!(
                            ":path: {}",
                            redact_url(header.strip_prefix(':')?.split_once(':')?.1.trim())
                        )
                    } else {
                        header.into()
                    };
                    Some(Value::String(header))
                })
                .collect(),
        )),
        Value::Object(object) => Some(Value::Object(
            object
                .iter()
                .filter_map(|(key, value)| {
                    let name = key.to_ascii_lowercase();
                    if !safe_request_header(&name) {
                        return None;
                    }
                    let text = value.as_str()?;
                    Some((
                        key.clone(),
                        Value::String(if name == ":path" {
                            redact_url(text)
                        } else {
                            text.into()
                        }),
                    ))
                })
                .collect(),
        )),
        _ => None,
    }
}

/// Remove URL userinfo and redact query parameters whose names suggest credentials.
/// Safe parameters remain available for diagnostics. Arbitrary secret values under
/// otherwise innocuous parameter names cannot be identified automatically.
pub fn redact_url(input: &str) -> String {
    if input.starts_with("//") {
        let redacted = redact_url(&format!("https:{input}"));
        return redacted.strip_prefix("https:").unwrap_or(&redacted).into();
    }
    if let Ok(mut url) = Url::parse(input) {
        let _ = url.set_username("");
        let _ = url.set_password(None);
        if let Some(query) = url.query().map(str::to_owned) {
            url.set_query(Some(&redact_query(&query)));
        }
        if url
            .fragment()
            .is_some_and(|fragment| fragment.contains('='))
        {
            let fragment = redact_query(url.fragment().unwrap_or_default());
            url.set_fragment(Some(&fragment));
        }
        return url.to_string();
    }
    // HTTP/2 :path is a relative URL, so preserve its path and safe query values.
    let (base, fragment) = input
        .split_once('#')
        .map_or((input, None), |(base, fragment)| (base, Some(fragment)));
    let mut redacted = base.split_once('?').map_or_else(
        || base.to_owned(),
        |(path, query)| format!("{path}?{}", redact_query(query)),
    );
    if let Some(fragment) = fragment {
        redacted.push('#');
        redacted.push_str(&redact_query(fragment));
    }
    redacted
}

fn redact_query(query: &str) -> String {
    let pairs: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
    if !pairs.iter().any(|(name, _)| credential_parameter(name)) {
        return query.into();
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(
            &name,
            if credential_parameter(&name) {
                "[REDACTED]"
            } else {
                &value
            },
        );
    }
    serializer.finish()
}

fn credential_parameter(name: &str) -> bool {
    let name: String = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    matches!(
        name.as_str(),
        "key"
            | "apikey"
            | "password"
            | "passwd"
            | "secret"
            | "auth"
            | "authorization"
            | "signature"
            | "sig"
            | "code"
            | "credential"
            | "credentials"
            | "session"
            | "sessionid"
            | "jwt"
    ) || name.contains("token")
        || name.contains("secret")
        || name.contains("password")
        || name.ends_with("apikey")
        || name.ends_with("signature")
        || name.ends_with("credential")
}

fn redact_text_urls(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut remaining = input;
    loop {
        let start = ["https://", "http://", "wss://", "ws://"]
            .iter()
            .filter_map(|prefix| remaining.find(prefix))
            .min();
        let Some(start) = start else {
            result.push_str(remaining);
            break;
        };
        result.push_str(&remaining[..start]);
        remaining = &remaining[start..];
        let end = remaining
            .find(|character: char| {
                character.is_whitespace() || matches!(character, ')' | '"' | '\'' | '<' | '>')
            })
            .unwrap_or(remaining.len());
        result.push_str(&redact_url(&remaining[..end]));
        remaining = &remaining[end..];
    }
    result
}

pub(crate) fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snapshot(status: u16, body: Vec<u8>) -> ResponseSnapshot {
        ResponseSnapshot {
            status,
            http_version: "HTTP/2".into(),
            final_url: "https://tls.peet.ws/api/all".into(),
            headers: BTreeMap::new(),
            body,
            duration_ms: 42,
        }
    }

    #[test]
    fn extracts_server_observed_fingerprints_and_transport_metadata() {
        let body = json!({
            "user_agent": "Observed browser",
            "tls": {"ja3": "771,4865,0,29,0", "ja3_hash": "observed-ja3", "ja4": "observed-ja4", "ja4_r": "raw-ja4", "tls_version_negotiated": "772"},
            "http2": {"akamai_fingerprint": "1:65536|0|0|m,a,s,p", "sent_frames": [{"frame_type": "SETTINGS", "settings": ["INITIAL_WINDOW_SIZE = 65535"]}]}
        });
        let observation = Observation::from_response(
            "wreq",
            Some("Chrome".into()),
            snapshot(200, serde_json::to_vec(&body).unwrap()),
        );
        let fingerprints = &observation.fingerprints;
        assert_eq!(fingerprints.ja3.as_deref(), Some("771,4865,0,29,0"));
        assert_eq!(fingerprints.ja3_hash.as_deref(), Some("observed-ja3"));
        assert_eq!(fingerprints.ja4.as_deref(), Some("observed-ja4"));
        assert_eq!(fingerprints.ja4_r.as_deref(), Some("raw-ja4"));
        assert_eq!(fingerprints.tls_version.as_deref(), Some("772"));
        assert_eq!(fingerprints.user_agent.as_deref(), Some("Observed browser"));
        assert_eq!(
            fingerprints.http2_fingerprint.as_deref(),
            Some("1:65536|0|0|m,a,s,p")
        );
        assert_eq!(
            fingerprints.raw_http2.as_ref().unwrap()["sent_frames"][0]["frame_type"],
            "SETTINGS"
        );
        assert_eq!(observation.outcome, Outcome::Success);
        assert!(observation.notes.is_empty());
    }

    #[test]
    fn missing_measurements_remain_none_without_guessed_browser_values() {
        let observation = Observation::from_response(
            "wreq",
            Some("Chrome".into()),
            snapshot(200, b"{\"user_agent\":\"Chrome\"}".to_vec()),
        );
        assert!(observation.fingerprints.ja3.is_none());
        assert!(observation.fingerprints.ja3_hash.is_none());
        assert!(observation.fingerprints.ja4.is_none());
        assert!(observation.fingerprints.raw_tls.is_none());
        assert!(
            observation
                .notes
                .iter()
                .any(|note| note.contains("No server-observed"))
        );
    }

    #[test]
    fn explicit_cloudflare_challenge_overrides_success_status() {
        let mut response = snapshot(200, b"challenge".to_vec());
        response
            .headers
            .insert("CF-Mitigated".into(), "Challenge".into());
        let observation = Observation::from_response("reqwest", None, response);
        assert_eq!(observation.outcome, Outcome::Challenge);
        assert!(
            observation
                .notes
                .iter()
                .any(|note| note.contains("explicitly marked"))
        );
    }

    #[test]
    fn fixture_responses_are_explicitly_labeled_as_simulations() {
        for challenged in [false, true] {
            let mut response = snapshot(200, Vec::new());
            response
                .headers
                .insert("X-Lab-Fixture".into(), "local-test".into());
            if challenged {
                response
                    .headers
                    .insert("cf-mitigated".into(), "challenge".into());
            }
            let observation = Observation::from_response("wreq", None, response);
            assert_eq!(
                observation
                    .response_headers
                    .get("x-lab-fixture")
                    .map(String::as_str),
                Some("local-test")
            );
            assert_eq!(
                observation.outcome,
                if challenged {
                    Outcome::Challenge
                } else {
                    Outcome::Success
                }
            );
            assert!(observation.notes.iter().any(|note| {
                note.contains("local simulation")
                    && note.contains("not evidence of real Cloudflare behavior")
            }));
            assert!(
                !observation
                    .notes
                    .iter()
                    .any(|note| note.contains("Cloudflare explicitly marked"))
            );
            if challenged {
                assert!(
                    observation
                        .notes
                        .iter()
                        .any(|note| note.contains("simulated a Cloudflare challenge"))
                );
            }
        }
    }

    #[test]
    fn forbidden_and_cloudflare_server_header_do_not_prove_a_challenge() {
        let mut response = snapshot(403, b"<html>Access denied</html>".to_vec());
        response
            .headers
            .insert("server".into(), "cloudflare".into());
        let observation = Observation::from_response("reqwest", None, response);
        assert_eq!(observation.outcome, Outcome::Denied);
        assert!(
            observation
                .notes
                .iter()
                .any(|note| note.contains("does not identify Cloudflare"))
        );
        assert!(
            !observation
                .notes
                .iter()
                .any(|note| note.contains("explicitly marked"))
        );
    }

    #[test]
    fn html_markers_are_only_suspected_and_rate_limiting_is_distinct() {
        let observation = Observation::from_response(
            "reqwest",
            None,
            snapshot(
                429,
                b"<html><script src='/cdn-cgi/challenge-platform/test'></script></html>".to_vec(),
            ),
        );
        assert_eq!(observation.outcome, Outcome::RateLimited);
        assert!(
            observation
                .notes
                .iter()
                .any(|note| note.contains("suspected, not a confirmed"))
        );
    }

    #[test]
    fn reports_exclude_credentials_and_application_bodies() {
        let body = json!({
            "body": "TOP-LEVEL-BODY-SECRET",
            "tls": {"ja3_hash": "observed", "authorization": "TLS-AUTH-SECRET"},
            "http2": {"akamai_fingerprint": "measured", "sent_frames": [
                {"frame_type": "HEADERS", "headers": [":method: GET", "user-agent: browser", "cookie: COOKIE-SECRET", "Authorization: AUTH-SECRET", "x-api-key: API-SECRET", ":path: /?token=PATH-SECRET"]},
                {"frame_type": "DATA", "data": "FRAME-BODY-SECRET"}
            ]}
        });
        let mut response = snapshot(200, serde_json::to_vec(&body).unwrap());
        response
            .headers
            .insert("Set-Cookie".into(), "RESPONSE-COOKIE-SECRET".into());
        response
            .headers
            .insert("Authorization".into(), "RESPONSE-AUTH-SECRET".into());
        response
            .headers
            .insert("x-secret".into(), "CUSTOM-SECRET".into());
        response
            .headers
            .insert("Content-Type".into(), "application/json".into());
        let observation = Observation::from_response("reqwest", None, response);
        assert_eq!(observation.response_headers.len(), 1);
        let report = ProbeReport::new("https://tls.peet.ws/api/all".into(), vec![observation]);
        for rendered in [
            report.to_json().unwrap(),
            report.render_text(),
            report.render_html(),
        ] {
            assert!(!rendered.contains("SECRET"), "Leaked data: {rendered}");
        }
        assert!(report.to_json().unwrap().contains("user-agent: browser"));
    }

    #[test]
    fn html_escapes_every_user_supplied_field() {
        let injection = "<script>alert('x')</script>\"&";
        let mut observation =
            Observation::failed(injection, Some(injection.into()), injection.into(), 12);
        observation.client_version = Some(injection.into());
        observation.final_url = Some(injection.into());
        observation.http_version = Some(injection.into());
        observation.fingerprints.ja3 = Some(injection.into());
        observation.notes.push(injection.into());
        let report = ProbeReport::new(injection.into(), vec![observation]);
        let html = report.render_html();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&quot;&amp;"));
    }

    #[test]
    fn comparisons_distinguish_missing_matching_and_different_values() {
        let mut first = Observation::from_response("reqwest", None, snapshot(200, Vec::new()));
        first.fingerprints.ja3_hash = Some("baseline".into());
        first.fingerprints.ja4 = Some("same".into());
        let mut second = Observation::from_response("wreq", None, snapshot(200, Vec::new()));
        second.fingerprints.ja3_hash = Some("other".into());
        second.fingerprints.ja4 = Some("same".into());
        let report = ProbeReport::new("https://example.test".into(), vec![first, second]);
        let text = report.render_text();
        assert!(
            text.contains("JA3 hash differs; JA4 matches; HTTP/2 not measured for both clients")
        );
        assert!(text.contains("TLS extension order is randomized"));
        assert!(
            report
                .render_html()
                .contains("Matching fingerprints do not prove")
        );
        let json: Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["observations"][0]["outcome"], "success");
    }

    #[test]
    fn report_round_trip_accepts_existing_schema_without_navigation_metadata() {
        let report = ProbeReport::new(
            "https://example.com/".into(),
            vec![Observation::failed(
                "browser",
                None,
                "network error".into(),
                10,
            )],
        );
        let json = report.to_json().unwrap();
        assert!(!json.contains("browser_navigation"));
        let restored: ProbeReport = serde_json::from_str(&json).unwrap();
        assert!(restored.observations[0].browser_navigation.is_none());
        assert_eq!(restored.to_json().unwrap(), json);
        let mut unsupported = restored;
        unsupported.schema_version = 0;
        assert!(unsupported.validate_schema().is_err());
        assert!(unsupported.to_json().is_err());
    }

    #[test]
    fn compares_every_pair_with_version_and_profile_context() {
        let mut a = Observation::failed("reqwest", None, "network".into(), 10);
        a.client_version = Some("0.12".into());
        let mut b = Observation::failed("wreq", Some("chrome_150".into()), "network".into(), 10);
        b.client_version = Some("wreq 0.16.1".into());
        let mut c = Observation::failed("browser", None, "network".into(), 10);
        c.client_version = Some("149.0.0.0".into());
        let report = ProbeReport::new("https://example.com/".into(), vec![a, b, c]);
        let comparisons = report.comparisons();
        assert_eq!(
            comparisons
                .iter()
                .filter(|line| line.contains("compared with"))
                .count(),
            3
        );
        assert!(
            comparisons
                .iter()
                .any(|line| line.contains("Client version mismatch"))
        );
        assert!(
            comparisons
                .iter()
                .any(|line| line.contains("real Chromium 149 versus selected Chrome profile 150"))
        );
    }

    #[test]
    fn human_tls_labels_preserve_measured_protocol_number_in_json() {
        let mut observation = Observation::failed("wreq", None, "network".into(), 1);
        observation.fingerprints.tls_version = Some("772".into());
        let report = ProbeReport::new("https://example.com/".into(), vec![observation]);
        assert!(report.render_text().contains("TLS 1.3 (772)"));
        assert!(report.render_html().contains("TLS 1.3 (772)"));
        let json: Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        assert_eq!(
            json["observations"][0]["fingerprints"]["tls_version"],
            "772"
        );
    }

    #[test]
    fn url_and_embedded_error_redaction_keep_safe_diagnostic_parameters() {
        let input = "https://user:USERINFO-SECRET@example.com/path?api_key=KEY-SECRET&access_token=TOKEN-SECRET&q=safe&code=CODE-SECRET#secret=FRAGMENT-SECRET";
        let redacted = redact_url(input);
        assert!(!redacted.contains("SECRET"));
        assert!(redacted.contains("q=safe"));
        assert!(!redacted.contains("user:"));
        let observation =
            Observation::failed("reqwest", None, format!("request failed for ({input})"), 10);
        assert!(!observation.error.unwrap().contains("SECRET"));
        assert!(!redact_url("//user:pass@example.com/?token=SECRET").contains("pass"));
    }

    #[test]
    fn imported_navigation_and_http2_paths_are_sanitized_before_serialization() {
        let mut observation = Observation::failed("browser", None, "network".into(), 1);
        observation.browser_navigation = Some(BrowserNavigation {
            initial_status: Some(302),
            initial_url: Some("https://example.com/?token=INITIAL-SECRET&q=keep".into()),
            redirect_chain: vec!["https://example.com/?code=REDIRECT-SECRET".into()],
            initial_observed_at_ms: Some(15),
            final_observed_at_ms: Some(120),
        });
        observation.fingerprints.raw_http2 = Some(
            json!({"sent_frames": [{"frame_type": "HEADERS", "headers": [":path: /api?token=PATH-SECRET&q=keep", "cookie: COOKIE-SECRET"]}]}),
        );
        observation
            .response_headers
            .insert("set-cookie".into(), "IMPORTED-SECRET".into());
        let report = ProbeReport::new("https://example.com/".into(), vec![observation]);
        let json = report.to_json().unwrap();
        assert!(!json.contains("SECRET"));
        assert!(json.contains("q=keep"));
        assert!(json.contains("browser_navigation"));
        assert!(report.render_html().contains("Initial browser response"));
        assert!(
            report
                .render_text()
                .contains("Final response observed at: 120 ms after probe start")
        );
        assert!(report.render_html().contains("15 ms after probe start"));
    }
}
