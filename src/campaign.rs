use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::report::{CAVEAT, Observation, ProbeReport, comparison_notes, escape_html, redact_url};

pub const CAMPAIGN_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignReport {
    pub schema_version: u8,
    pub target_url: String,
    pub started_at_unix: u64,
    pub runs: Vec<ProbeReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DurationSummary {
    pub min: u64,
    pub median: f64,
    pub max: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintConsistency {
    Unknown,
    SingleSample,
    Consistent,
    Inconsistent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FingerprintSummary {
    pub unique: Vec<String>,
    pub measured: usize,
    pub missing: usize,
    pub consistency: FingerprintConsistency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSummary {
    pub client: String,
    pub profile: Option<String>,
    pub client_version: Option<String>,
    pub observations: usize,
    pub outcomes: BTreeMap<String, usize>,
    pub duration_ms: DurationSummary,
    pub ja3: FingerprintSummary,
    pub ja3_hash: FingerprintSummary,
    pub ja4: FingerprintSummary,
    pub http2: FingerprintSummary,
}

impl CampaignReport {
    pub fn new(target_url: String, runs: Vec<ProbeReport>) -> Self {
        let started_at_unix = runs
            .iter()
            .map(|run| run.generated_at_unix)
            .min()
            .unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs())
                    .unwrap_or_default()
            });
        Self {
            schema_version: CAMPAIGN_SCHEMA_VERSION,
            target_url: redact_url(&target_url),
            started_at_unix,
            runs: runs.iter().map(ProbeReport::sanitized).collect(),
        }
    }

    pub fn to_json(&self) -> Result<String> {
        ensure!(
            self.schema_version == CAMPAIGN_SCHEMA_VERSION,
            "unsupported campaign schema version {}",
            self.schema_version
        );
        for run in &self.runs {
            run.validate_schema()?;
            ensure!(
                redact_url(&run.target_url) == redact_url(&self.target_url),
                "campaign contains a run for a different target"
            );
        }
        let sanitized = Self {
            schema_version: self.schema_version,
            target_url: redact_url(&self.target_url),
            started_at_unix: self.started_at_unix,
            runs: self.runs.iter().map(ProbeReport::sanitized).collect(),
        };
        let mut json = serde_json::to_value(&sanitized)?;
        json["summaries"] = serde_json::to_value(sanitized.summaries())?;
        json["browser_comparisons"] = serde_json::to_value(sanitized.browser_comparisons())?;
        Ok(serde_json::to_string_pretty(&json)?)
    }

    /// Version/profile changes form separate groups instead of creating false
    /// fingerprint inconsistency within a single client configuration.
    pub fn summaries(&self) -> Vec<ClientSummary> {
        type GroupKey = (String, Option<String>, Option<String>);
        let mut groups: BTreeMap<GroupKey, Vec<&Observation>> = BTreeMap::new();
        for observation in self.runs.iter().flat_map(|run| &run.observations) {
            groups
                .entry((
                    observation.client.clone(),
                    observation.profile.clone(),
                    observation.client_version.clone(),
                ))
                .or_default()
                .push(observation);
        }
        groups
            .into_iter()
            .map(|((client, profile, client_version), observations)| {
                let mut outcomes = BTreeMap::new();
                let mut durations = Vec::with_capacity(observations.len());
                for observation in &observations {
                    *outcomes
                        .entry(observation.outcome.as_str().into())
                        .or_insert(0) += 1;
                    durations.push(observation.duration_ms);
                }
                durations.sort_unstable();
                let midpoint = durations.len() / 2;
                let median = if durations.len() % 2 == 0 {
                    durations[midpoint - 1] as f64 / 2.0 + durations[midpoint] as f64 / 2.0
                } else {
                    durations[midpoint] as f64
                };
                ClientSummary {
                    client,
                    profile,
                    client_version,
                    observations: observations.len(),
                    outcomes,
                    duration_ms: DurationSummary {
                        min: durations[0],
                        median,
                        max: durations[durations.len() - 1],
                    },
                    ja3: summarize_fingerprints(
                        observations
                            .iter()
                            .map(|observation| observation.fingerprints.ja3.as_deref()),
                    ),
                    ja3_hash: summarize_fingerprints(
                        observations
                            .iter()
                            .map(|observation| observation.fingerprints.ja3_hash.as_deref()),
                    ),
                    ja4: summarize_fingerprints(
                        observations
                            .iter()
                            .map(|observation| observation.fingerprints.ja4.as_deref()),
                    ),
                    http2: summarize_fingerprints(
                        observations.iter().map(|observation| {
                            observation.fingerprints.http2_fingerprint.as_deref()
                        }),
                    ),
                }
            })
            .collect()
    }

    pub fn render_text(&self) -> String {
        let mut text = format!(
            "Fingerprint Lab campaign\nTarget: {}\nRuns: {}\nStarted at Unix timestamp: {}\n\n",
            self.target_url,
            self.runs.len(),
            self.started_at_unix
        );
        for summary in self.summaries() {
            let _ = writeln!(
                text,
                "{} | profile: {} | version: {} | {} observations",
                summary.client,
                summary.profile.as_deref().unwrap_or("unspecified"),
                summary.client_version.as_deref().unwrap_or("unknown"),
                summary.observations
            );
            let _ = writeln!(text, "  Outcomes: {}", outcome_text(&summary.outcomes));
            let _ = writeln!(
                text,
                "  Duration ms: min {}, median {}, max {}",
                summary.duration_ms.min, summary.duration_ms.median, summary.duration_ms.max
            );
            for (name, fingerprint) in summary.fingerprint_rows() {
                let _ = writeln!(text, "  {name}: {}", fingerprint_text(fingerprint));
                for value in &fingerprint.unique {
                    let _ = writeln!(text, "    {value}");
                }
            }
            text.push('\n');
        }
        for note in self.context_notes() {
            let _ = writeln!(text, "Note: {note}");
        }
        for line in self.browser_comparisons() {
            let _ = writeln!(text, "{line}");
        }
        let _ = writeln!(text, "\n{CAVEAT}");
        text
    }

    pub fn render_html(&self) -> String {
        let mut html = String::from(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Fingerprint Lab campaign</title><style>body{margin:0;background:#f3f5f5;color:#172b38;font:16px/1.55 system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:32px 20px}h1{margin:0}h2{font-size:21px;margin:0 0 12px}.card{background:white;border:1px solid #dce4e7;border-radius:12px;padding:22px;margin:20px 0}.target,code,li{overflow-wrap:anywhere}.muted{color:#526874}.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:10px;border-bottom:1px solid #e7edef;vertical-align:top}code{font-size:12px;white-space:normal}.caveat{border-left:3px solid #17695a;background:#e8efed;padding:16px}.comparison{font-size:14px}</style></head><body><main><h1>Fingerprint Lab campaign</h1>",
        );
        let _ = write!(
            html,
            "<p class=\"target muted\">{}<br>{} runs · Started at Unix timestamp {}</p>",
            escape_html(&self.target_url),
            self.runs.len(),
            self.started_at_unix
        );
        for summary in self.summaries() {
            let _ = write!(
                html,
                "<section class=\"card\"><h2>{}</h2><p class=\"muted\">Profile: {} · Version: {} · {} observations</p><p>Outcomes: {}<br>Duration ms: min {}, median {}, max {}</p><div class=\"scroll\"><table><thead><tr><th>Fingerprint</th><th>Consistency / coverage</th><th>Observed values</th></tr></thead><tbody>",
                escape_html(&summary.client),
                escape_html(summary.profile.as_deref().unwrap_or("unspecified")),
                escape_html(summary.client_version.as_deref().unwrap_or("unknown")),
                summary.observations,
                escape_html(&outcome_text(&summary.outcomes)),
                summary.duration_ms.min,
                summary.duration_ms.median,
                summary.duration_ms.max
            );
            for (name, fingerprint) in summary.fingerprint_rows() {
                let _ = write!(
                    html,
                    "<tr><td>{}</td><td>{}</td><td>",
                    escape_html(name),
                    escape_html(&fingerprint_text(fingerprint))
                );
                for value in &fingerprint.unique {
                    let _ = write!(html, "<code>{}</code><br>", escape_html(value));
                }
                html.push_str("</td></tr>");
            }
            html.push_str("</tbody></table></div></section>");
        }
        html.push_str("<section class=\"card\"><h2>Interpretation</h2><ul>");
        for note in self.context_notes() {
            let _ = write!(html, "<li>{}</li>", escape_html(&note));
        }
        html.push_str("</ul></section>");
        let comparisons = self.browser_comparisons();
        if !comparisons.is_empty() {
            html.push_str("<section class=\"card\"><h2>Real browser comparisons</h2>");
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

    pub fn browser_comparisons(&self) -> Vec<String> {
        let mut comparisons = Vec::new();
        for (index, run) in self.runs.iter().enumerate() {
            for browser in run
                .observations
                .iter()
                .filter(|observation| observation.client == "browser")
            {
                for other in run
                    .observations
                    .iter()
                    .filter(|observation| observation.client != "browser")
                {
                    comparisons.extend(
                        comparison_notes(browser, other)
                            .into_iter()
                            .map(|note| format!("Run {}: {note}", index + 1)),
                    );
                }
            }
        }
        comparisons
    }

    fn context_notes(&self) -> Vec<String> {
        let mut notes = vec!["Unknown means no fingerprint was measured. A single sample cannot establish consistency. Inconsistent means multiple distinct measured values, not missing measurements.".into(), "Statistics include failed request durations. Client/profile/version combinations are reported separately.".into()];
        type Configuration<'a> = (&'a Option<String>, &'a Option<String>);
        let mut configurations: BTreeMap<&str, BTreeSet<Configuration<'_>>> = BTreeMap::new();
        let mut browser_seen = false;
        let mut browser_response_seen = false;
        let mut simulated = false;
        for observation in self.runs.iter().flat_map(|run| &run.observations) {
            configurations
                .entry(&observation.client)
                .or_default()
                .insert((&observation.profile, &observation.client_version));
            browser_seen |= observation.client == "browser";
            browser_response_seen |=
                observation.client == "browser" && observation.status.is_some();
            simulated |= observation.response_headers.contains_key("x-lab-fixture");
        }
        for (client, configurations) in configurations {
            if configurations.len() > 1 {
                notes.push(format!("{client} changed profile or version during this campaign; its configurations are separate groups."));
            }
        }
        if !browser_seen {
            notes.push("No real browser was included; browser equivalence is unknown.".into());
        } else if !browser_response_seen {
            notes.push("The browser adapter was requested, but no browser HTTP response was recorded; browser equivalence remains unknown.".into());
        }
        if simulated {
            notes.push("This campaign includes local simulations. Those responses are not evidence of real Cloudflare behavior.".into());
        }
        notes
    }
}

impl ClientSummary {
    fn fingerprint_rows(&self) -> [(&str, &FingerprintSummary); 4] {
        [
            ("JA3", &self.ja3),
            ("JA3 hash", &self.ja3_hash),
            ("JA4", &self.ja4),
            ("HTTP/2", &self.http2),
        ]
    }
}

fn summarize_fingerprints<'a>(values: impl Iterator<Item = Option<&'a str>>) -> FingerprintSummary {
    let mut unique = BTreeSet::new();
    let mut measured = 0;
    let mut missing = 0;
    for value in values {
        match value.filter(|value| !value.is_empty()) {
            Some(value) => {
                measured += 1;
                unique.insert(value.to_owned());
            }
            None => missing += 1,
        }
    }
    let consistency = if measured == 0 {
        FingerprintConsistency::Unknown
    } else if unique.len() > 1 {
        FingerprintConsistency::Inconsistent
    } else if measured == 1 {
        FingerprintConsistency::SingleSample
    } else {
        FingerprintConsistency::Consistent
    };
    FingerprintSummary {
        unique: unique.into_iter().collect(),
        measured,
        missing,
        consistency,
    }
}

fn fingerprint_text(summary: &FingerprintSummary) -> String {
    let consistency = match summary.consistency {
        FingerprintConsistency::Unknown => "unknown",
        FingerprintConsistency::SingleSample => "single sample",
        FingerprintConsistency::Consistent => "consistent among measured samples",
        FingerprintConsistency::Inconsistent => "inconsistent measured values",
    };
    format!(
        "{consistency}; {} unique, {} measured, {} missing",
        summary.unique.len(),
        summary.measured,
        summary.missing
    )
}

fn outcome_text(outcomes: &BTreeMap<String, usize>) -> String {
    outcomes
        .iter()
        .map(|(outcome, count)| format!("{outcome}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Outcome;

    fn observation(duration_ms: u64, ja3: Option<&str>, ja4: Option<&str>) -> Observation {
        let mut observation = Observation::failed(
            "wreq",
            Some("chrome_149".into()),
            "network error".into(),
            duration_ms,
        );
        observation.client_version = Some("wreq 0.16.1".into());
        observation.fingerprints.ja3 = ja3.map(str::to_owned);
        observation.fingerprints.ja4 = ja4.map(str::to_owned);
        observation
    }

    #[test]
    fn aggregates_missing_varying_fingerprints_and_even_median() {
        let mut first = observation(10, Some("permutation-a"), Some("stable"));
        first.outcome = Outcome::Success;
        let second = observation(40, Some("permutation-b"), Some("stable"));
        let third = observation(20, None, None);
        let fourth = observation(30, None, None);
        let runs = [first, second, third, fourth]
            .into_iter()
            .map(|observation| ProbeReport::new("https://example.com/".into(), vec![observation]))
            .collect();
        let campaign = CampaignReport::new("https://example.com/".into(), runs);
        let summary = campaign.summaries().remove(0);
        assert_eq!(
            summary.duration_ms,
            DurationSummary {
                min: 10,
                median: 25.0,
                max: 40
            }
        );
        assert_eq!(summary.outcomes["success"], 1);
        assert_eq!(summary.outcomes["transport_error"], 3);
        assert_eq!(
            summary.ja3.consistency,
            FingerprintConsistency::Inconsistent
        );
        assert_eq!(summary.ja3.unique.len(), 2);
        assert_eq!(summary.ja3.missing, 2);
        assert_eq!(summary.ja4.consistency, FingerprintConsistency::Consistent);
        assert_eq!(summary.http2.consistency, FingerprintConsistency::Unknown);
        assert!(
            campaign
                .render_text()
                .contains("TLS extension order is randomized")
        );
    }

    #[test]
    fn version_changes_stay_separate_and_browser_mismatches_are_visible() {
        let mut emulated = observation(10, Some("a"), Some("b"));
        emulated.profile = Some("chrome_150".into());
        let mut updated = emulated.clone();
        updated.client_version = Some("wreq future".into());
        let mut browser = Observation::failed("browser", None, "network error".into(), 5);
        browser.client_version = Some("149.0.0.0".into());
        let runs = vec![
            ProbeReport::new("https://example.com/".into(), vec![emulated, browser]),
            ProbeReport::new("https://example.com/".into(), vec![updated]),
        ];
        let campaign = CampaignReport::new("https://example.com/".into(), runs);
        assert_eq!(campaign.summaries().len(), 3);
        assert!(
            campaign
                .render_text()
                .contains("changed profile or version")
        );
        assert!(
            campaign
                .browser_comparisons()
                .iter()
                .any(|line| line.contains("real Chromium 149 versus selected Chrome profile 150"))
        );
        assert_eq!(
            campaign
                .summaries()
                .iter()
                .find(|summary| summary.client == "wreq")
                .unwrap()
                .ja3
                .consistency,
            FingerprintConsistency::SingleSample
        );
    }

    #[test]
    fn campaign_round_trip_escapes_html_and_rejects_unknown_schema() {
        let injected = "<script>alert('x')</script>\"&";
        let mut observation = observation(10, Some(injected), Some(injected));
        observation.client = injected.into();
        observation.profile = Some(injected.into());
        let campaign = CampaignReport::new(
            injected.into(),
            vec![ProbeReport::new(injected.into(), vec![observation])],
        );
        let restored: CampaignReport = serde_json::from_str(&campaign.to_json().unwrap()).unwrap();
        assert_eq!(restored.to_json().unwrap(), campaign.to_json().unwrap());
        let html = restored.render_html();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&quot;&amp;"));
        let mut unknown = campaign;
        unknown.schema_version = 99;
        assert!(unknown.to_json().is_err());
    }
}
