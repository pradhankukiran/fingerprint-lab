use std::path::Path;
use std::process::Output;
use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;

async fn cli(directory: &Path, arguments: &[&str]) -> Output {
    tokio::time::timeout(
        Duration::from_secs(10),
        Command::new(env!("CARGO_BIN_EXE_fingerprint-lab"))
            .arg("--data-dir")
            .arg(directory.join("state"))
            .args(arguments)
            .current_dir(directory)
            .env("RUST_LOG", "error")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("CLI command exceeded its deadline")
    .expect("CLI command failed to start")
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid CLI JSON: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[tokio::test]
async fn repeated_comparison_exports_sanitized_summaries_and_manages_history() {
    let directory = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!(
        "http://{}/echo?token=private-value&name=visible",
        listener.local_addr().unwrap()
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, fingerprint_lab::fixture::router())
            .await
            .unwrap();
    });
    let result = cli(
        directory.path(),
        &[
            "compare",
            &target,
            "--clients",
            "reqwest,wreq",
            "--repeat",
            "2",
            "--interval-ms",
            "0",
            "--format",
            "json",
            "--json",
            "comparison.json",
            "--html",
            "comparison.html",
        ],
    )
    .await;
    server.abort();
    let _ = server.await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let campaign = json(&result);
    assert_eq!(campaign["runs"].as_array().unwrap().len(), 2);
    assert_eq!(campaign["summaries"].as_array().unwrap().len(), 2);
    for summary in campaign["summaries"].as_array().unwrap() {
        assert_eq!(summary["observations"], 2);
        assert_eq!(summary["outcomes"]["success"], 2);
        assert_eq!(summary["ja4"]["measured"], 0);
        assert_eq!(summary["ja4"]["consistency"], "unknown");
    }
    for file in ["comparison.json", "comparison.html"] {
        let contents = std::fs::read_to_string(directory.path().join(file)).unwrap();
        assert!(!contents.contains("private-value"));
        assert!(contents.contains("visible"));
    }
    let saved = cli(directory.path(), &["history", "list", "--format", "json"]).await;
    assert!(saved.status.success());
    let saved = json(&saved);
    let rows = saved.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row["observation_count"] == 2));
    let id = rows[0]["id"].as_i64().unwrap().to_string();
    let exported = cli(
        directory.path(),
        &[
            "history",
            "show",
            &id,
            "--format",
            "json",
            "--html",
            "saved.html",
        ],
    )
    .await;
    assert!(exported.status.success());
    assert_eq!(json(&exported)["observations"].as_array().unwrap().len(), 2);
    assert!(directory.path().join("saved.html").is_file());
    assert!(
        cli(directory.path(), &["history", "delete", &id])
            .await
            .status
            .success()
    );
    let remaining = cli(directory.path(), &["history", "list", "--format", "json"]).await;
    assert_eq!(json(&remaining).as_array().unwrap().len(), 1);
    assert!(
        !cli(directory.path(), &["history", "show", &id])
            .await
            .status
            .success()
    );
}

#[tokio::test]
async fn failed_probe_is_saved_and_exporting_it_succeeds() {
    let directory = tempfile::tempdir().unwrap();
    // A bound listener without an HTTP server guarantees a local response timeout.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("http://{}/", listener.local_addr().unwrap());
    let probe = cli(
        directory.path(),
        &[
            "probe",
            &target,
            "--client",
            "reqwest",
            "--timeout",
            "1",
            "--format",
            "json",
        ],
    )
    .await;
    assert_eq!(probe.status.code(), Some(1));
    assert_eq!(
        json(&probe)["observations"][0]["outcome"],
        "transport_error"
    );
    let saved = cli(directory.path(), &["history", "list", "--format", "json"]).await;
    let saved = json(&saved);
    assert_eq!(saved.as_array().unwrap().len(), 1);
    assert_eq!(saved[0]["error_count"], 1);
    let id = saved[0]["id"].as_i64().unwrap().to_string();
    let exported = cli(
        directory.path(),
        &[
            "history",
            "show",
            &id,
            "--format",
            "json",
            "--json",
            "failed.json",
        ],
    )
    .await;
    assert!(exported.status.success());
    assert_eq!(
        json(&exported)["observations"][0]["outcome"],
        "transport_error"
    );
    let file: Value =
        serde_json::from_slice(&std::fs::read(directory.path().join("failed.json")).unwrap())
            .unwrap();
    assert_eq!(file["observations"][0]["outcome"], "transport_error");
}
