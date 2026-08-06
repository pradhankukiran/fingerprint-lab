use std::fmt::Write;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};

use crate::external::browser_runner;
use crate::transport::compiled_dependency_version;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(8);
const COMMAND_OUTPUT_LIMIT: usize = 32 * 1024;
const CLEANUP_GRACE: Duration = Duration::from_millis(250);
const REAP_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub available: bool,
    pub detail: String,
}

impl DoctorCheck {
    fn new(name: &str, available: bool, detail: String) -> Self {
        Self {
            name: name.into(),
            available,
            detail,
        }
    }

    fn from_command(name: &str, result: Result<String>) -> Self {
        match result {
            Ok(detail) => Self::new(name, true, detail),
            Err(error) => Self::new(name, false, format!("{error:#}")),
        }
    }
}

/// Inspect installed runtime dependencies. No downloads, navigation, or network
/// requests are performed; unavailable optional clients remain independent.
pub async fn inspect(
    browser_executable: Option<&Path>,
    curl_executable: &Path,
) -> Vec<DoctorCheck> {
    let libraries = ["reqwest", "wreq", "wreq-util"]
        .map(|name| {
            format!(
                "{name} {}",
                compiled_dependency_version(name).unwrap_or("unknown")
            )
        })
        .join("; ");
    let mut checks = vec![DoctorCheck::new(
        "Rust transports",
        true,
        format!(
            "fingerprint-lab {}; {libraries}; platform {}-{}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
        ),
    )];
    let mut curl_command = Command::new(curl_executable);
    curl_command.args(["--disable", "--version"]);
    let (browser_checks, curl) = tokio::join!(
        inspect_browser(browser_executable),
        run_command(&mut curl_command, COMMAND_TIMEOUT),
    );
    checks.extend(browser_checks);
    let mut curl = DoctorCheck::from_command("curl executable", curl);
    if curl.available {
        let version = curl
            .detail
            .lines()
            .next()
            .unwrap_or("unknown version")
            .to_owned();
        curl.detail = format!(
            "{}: {version}. Version availability does not verify --impersonate support.",
            curl_executable.display(),
        );
    }
    checks.push(curl);
    checks
}

async fn inspect_browser(executable: Option<&Path>) -> Vec<DoctorCheck> {
    let node = DoctorCheck::from_command(
        "Node.js",
        run_command(Command::new("node").arg("--version"), COMMAND_TIMEOUT).await,
    );
    if !node.available {
        return vec![
            node,
            DoctorCheck::new("Browser runner", false, "Node.js is unavailable".into()),
            DoctorCheck::new("Playwright", false, "Node.js is unavailable".into()),
            DoctorCheck::new("Chromium", false, "Node.js is unavailable".into()),
        ];
    }
    let runner = browser_runner();
    let mut runtime = Command::new("node");
    runtime.arg(&runner).arg("--doctor");
    if let Some(executable) = executable {
        runtime.arg("--executable").arg(executable);
    }
    let mut syntax_command = Command::new("node");
    syntax_command.arg("--check").arg(&runner);
    let (syntax, runtime) = tokio::join!(
        run_command(&mut syntax_command, COMMAND_TIMEOUT),
        run_command(&mut runtime, COMMAND_TIMEOUT),
    );
    let syntax = syntax.map(|_| format!("{}; syntax check passed", runner.display()));
    let mut checks = vec![node, DoctorCheck::from_command("Browser runner", syntax)];
    #[derive(Deserialize)]
    struct BrowserAvailability {
        playwright_available: bool,
        playwright_version: Option<String>,
        chromium_available: bool,
        chromium_executable: Option<String>,
        version: Option<String>,
        error: Option<String>,
    }
    let availability = runtime.and_then(|json| {
        serde_json::from_str::<BrowserAvailability>(&json)
            .context("browser runner returned invalid availability JSON")
    });
    match availability {
        Ok(availability) => {
            let failure = availability.error.as_deref().unwrap_or("not installed");
            checks.push(DoctorCheck::new(
                "Playwright",
                availability.playwright_available,
                if availability.playwright_available {
                    availability
                        .playwright_version
                        .unwrap_or_else(|| "installed; version unavailable".into())
                } else {
                    failure.to_owned()
                },
            ));
            checks.push(DoctorCheck::new(
                "Chromium",
                availability.chromium_available,
                if availability.chromium_available {
                    format!(
                        "{}; {}",
                        availability
                            .chromium_executable
                            .as_deref()
                            .unwrap_or("executable unavailable"),
                        availability
                            .version
                            .as_deref()
                            .unwrap_or("version unavailable"),
                    )
                } else {
                    failure.to_owned()
                },
            ));
        }
        Err(error) => {
            checks.push(DoctorCheck::new("Playwright", false, format!("{error:#}")));
            checks.push(DoctorCheck::new("Chromium", false, format!("{error:#}")));
        }
    }
    checks
}

async fn read_output(reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .take((COMMAND_OUTPUT_LIMIT + 1) as u64)
        .read_to_end(&mut output)
        .await
        .context("reading diagnostic command output")?;
    if output.len() > COMMAND_OUTPUT_LIMIT {
        bail!("diagnostic command exceeded its output limit");
    }
    Ok(output)
}

async fn run_command(command: &mut Command, timeout: Duration) -> Result<String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(windows)]
    command.creation_flags(0x0000_0200); // CREATE_NEW_PROCESS_GROUP
    let child = command.spawn().context("starting diagnostic command")?;
    let mut process = DiagnosticProcess::new(child)?;
    let stdout = process
        .child_mut()
        .stdout
        .take()
        .context("diagnostic stdout is unavailable")?;
    let stderr = process
        .child_mut()
        .stderr
        .take()
        .context("diagnostic stderr is unavailable")?;
    let result = tokio::select! {
        result = async {
            tokio::try_join!(read_output(stdout), read_output(stderr), async {
                process.child_mut().wait().await.context("waiting for diagnostic command")
            })
        } => result,
        _ = tokio::time::sleep(timeout) => Err(anyhow::anyhow!("diagnostic command timed out")),
        result = interrupted() => Err(anyhow::anyhow!(
            "diagnostic command interrupted{}",
            if result.is_err() { " (signal listener failed)" } else { "" },
        )),
    };
    let (stdout, stderr, status) = match result {
        Ok(result) => result,
        Err(error) => {
            process.terminate().await;
            return Err(error);
        }
    };
    // Capture has ended and the direct child has been reaped. A command that
    // leaves a detached descendant in its group still needs cleanup.
    process.terminate_remaining().await;
    if !status.success() {
        let message = String::from_utf8_lossy(&stderr).trim().to_owned();
        bail!("diagnostic command exited with {status}: {message}");
    }
    Ok(
        String::from_utf8_lossy(if stdout.is_empty() { &stderr } else { &stdout })
            .trim()
            .to_owned(),
    )
}

struct DiagnosticProcess {
    child: Option<Child>,
    id: u32,
}

impl DiagnosticProcess {
    fn new(child: Child) -> Result<Self> {
        let id = child.id().context("diagnostic process ID is unavailable")?;
        Ok(Self {
            child: Some(child),
            id,
        })
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child
            .as_mut()
            .expect("diagnostic child is owned until cleanup")
    }

    async fn terminate(&mut self) {
        #[cfg(unix)]
        self.signal_group(libc::SIGTERM);
        #[cfg(windows)]
        terminate_windows_tree(self.id, false).await;
        #[cfg(not(any(unix, windows)))]
        if let Some(child) = &mut self.child {
            let _ = child.start_kill();
        }

        // Do not finish cleanup just because Node exited. Chromium or another
        // descendant may ignore SIGTERM and retain the group's pipes.
        tokio::time::sleep(CLEANUP_GRACE).await;
        #[cfg(unix)]
        self.signal_group(libc::SIGKILL);
        #[cfg(windows)]
        terminate_windows_tree(self.id, true).await;
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(REAP_TIMEOUT, child.wait()).await;
        }
    }

    async fn terminate_remaining(&mut self) {
        #[cfg(unix)]
        {
            // A successful wait does not prove the process group is empty.
            if unsafe { libc::kill(-(self.id as i32), 0) } == 0 {
                self.terminate().await;
            } else {
                self.child.take();
            }
        }
        #[cfg(not(unix))]
        self.child.take();
    }

    #[cfg(unix)]
    fn signal_group(&self, signal: libc::c_int) {
        // This ID belongs to the private group created for this command.
        unsafe {
            libc::kill(-(self.id as i32), signal);
        }
    }
}

impl Drop for DiagnosticProcess {
    fn drop(&mut self) {
        if self.child.is_none() {
            return;
        }
        // If the entire diagnostic future is abandoned, there is no opportunity
        // to await grace. Stop its private group synchronously; normal timeout
        // and signal paths use terminate() and reap the direct child above.
        #[cfg(unix)]
        {
            self.signal_group(libc::SIGTERM);
            self.signal_group(libc::SIGKILL);
        }
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("taskkill")
                .args(["/PID", &self.id.to_string(), "/T", "/F"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
        }
        if let Some(child) = &mut self.child {
            let _ = child.start_kill();
        }
    }
}

#[cfg(windows)]
async fn terminate_windows_tree(id: u32, force: bool) {
    let mut command = Command::new("taskkill");
    command.args(["/PID", &id.to_string(), "/T"]);
    if force {
        command.arg("/F");
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let _ = tokio::time::timeout(REAP_TIMEOUT, command.status()).await;
}

async fn interrupted() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

pub fn render_text(checks: &[DoctorCheck]) -> String {
    let mut text = String::new();
    for check in checks {
        let status = if check.available {
            "available"
        } else {
            "unavailable"
        };
        let _ = writeln!(text, "{}: {status}\n  {}", check.name, check.detail);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_and_json_keep_optional_checks_independent() {
        let checks = vec![
            DoctorCheck::new("Rust", true, "installed".into()),
            DoctorCheck::new("curl", false, "missing".into()),
        ];
        let text = render_text(&checks);
        assert!(text.contains("Rust: available"));
        assert!(text.contains("curl: unavailable"));
        let json = serde_json::to_value(&checks).unwrap();
        assert_eq!(json[0]["available"], true);
        assert_eq!(json[1]["available"], false);
    }

    #[tokio::test]
    async fn command_output_has_a_limit() {
        assert!(
            read_output(&vec![b'x'; COMMAND_OUTPUT_LIMIT + 1][..])
                .await
                .is_err()
        );
        assert_eq!(read_output(&b"version"[..]).await.unwrap(), b"version");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_terminates_and_reaps_a_sleeping_grandchild() {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("grandchild.pid");
        // The shell reaps its worker during graceful group termination. Killing
        // only the shell would leave this sleep running and fail the assertion.
        let script = "trap 'wait \"$worker\"; exit 0' TERM; sleep 30 & worker=$!; printf '%s' \"$worker\" > \"$1\"; wait \"$worker\"";
        let mut command = Command::new("sh");
        command
            .args(["-c", script, "diagnostic-timeout-test"])
            .arg(&pid_path);
        let error = run_command(&mut command, Duration::from_millis(500))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("timed out"));
        let pid: libc::pid_t = std::fs::read_to_string(&pid_path).unwrap().parse().unwrap();
        let deadline = tokio::time::Instant::now() + REAP_TIMEOUT;
        loop {
            let result = unsafe { libc::kill(pid, 0) };
            if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                // Keep a failing regression from leaving its fixture running.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                panic!("diagnostic grandchild {pid} survived timeout cleanup");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
