use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use fingerprint_lab::campaign::CampaignReport;
use fingerprint_lab::external::{probe_browser, probe_curl};
use fingerprint_lab::history::History;
use fingerprint_lab::proxy::ProxyConfig;
use fingerprint_lab::report::{Observation, Outcome, ProbeReport};
use fingerprint_lab::transport::{
    TransportOptions, parse_header, probe_reqwest, probe_wreq, validate_network_proxy, validate_url,
};
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Parser)]
#[command(
    version,
    about = "Compare HTTP transport fingerprints, retain diagnostic history, and run a local reverse proxy"
)]
struct Cli {
    /// Directory for private diagnostic history and proxy session databases.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Measure a client's fingerprints and classify its actual HTTP response.
    Probe(ProbeArgs),
    /// Compare clients; repeated runs measure stability and outcome frequencies.
    Compare(CompareArgs),
    /// Run a local HTTP reverse proxy with durable, isolated sessions.
    Proxy(ProxyArgs),
    /// Inspect runtime dependencies without downloading or navigating websites.
    Doctor(DoctorArgs),
    /// List, inspect, export, or delete saved diagnostic runs.
    History(HistoryArgs),
    /// List profiles supported by the pinned browser transport library.
    Profiles,
    #[command(hide = true)]
    Fixture(ServerArgs),
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Client {
    Reqwest,
    Wreq,
    Browser,
    Curl,
}

#[derive(Args)]
struct ConnectionOptions {
    #[arg(long, default_value = "chrome_149")]
    profile: String,
    #[arg(long,default_value_t=default_platform(),value_parser=["linux","windows","macos","android","ios"])]
    platform: String,
    /// TCP/TLS connection deadline, in seconds.
    #[arg(long,default_value_t=10,value_parser=clap::value_parser!(u64).range(1..=300))]
    connect_timeout: u64,
    /// Explicit HTTP/HTTPS forward proxy; environment proxies are ignored.
    #[arg(long)]
    network_proxy: Option<String>,
    /// Repeatable NAME: VALUE header, scoped to the requested origin.
    #[arg(long = "header", value_name = "NAME: VALUE")]
    headers: Vec<String>,
}

impl ConnectionOptions {
    fn transport(&self, timeout: Duration) -> Result<TransportOptions> {
        if let Some(proxy) = &self.network_proxy {
            validate_network_proxy(proxy)?;
        }
        let mut headers = http::HeaderMap::new();
        for raw in &self.headers {
            let (name, value) = parse_header(raw)?;
            headers.append(name, value);
        }
        Ok(TransportOptions {
            profile: self.profile.clone(),
            platform: self.platform.clone(),
            timeout,
            connect_timeout: Duration::from_secs(self.connect_timeout),
            network_proxy: self.network_proxy.clone(),
            headers,
        })
    }
}

fn default_platform() -> String {
    match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "macos",
        _ => "linux",
    }
    .into()
}

#[derive(Args)]
struct HttpOptions {
    #[command(flatten)]
    connection: ConnectionOptions,
    /// Whole probe deadline, in seconds, including browser observation wait.
    #[arg(long,default_value_t=30,value_parser=clap::value_parser!(u64).range(1..=300))]
    timeout: u64,
}

#[derive(Args)]
struct AdapterOptions {
    #[arg(long)]
    browser_executable: Option<PathBuf>,
    /// Observe subsequent browser navigation for this many seconds.
    #[arg(long,default_value_t=0,value_parser=clap::value_parser!(u64).range(0..=299))]
    browser_wait: u64,
    #[arg(long, default_value = "curl-impersonate")]
    curl_executable: PathBuf,
    #[arg(long)]
    curl_profile: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Args)]
struct OutputOptions {
    #[arg(long)]
    json: Option<PathBuf>,
    #[arg(long)]
    html: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,
}

#[derive(Args)]
struct ProbeArgs {
    #[arg(default_value = "https://tls.peet.ws/api/all")]
    url: String,
    #[arg(long, value_enum, default_value = "wreq")]
    client: Client,
    #[command(flatten)]
    http: HttpOptions,
    #[command(flatten)]
    adapters: AdapterOptions,
    /// Do not retain this run in diagnostic history.
    #[arg(long)]
    no_save: bool,
    #[command(flatten)]
    output: OutputOptions,
}

#[derive(Args)]
struct CompareArgs {
    #[arg(default_value = "https://tls.peet.ws/api/all")]
    url: String,
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_value = "reqwest,wreq",
        num_args = 1
    )]
    clients: Vec<Client>,
    #[arg(long,default_value_t=1,value_parser=clap::value_parser!(u32).range(1..=1000))]
    repeat: u32,
    /// Delay between complete runs, in milliseconds.
    #[arg(long,default_value_t=1000,value_parser=clap::value_parser!(u64).range(0..=60000))]
    interval_ms: u64,
    #[command(flatten)]
    http: HttpOptions,
    #[command(flatten)]
    adapters: AdapterOptions,
    #[arg(long)]
    no_save: bool,
    #[command(flatten)]
    output: OutputOptions,
}

#[derive(Args)]
struct ProxyArgs {
    /// One fixed HTTP/HTTPS origin (no path, query, credentials, or fragment).
    #[arg(long)]
    upstream: String,
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,
    #[command(flatten)]
    connection: ConnectionOptions,
    /// Inactivity timeout; active uploads/downloads are allowed to continue.
    #[arg(long,default_value_t=30,value_parser=clap::value_parser!(u64).range(1..=3600))]
    idle_timeout: u64,
    #[arg(long,default_value_t=1800,value_parser=clap::value_parser!(u64).range(1..=86400))]
    session_idle: u64,
    #[arg(long,default_value_t=256,value_parser=clap::value_parser!(u32).range(1..=10000))]
    max_sessions: u32,
    #[arg(long,default_value_t=64,value_parser=clap::value_parser!(u32).range(1..=10000))]
    max_in_flight: u32,
    #[arg(long,default_value_t=16_777_216,value_parser=clap::value_parser!(u64).range(1..=1_073_741_824))]
    max_request_bytes: u64,
    #[arg(long,default_value_t=1_048_576,value_parser=clap::value_parser!(u64).range(1..=67_108_864))]
    max_websocket_bytes: u64,
    #[arg(long)]
    session_db: Option<PathBuf>,
    #[arg(long, conflicts_with = "session_db")]
    ephemeral_sessions: bool,
}

#[derive(Args)]
struct ServerArgs {
    #[arg(long, default_value = "127.0.0.1:8788")]
    listen: SocketAddr,
}

#[derive(Args)]
struct DoctorArgs {
    #[arg(long)]
    browser_executable: Option<PathBuf>,
    #[arg(long, default_value = "curl-impersonate")]
    curl_executable: PathBuf,
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,
}

#[derive(Args)]
struct HistoryArgs {
    #[command(subcommand)]
    command: HistoryCommand,
}

#[derive(Subcommand)]
enum HistoryCommand {
    List {
        #[arg(long,default_value_t=20,value_parser=clap::value_parser!(u32).range(1..=1000))]
        limit: u32,
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
    Show {
        #[arg(value_parser=clap::value_parser!(i64).range(1..))]
        id: i64,
        #[command(flatten)]
        output: OutputOptions,
    },
    Delete {
        #[arg(value_parser=clap::value_parser!(i64).range(1..))]
        id: i64,
    },
}

#[derive(Clone)]
struct Control {
    cancelled: CancellationToken,
    exit: Arc<AtomicU8>,
}

impl Control {
    fn start() -> Self {
        let control = Self {
            cancelled: CancellationToken::new(),
            exit: Arc::new(AtomicU8::new(0)),
        };
        let observed = control.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            let code = {
                let terminate =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
                match terminate {
                    Ok(mut terminate) => {
                        tokio::select! { _=tokio::signal::ctrl_c()=>130,_=terminate.recv()=>143 }
                    }
                    Err(_) => {
                        let _ = tokio::signal::ctrl_c().await;
                        130
                    }
                }
            };
            #[cfg(not(unix))]
            let code = {
                let _ = tokio::signal::ctrl_c().await;
                130
            };
            observed.exit.store(code, Ordering::Relaxed);
            observed.cancelled.cancel();
        });
        control
    }
}

pub async fn run_main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fingerprint_lab=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let control = Control::start();
    let result = run(cli, &control).await;
    if control.exit.load(Ordering::Relaxed) > 0 {
        return ExitCode::from(control.exit.load(Ordering::Relaxed));
    }
    match result {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(1),
        Err(error) => {
            eprintln!("Error: {error:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli, control: &Control) -> Result<bool> {
    let data = cli.data_dir.unwrap_or_else(default_data_directory);
    match cli.command {
        Command::Probe(args) => {
            validate_adapter_wait(&args.adapters, args.http.timeout)?;
            let url = validate_url(&args.url)?;
            let options = args
                .http
                .connection
                .transport(Duration::from_secs(args.http.timeout))?;
            let observation = probe(args.client, &url, &options, &args.adapters, control).await;
            let report = ProbeReport::new(url.to_string(), vec![observation]);
            if !args.no_save {
                save_history(&data, &report)?;
            }
            write_report(&report, &args.output).await
        }
        Command::Compare(args) => {
            if args
                .clients
                .iter()
                .enumerate()
                .any(|(index, client)| args.clients[..index].contains(client))
            {
                bail!("select each client once; use --repeat for repeated measurements");
            }
            validate_adapter_wait(&args.adapters, args.http.timeout)?;
            let url = validate_url(&args.url)?;
            let options = args
                .http
                .connection
                .transport(Duration::from_secs(args.http.timeout))?;
            let mut runs = Vec::new();
            let started = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|time| time.as_secs())
                .unwrap_or_default();
            let mut captured_bytes = 0usize;
            for run in 0..args.repeat {
                if control.cancelled.is_cancelled() {
                    break;
                }
                let mut observations = Vec::new();
                for client in &args.clients {
                    if control.cancelled.is_cancelled() {
                        break;
                    }
                    observations
                        .push(probe(*client, &url, &options, &args.adapters, control).await);
                }
                if observations.is_empty() {
                    break;
                }
                let report = ProbeReport::new(url.to_string(), observations);
                captured_bytes = captured_bytes.saturating_add(report.to_json()?.len());
                if captured_bytes > 128 * 1024 * 1024 {
                    bail!(
                        "campaign capture exceeded 128 MiB; reduce --repeat (completed runs remain in history unless --no-save was selected)"
                    );
                }
                if !args.no_save {
                    save_history(&data, &report)?;
                }
                runs.push(report);
                if run + 1 < args.repeat {
                    tokio::select! {_=tokio::time::sleep(Duration::from_millis(args.interval_ms))=>{},_=control.cancelled.cancelled()=>break}
                }
            }
            if args.repeat == 1 {
                if let Some(report) = runs.first() {
                    write_report(report, &args.output).await
                } else {
                    Ok(true)
                }
            } else {
                let mut campaign = CampaignReport::new(url.to_string(), runs);
                campaign.started_at_unix = started;
                if let Some(path) = &args.output.json {
                    write_file(path, &campaign.to_json()?).await?;
                }
                if let Some(path) = &args.output.html {
                    write_file(path, &campaign.render_html()).await?;
                }
                match args.output.format {
                    OutputFormat::Text => print!("{}", campaign.render_text()),
                    OutputFormat::Json => println!("{}", campaign.to_json()?),
                }
                Ok(campaign
                    .runs
                    .iter()
                    .flat_map(|run| &run.observations)
                    .any(|row| row.outcome == Outcome::TransportError))
            }
        }
        Command::Proxy(args) => {
            if !args.listen.ip().is_loopback() {
                bail!("this diagnostic proxy accepts loopback listen addresses only");
            }
            let upstream = validate_url(&args.upstream)?;
            let options = args
                .connection
                .transport(Duration::from_secs(args.idle_timeout))?;
            let config = ProxyConfig {
                session_db: if args.ephemeral_sessions {
                    None
                } else {
                    Some(
                        args.session_db
                            .unwrap_or_else(|| data.join("proxy-sessions.sqlite")),
                    )
                },
                session_limit: args.max_sessions as usize,
                session_idle_limit: Duration::from_secs(args.session_idle),
                request_body_limit: args.max_request_bytes as usize,
                max_in_flight: args.max_in_flight as usize,
                websocket_message_limit: args.max_websocket_bytes as usize,
                shutdown: control.cancelled.clone(),
            };
            let router =
                fingerprint_lab::proxy::router_with_config(upstream.clone(), options, config)?;
            serve(
                router,
                args.listen,
                &format!("Proxy to {upstream}"),
                control,
            )
            .await?;
            Ok(false)
        }
        Command::Doctor(args) => {
            let checks = fingerprint_lab::doctor::inspect(
                args.browser_executable.as_deref(),
                &args.curl_executable,
            )
            .await;
            match args.format {
                OutputFormat::Text => print!("{}", fingerprint_lab::doctor::render_text(&checks)),
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&checks)?),
            }
            // Optional clients do not make the core Rust tool unusable.
            Ok(checks.first().is_none_or(|check| !check.available))
        }
        Command::History(args) => {
            let path = data.join("history.sqlite");
            if !path.exists() {
                if let HistoryCommand::List { format, .. } = args.command {
                    match format {
                        OutputFormat::Text => println!("No saved runs."),
                        OutputFormat::Json => println!("[]"),
                    };
                    return Ok(false);
                }
                bail!("no saved diagnostic history exists in {}", data.display());
            }
            let history = History::open(&path)?;
            match args.command {
                HistoryCommand::List { limit, format } => {
                    let entries = history.list(limit as usize)?;
                    match format {
                        OutputFormat::Json => {
                            println!("{}", serde_json::to_string_pretty(&entries)?)
                        }
                        OutputFormat::Text => {
                            if entries.is_empty() {
                                println!("No saved runs.");
                            }
                            for row in entries {
                                println!(
                                    "{} | {} | {} observations | {} non-success outcomes | {}",
                                    row.id,
                                    row.generated_at_unix,
                                    row.observation_count,
                                    row.error_count,
                                    row.target_url
                                );
                            }
                        }
                    }
                    Ok(false)
                }
                HistoryCommand::Show { id, output } => {
                    write_report(&history.load(id)?, &output).await?;
                    Ok(false)
                }
                HistoryCommand::Delete { id } => {
                    if history.delete(id)? {
                        println!("Deleted run {id}.");
                        Ok(false)
                    } else {
                        bail!("saved run {id} does not exist")
                    }
                }
            }
        }
        Command::Profiles => {
            for profile in fingerprint_lab::transport::profiles() {
                println!("{profile}");
            }
            Ok(false)
        }
        Command::Fixture(args) => {
            serve(
                fingerprint_lab::fixture::router(),
                args.listen,
                "Test origin",
                control,
            )
            .await?;
            Ok(false)
        }
    }
}

fn validate_adapter_wait(adapters: &AdapterOptions, timeout: u64) -> Result<()> {
    if adapters.browser_wait >= timeout {
        bail!("browser observation wait must be shorter than the whole probe timeout");
    }
    Ok(())
}

async fn probe(
    client: Client,
    url: &Url,
    options: &TransportOptions,
    adapters: &AdapterOptions,
    control: &Control,
) -> Observation {
    match client {
        Client::Reqwest => {
            tokio::select! {row=probe_reqwest(url,options)=>row,_=control.cancelled.cancelled()=>Observation::failed("reqwest",None,"probe interrupted".into(),0)}
        }
        Client::Wreq => {
            tokio::select! {row=probe_wreq(url,options)=>row,_=control.cancelled.cancelled()=>Observation::failed("wreq",Some(options.profile.clone()),"probe interrupted".into(),0)}
        }
        // External adapters handle process-tree cleanup before returning on signals.
        Client::Browser => {
            probe_browser(
                url,
                options,
                adapters.browser_executable.as_deref(),
                Duration::from_secs(adapters.browser_wait),
            )
            .await
        }
        Client::Curl => {
            probe_curl(
                url,
                options,
                &adapters.curl_executable,
                adapters.curl_profile.as_deref(),
            )
            .await
        }
    }
}

fn save_history(data: &Path, report: &ProbeReport) -> Result<()> {
    let history = History::open(&data.join("history.sqlite"))?;
    let id = history.save(report)?;
    eprintln!("Saved diagnostic run {id}");
    Ok(())
}

async fn write_report(report: &ProbeReport, output: &OutputOptions) -> Result<bool> {
    if let Some(path) = &output.json {
        write_file(path, &report.to_json()?).await?;
    }
    if let Some(path) = &output.html {
        write_file(path, &report.render_html()).await?;
    }
    match output.format {
        OutputFormat::Text => print!("{}", report.render_text()),
        OutputFormat::Json => println!("{}", report.to_json()?),
    }
    Ok(report
        .observations
        .iter()
        .any(|row| row.outcome == Outcome::TransportError))
}

async fn write_file(path: &Path, contents: &str) -> Result<()> {
    let path = path.to_owned();
    let contents = contents.to_owned();
    let written = path.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(contents.as_bytes())?;
        file.as_file_mut().sync_all()?;
        file.persist(&path)
            .map_err(|error| error.error)
            .with_context(|| format!("replacing {} atomically", path.display()))?;
        Ok(())
    })
    .await??;
    eprintln!("Saved {}", written.display());
    Ok(())
}

fn default_data_directory() -> PathBuf {
    if let Some(path) = std::env::var_os("FINGERPRINT_LAB_DATA_DIR") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(path).join("fingerprint-lab");
    }
    #[cfg(windows)]
    if let Some(path) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(path).join("fingerprint-lab");
    }
    if let Some(home) = std::env::var_os("HOME") {
        #[cfg(target_os = "macos")]
        return PathBuf::from(home).join("Library/Application Support/fingerprint-lab");
        #[cfg(not(target_os = "macos"))]
        return PathBuf::from(home).join(".local/share/fingerprint-lab");
    }
    PathBuf::from(".fingerprint-lab")
}

async fn serve(
    router: axum::Router,
    listen: SocketAddr,
    label: &str,
    control: &Control,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    eprintln!(
        "{label}: http://{} (Ctrl+C to stop)",
        listener.local_addr()?
    );
    let cancelled = control.cancelled.clone();
    let server = axum::serve(listener, router).with_graceful_shutdown(async move {
        cancelled.cancelled().await;
    });
    let completion = server.into_future();
    tokio::pin!(completion);
    tokio::select! {
        result=&mut completion=>result.context("serving HTTP"),
        _=control.cancelled.cancelled()=>{
            tokio::time::timeout(Duration::from_secs(10),&mut completion).await.context("proxy shutdown exceeded its ten-second grace period")?.context("serving HTTP")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compare_clients_do_not_consume_the_positional_url() {
        let cli = Cli::try_parse_from([
            "fingerprint-lab",
            "compare",
            "--clients",
            "reqwest,wreq",
            "https://example.com/",
            "--repeat",
            "2",
        ])
        .unwrap();
        match cli.command {
            Command::Compare(args) => {
                assert_eq!(args.url, "https://example.com/");
                assert_eq!(args.clients.len(), 2);
                assert_eq!(args.repeat, 2);
            }
            _ => panic!("wrong command"),
        }
    }
    #[test]
    fn proxy_uses_idle_limits_and_rejects_conflicting_session_settings() {
        assert!(
            Cli::try_parse_from([
                "fingerprint-lab",
                "proxy",
                "--upstream",
                "https://example.com",
                "--ephemeral-sessions",
                "--session-db",
                "state.sqlite"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "fingerprint-lab",
                "proxy",
                "--upstream",
                "https://example.com",
                "--idle-timeout",
                "0"
            ])
            .is_err()
        );
    }
    #[tokio::test]
    async fn atomic_output_replaces_a_complete_report() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested/report.json");
        write_file(&path, "{\"complete\":1}").await.unwrap();
        write_file(&path, "{\"complete\":2}").await.unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "{\"complete\":2}");
    }
}
