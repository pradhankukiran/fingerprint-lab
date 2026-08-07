# Fingerprint Lab

A Rust diagnostic tool for measuring HTTP client fingerprints, comparing real browser traffic, retaining results, and operating a local reverse proxy.

The CLI supports independent `reqwest`, `wreq`, Chromium, and curl clients. Comparisons record endpoint-reported JA3/JA4 fingerprints, HTTP/2 settings, client versions, response outcomes, and timing. Repeated runs distinguish missing measurements, individual samples, and variation across samples.

## Build and check dependencies

Requires Rust **1.98 or newer**. Building wreq also requires a C/C++ compiler, CMake, Perl, pkg-config, and libclang. Dependencies are locked; the transports use `wreq 0.16.1`, `wreq-util 0.2.0`, and `reqwest 0.12.28` with rustls.

```sh
cargo build --locked --release
npm ci --prefix browser
./target/release/fingerprint-lab doctor
```

Chromium must be installed to select the browser client. The runner discovers existing Playwright browser caches. Override discovery with `--browser-executable /path/to/chrome` or `FINGERPRINT_LAB_CHROMIUM`.

Curl is optional and requires **7.83 or newer**. Select an installed binary with `--curl-executable`. `doctor` reports each dependency separately and does not install software or make website requests. Checking ordinary curl does not establish browser impersonation support:

```sh
cargo run -- doctor --curl-executable curl --format json
cargo run -- profiles
```

## Measure and compare

The default target is the public measurement API at `https://tls.peet.ws/api/all`.

```sh
cargo run -- probe
cargo run -- compare --clients reqwest,wreq,browser
cargo run -- compare --clients reqwest,wreq,browser --repeat 5 --interval-ms 1000 --json reports/comparison.json --html reports/comparison.html
```

A single run produces an observation report. Multiple runs produce a campaign report with individual runs, outcome frequencies, minimum/median/maximum duration, unique fingerprints, and measurement coverage. JSON includes the computed summaries and browser comparisons. HTML is a standalone report that can be opened without a server.

Every client pair is compared. Campaign summaries keep different client/profile/library versions separate. Real Chromium's version can differ from the chosen emulation profile; reports make that difference explicit. JA3 often changes when TLS extension order is randomized, so variation is interpreted alongside JA4 and HTTP/2.

```sh
cargo run -- probe https://example.com/ --client wreq --profile chrome_149 --platform linux --timeout 30 --connect-timeout 10
cargo run -- compare https://example.com/ --clients reqwest,wreq,browser --header 'Accept-Language: en-US,en;q=0.9'
cargo run -- probe https://example.com/ --client browser --browser-wait 5 --timeout 30
```

`--header 'NAME: VALUE'` is repeatable. Supplied headers are scoped to the original target origin, including browser navigation and curl redirects. The clients preserve correctly scoped cookies across redirects. Routing and framing headers such as Host and Content-Length are managed by the transports.

`--browser-wait` records later browser navigation, including initial/final status, URL, timing, and navigation chain. It observes normal browser behavior without automatically solving challenges.

For a curl-impersonate binary accepting `--impersonate`:

```sh
cargo run -- compare --clients reqwest,wreq,curl --curl-executable curl-impersonate --curl-profile chrome149
```

For a browser wrapper, omit `--curl-profile`. Selecting ordinary curl gives an ordinary curl baseline.

## Use an explicit network proxy

HTTP and HTTPS forward proxies are supported by all adapters. Environment proxies and curl configuration files are ignored for reproducibility.

```sh
cargo run -- compare --clients reqwest,wreq,browser --network-proxy http://127.0.0.1:8080
```

This option requires a **forward proxy** that supports the requested traffic. Fingerprint Lab's `proxy` command is a **reverse proxy** pinned to one upstream origin. It is a separate function.

Transport failures produce explicit observations. There are no automatic retries, client substitutions, or fabricated fingerprint values.

## Saved history

Completed probe runs are saved automatically in SQLite. This includes individual runs from a repeated comparison. Use `--no-save` to disable history for that command.

The default directory is the user's application data directory: `$XDG_DATA_HOME/fingerprint-lab`, or `~/.local/share/fingerprint-lab` on Linux. Windows uses LocalAppData; macOS uses Library/Application Support. Set `FINGERPRINT_LAB_DATA_DIR` or the global `--data-dir` option to choose another location.

```sh
cargo run -- --data-dir state compare
cargo run -- --data-dir state history list
cargo run -- --data-dir state history list --format json
cargo run -- --data-dir state history show 1 --json reports/run-1.json --html reports/run-1.html
cargo run -- --data-dir state history delete 1
```

History validates schema versions and stored data. It uses transactional writes and private Unix file permissions. Deletion affects only the selected run. Report files are written atomically; reusing a path replaces the complete file.

## Local HTTP reverse proxy

```sh
cargo run -- --data-dir state proxy --upstream https://example.com/ --listen 127.0.0.1:8787
```

Requests to the local listener are forwarded to the configured upstream origin. Methods, query strings, uploads, ranges, response bytes, compression headers, ETags, and HEAD response lengths are preserved. Hop-by-hop headers are filtered, and same-origin redirects are resolved against the requested URL and rewritten to the local proxy.

Upstream TLS is verified normally. The selected wreq profile supplies the outgoing transport behavior. Local Origin/Referer headers are mapped to the upstream.

Each local browser session has its own cookie jar. Cookie selection respects domain, path, expiry, and Secure attributes; matching cookies with longer paths are sent first. Upstream cookies are stored server-side behind an HttpOnly local session identifier.

Sessions persist across proxy restarts by default. Their database is private and has a process lock. The session namespace includes upstream origin, browser profile, platform, and forward-proxy route. An active session is never evicted to make room for another user; capacity exhaustion returns 503.

```sh
cargo run -- proxy --upstream https://example.com/ --ephemeral-sessions
cargo run -- proxy --upstream https://example.com/ --session-db state/custom-sessions.sqlite
cargo run -- proxy --upstream https://example.com/ --idle-timeout 60 --connect-timeout 10 --max-in-flight 64 --max-sessions 256 --session-idle 1800 --max-request-bytes 16777216 --max-websocket-bytes 1048576
```

`--idle-timeout` resets while data arrives. Active streams can outlive that duration. Uploads and responses stream with bounded memory; the CLI's default upload limit is 16 MiB. WebSocket messages default to 1 MiB. Concurrency limits cover the complete response or WebSocket connection, including stalled consumers.

The proxy bridges WebSocket text/binary messages, session cookies, and subprotocol negotiation. Ctrl+C and SIGTERM stop new work, close WebSockets, cancel active streams, and allow a bounded shutdown grace period. External diagnostic clients also terminate their owned process trees on interruption.

Control endpoints are available locally:

- `/_fingerprint-lab/health`: service status and available request slots.
- `/_fingerprint-lab/metrics`: request/error counts, active requests, and transferred bytes in Prometheus text format.

Listeners are restricted to loopback. This is an HTTP transport proxy; complete website adaptation, JavaScript rewriting, and cross-origin page rewriting are outside its scope. Pages that require JavaScript-readable upstream cookies need website adaptation. Global Cookie overrides are rejected in proxy mode to preserve separate session jars.

## Interpret the evidence

A normal website usually does not return its visitor's TLS fingerprints. Missing measurements remain missing. Use a fingerprint endpoint to measure JA3/JA4; request the protected website separately to observe access outcomes.

`cf-mitigated: challenge` identifies an explicitly marked Cloudflare challenge. A generic 403 is denied without guessing its cause. A 429 is rate limited. HTML challenge markers without the explicit header are reported as suspected. HTTP success is not proof that bot protection was bypassed.

Matching network fingerprints do not establish identical browser or JavaScript behavior. Cloudflare also considers session characteristics, JavaScript, and other signals. Its own JA3/JA4 fields require Enterprise Bot Management; independent fingerprint measurement does not require that product.

**No live Cloudflare-protected target has been verified for this project.** The supplied local challenge fixture is strictly an automated-test fixture and is labeled as simulated. Real verification requires a suitable permitted target.

## Data and resource limits

Reports omit general response bodies and authentication/cookie headers. URLs lose userinfo and redact credential-looking query parameters such as token, api_key, password, secret, authorization, signature, and code. HTTP/2 diagnostic paths receive the same treatment. Unknown parameter names can still contain sensitive data.

Proxy cookie databases contain login credentials and use private file permissions on Unix. Cookie jars are capped at 256 cookies, 8 KiB per cookie, and 4 MiB per serialized jar. Invalid stored data is reported rather than overwritten.

Probe bodies are capped at 2 MiB. History caps each report at 8 MiB and 1,024 observations. A comparison accepts up to 1,000 repeats and caps accumulated serialized capture at 128 MiB. Reduce repetitions for unusually large measurement payloads.

Exit code 0 means a diagnostic command completed; a denied or challenged HTTP response can be a valid measurement. Exit code 1 means a transport/command failed. Interrupted commands use 130 for Ctrl+C and 143 for SIGTERM. Repeated comparisons retain completed runs when interrupted, unless `--no-save` was selected. Exporting a saved failed run is a successful history operation.

## Verification

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all --check
BROWSER_PROBE_INTEGRATION=1 npm test --prefix browser
```

Tests cover actual local connections: cookie isolation and persistence across restart, upload limits, long active streams, compression and HEAD semantics, concurrency/backpressure, WebSocket authentication and shutdown, redirect header scoping, history corruption, report redaction, and owned process cleanup.

## Sources

- [wreq](https://github.com/0x676e67/wreq) and [wreq-util](https://github.com/0x676e67/wreq-util)
- [curl-impersonate](https://github.com/lexiforest/curl-impersonate)
- [Fingerprint measurement API](https://tls.peet.ws/)
- [Cloudflare challenge response header](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/)
- [Cloudflare JA3/JA4](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/)
- [Cloudflare detection engines](https://developers.cloudflare.com/bots/concepts/bot-detection-engines/)
- [Playwright browser launch](https://playwright.dev/docs/api/class-browsertype) and [CDP sessions](https://playwright.dev/docs/api/class-cdpsession)

MIT licensed.
