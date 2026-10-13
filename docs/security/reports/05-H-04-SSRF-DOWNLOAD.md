UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: H-04 — SSRF / download hardening (address policy, TLS-only engine)
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| Download tool followed user URLs | `MediaStoreDownloader.kt` chain | reached arbitrary hosts incl. private ranges; redirect auto-follow | agent baseline probe |
| Permissive SSL seam reachable | `SslUtils.configurePermissiveSsl` | call sites allowed unverified certificates in builds | reproduced from 16f3971 |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| services/storage/DownloadAddressPolicy.kt | NEW | Per-resolved-address policy incl. literal IPs; per-hop revalidation | `DownloadAddressPolicyTest` |
| services/storage/DownloadEngine.kt / DownloadTransport.kt | NEW | Engine + `SecureDownloadTransportFactory`: strict TLS always, `PolicyDns` per resolved address, **no redirect auto-follow** | `DownloadEngineTest`, `DownloadTransportTest` |
| app/src/main/kotlin .../di/AppModule.kt | MOD | Engine DI wiring | `DownloadNetworkLabTest` |
| DownloadUrlValidator.kt | REWORK | HTTPS-only; credential-in-URL, numeric-host, literal-IP denials (169.254.169.254, 127/8, 10/8, 172.16/12, 192.168/16, ::1, ::ffff: maps, oversized, non-HTTPS, decimal/octal encodings) | `DownloadUrlValidatorTest` |
| FileTools.kt | MOD | labHardened removes download tool + dispatch gate (~L627: unverified HTTPS certs must be explicitly allowed) | `DownloadNetworkLabTest.deniesToolInHardenedVariant` |
| MediaStoreDownloader / FileOperationProviderImpl / MediaStoreFileOperationsImpl | MOD | Rerouted through engine; provider-level permissive path eliminated | `FileOperationProviderTest` |
| integration/DownloadNetworkLabTest.kt | NEW | Real-TLS loopback servers (H-09 style): private v4/v6/v4-mapped denial, cert-mismatch/expired/self-signed rejection, redirect-to-internal + DNS-rebinding denial, size/timeout caps + no-secret logging, hardened tool denial | 5 required-style tests (real sockets, no mocks) |
| FileToolsIntegrationTest / McpProtocolIntegrationTest / AuthIntegrationTest / FileOperationProviderTest / MediaStoreDownloaderTest | MOD | 7 `assumeFalse(hardened)` guards; flavor-aware counts 56/57; provider permissive-SSL seam test superseded at merge (see resolution note) | merge 3a18e51 commit message |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `:app:testLabHardenedDebugUnitTest` (agent run @ 943915d) | 0* | agent logs; *env gate only | DownloadNetworkLabTest real-TLS green |
| `:app:testGmsDebugUnitTest` | 0* | agent logs | guard-count adjusted |
| `:app:ktlintCheck :app:detekt` | 0 | agent logs | clean |
| merge conflict resolution validation at 3a18e51 | 0 | coordinator gate run | compile+suites+lint green w/ env gates |


## Validation NOT executed / blockers

- **NgrokTunnelIntegrationTest — initializationError (both variants)**: requires `NGROK_AUTHTOKEN`, unset on this host by design; CI supplies it via secret (`.github/workflows/ci.yml` ~L147). Identical failure reproduced at pinned baseline — pre-existing environment gate, not a regression. No PASS attributed for the Ngrok tunnel path.
- **CloudflareTunnelIntegrationTest — launch timeout (both variants)**: real `cloudflared` (2026.8.2, `~/.local/bin`) probed directly outside Gradle: trycloudflare.com answers `ERR error code: 1015, status_code=429 Too Many Requests` — provider-side IP rate-limit of the shared host, external to the repo. Test and vendor binary untouched. No PASS attributed for the Cloudflare quick-tunnel path.
- Suite flake note (transient, resolved): shared 32-core box at load 142–315 produced `UncompletedCoroutinesError` clusters during parallel agent runs; final gates were rerun at `--max-workers=3`/`2` and are green apart from the two environment gates above.


## Security invariants verified

- Hardened: download tool absent at dispatch AND gateway; connection-layer denial proven with real loopback TLS servers (no mocks) for private ranges, rebinding, redirects, and certificate failures; redirects never auto-followed (revalidated per hop).
- **Merge resolution 3a18e51**: h05's provider-level permissive-SSL seam test targeted a code path h04 removed outright; removed with justification in merge commit. Intent sustained by `TlsPolicyTest` (h05) + `DownloadNetworkLabTest.deniesCertMismatchExpiredSelfSigned` (h04).


## Risks and follow-ups

- Documented residuals: `allowHttpDownloads` config now inert (no allowlist consumer); `SslUtils` retained as gated legacy helper with zero main-source callers; policy API types are public (extension surface).


## Rollback

`git revert 3a18e51` (H-05 must be reverted together to restore the permissive download path).


## Status

`PASS`
