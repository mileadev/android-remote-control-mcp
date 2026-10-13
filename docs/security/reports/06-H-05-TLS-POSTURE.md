UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: H-05 — TLS posture fail-closed (trust-all removal)
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| Trust-all toggle surfaces | `SettingsRepositoryImpl` key, `StorageSettingsScreen`, `AdbConfigHandler/Receiver` | user-flippable permissive SSL persisted and exposed in UI/ADB | reproduced from 16f3971 |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| utils/SslUtils.kt | MOD | `configurePermissiveSsl` throws `IllegalStateException` under `LAB_HARDENED` (fail-closed choke point, explicit message) | `TlsPolicyTest` (variant-aware) |
| SettingsRepositoryImpl.kt / SettingsRepository.kt / MainViewModel / StorageSettingsScreen / strings.xml | MOD | Permissive-TLS setting key + UI surface removed | `TlsPolicyTest` |
| AdbConfigHandler / AdbConfigReceiver | MOD | Toggle no longer settable via ADB channel | `TlsPolicyTest` |
| SslUtilsTest.kt | DELETED | Superseded by variant-aware `TlsPolicyTest` | — |
| docs/README*  | MOD | Posture documented | — |

*(Audit finding 19 update: the `SslUtils.configurePermissiveSsl` gate and `TlsPolicyTest` were both
deleted — the helper had zero production callers in every flavor, so the gate protected nothing and
the test proved only the gate itself. The rows above record what H-05 did at the time; the trust-all
path is now absent from the source rather than blocked inside it, which `DownloadNetworkLabTest`
proves by real chain rejection.)*


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `:app:testLabHardenedDebugUnitTest` (agent run @ 3fadfd9) | 0* | agent logs; *env gate only | hardened: permissive call ⇒ throw, proven |
| `:app:testGmsDebugUnitTest` | 0* | agent logs | toggle removed for all flavors |
| `:app:ktlintCheck :app:detekt` | 0 | agent logs | clean |


## Validation NOT executed / blockers

- **NgrokTunnelIntegrationTest — initializationError (both variants)**: requires `NGROK_AUTHTOKEN`, unset on this host by design; CI supplies it via secret (`.github/workflows/ci.yml` ~L147). Identical failure reproduced at pinned baseline — pre-existing environment gate, not a regression. No PASS attributed for the Ngrok tunnel path.
- **CloudflareTunnelIntegrationTest — launch timeout (both variants)**: real `cloudflared` (2026.8.2, `~/.local/bin`) probed directly outside Gradle: trycloudflare.com answers `ERR error code: 1015, status_code=429 Too Many Requests` — provider-side IP rate-limit of the shared host, external to the repo. Test and vendor binary untouched. No PASS attributed for the Cloudflare quick-tunnel path.
- Suite flake note (transient, resolved): shared 32-core box at load 142–315 produced `UncompletedCoroutinesError` clusters during parallel agent runs; final gates were rerun at `--max-workers=3`/`2` and are green apart from the two environment gates above.


## Security invariants verified

- No trust-all path reachable in hardened variant (throw at choke point, proven); invalid chain/hostname/expired cert rejected by engine TLS validation (jointly proven with H-04's real-loopback `DownloadNetworkLabTest`).
- UI/ADB toggle surfaces removed in ALL flavors — the two settings (`allowUnverifiedHttpsCerts`, `allowHttpDownloads`) and the trust-all helper `SslUtils` are gone from the source entirely (audit finding 19), so there is no permissive seam left to gate. `DownloadNetworkLabTest` rejects a wrong-host/expired/self-signed chain against real loopback TLS.


## Risks and follow-ups

- No P0 residual risk identified in lab scope; residual exposure is limited to the documented environment gates (above) and per-item residuals (see invariants).


## Rollback

`git revert 886b806` (must pair with reverting H-04 merge `3a18e51`).


## Status

`PASS`
