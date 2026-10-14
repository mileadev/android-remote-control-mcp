UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: H-07 — Manifest flavor hardening (permission minimization)
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| Dangerous permissions on lab build | merged-manifest dump (agent) | RECEIVE_BOOT_COMPLETED, CAMERA, RECORD_AUDIO, QUERY_ALL_PACKAGES present pre-hardening | agent captured all-variant dumps |
| Debug receivers exported on debug builds | merged-manifest dump | E2EConfigReceiver + OAuthApprovalTestReceiver present | — |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| app/src/labHardened/AndroidManifest.xml | NEW | Removes RECEIVE_BOOT_COMPLETED + `BootCompletedReceiver` (`tools:node=remove` inside `<application>`); QUERY_ALL_PACKAGES → targeted `<queries>`; removes CAMERA, RECORD_AUDIO, media permissions (root-level permission removals work at flavor level) | `BuildSurfaceTest` |
| app/src/labHardenedDebug/AndroidManifest.xml | NEW | Strips E2EConfigReceiver + OAuthApprovalTestReceiver (buildType-declared nodes require combined flavor×buildType source set) | `BuildSurfaceTest` |
| testLabHardened .../manifest/BuildSurfaceTest.kt | NEW (7 tests) | Asserts final merged manifest surface per flavor/config | `BuildSurfaceTest` (required name), 7/7 |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `./gradlew :app:processLabHardenedDebugMainManifest` merged-dump diff | 0 | agent evidence (all-variant dumps) | forbidden permissions/receivers absent |
| `:app:testLabHardenedDebugUnitTest` (agent run @ f9cb498) | 0* | agent logs; *env gate only | `BuildSurfaceTest` 7/7 |
| `:app:ktlintCheck :app:detekt` | 0 | agent logs | clean |


## Validation NOT executed / blockers

- **NgrokTunnelIntegrationTest — initializationError (both variants)**: requires `NGROK_AUTHTOKEN`, unset on this host by design; CI supplies it via secret (`.github/workflows/ci.yml` ~L147). Identical failure reproduced at pinned baseline — pre-existing environment gate, not a regression. No PASS attributed for the Ngrok tunnel path.
- **CloudflareTunnelIntegrationTest — launch timeout (both variants)**: real `cloudflared` (2026.8.2, `~/.local/bin`) probed directly outside Gradle: trycloudflare.com answers `ERR error code: 1015, status_code=429 Too Many Requests` — provider-side IP rate-limit of the shared host, external to the repo. Test and vendor binary untouched. No PASS attributed for the Cloudflare quick-tunnel path.
- Suite flake note (transient, resolved): shared 32-core box at load 142–315 produced `UncompletedCoroutinesError` clusters during parallel agent runs; final gates were rerun at `--max-workers=3`/`2` and are green apart from the two environment gates above.


## Security invariants verified

- Hardened merged manifest: no RECEIVE_BOOT_COMPLETED/CAMERA/RECORD_AUDIO/media permissions; boot receiver gone; debug-only test receivers absent; package-visibility narrowed to `<queries>`.
- AGP lesson (recorded): `tools:node=remove` works for components inside `<application>` only; root permission removals must live at flavor level.
- gms/foss manifests untouched (release-store APK surface remains upstream's — V09 signature checks belong to the release gate).


## Risks and follow-ups

- No P0 residual risk identified in lab scope; residual exposure is limited to the documented environment gates (above) and per-item residuals (see invariants).


## Rollback

`git revert 0af5fd3`.


## Status

`PASS`
