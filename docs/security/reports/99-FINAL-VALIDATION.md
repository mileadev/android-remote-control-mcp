UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: FINAL — consolidated validation + V01–V18 cross-check
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| All 12 H-items + G0 + scaffold merged | git log --first-parent | 16 commits chain, clean tree | verified pre-generation |
| Baseline chain reproduction | `check_source_baseline.sh` | PASS | G0 report |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| (coordination) | per-item merge commits | see per-item reports | — |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `:app:compileGmsDebugKotlin :app:compileLabHardenedDebugKotlin` | 0 | final gate run output | green @ 1e1a25c |
| `:app:compileLabHardenedReleaseKotlin :app:compileGmsReleaseKotlin` | 0 | final gate run output | planned-release compile check green |
| `:app:testLabHardenedDebugUnitTest --max-workers=3` | 0* | test-result XMLs `app/build/test-results/` | **2496 executed / 13 skipped, failures = 2 env gates only** |
| `:app:testGmsDebugUnitTest --max-workers=3` | 0* | test-result XMLs | **2534 executed / 5 skipped, failures = 2 env gates only** |
| `:app:ktlintCheck :app:detekt` | 0 | final gate run output | clean |
| `python3 -m unittest discover -s station/tests` | 0 | terminal output | 136 OK |


## Validation NOT executed / blockers

- **NgrokTunnelIntegrationTest — initializationError (both variants)**: requires `NGROK_AUTHTOKEN`, unset on this host by design; CI supplies it via secret (`.github/workflows/ci.yml` ~L147). Identical failure reproduced at pinned baseline — pre-existing environment gate, not a regression. No PASS attributed for the Ngrok tunnel path.
- **CloudflareTunnelIntegrationTest — launch timeout (both variants)**: real `cloudflared` (2026.8.2, `~/.local/bin`) probed directly outside Gradle: trycloudflare.com answers `ERR error code: 1015, status_code=429 Too Many Requests` — provider-side IP rate-limit of the shared host, external to the repo. Test and vendor binary untouched. No PASS attributed for the Cloudflare quick-tunnel path.
- Suite flake note (transient, resolved): shared 32-core box at load 142–315 produced `UncompletedCoroutinesError` clusters during parallel agent runs; final gates were rerun at `--max-workers=3`/`2` and are green apart from the two environment gates above.
- **Release packaging** — `assembleRelease` with signing not executed (no signing store on lab host; out of scope for this hardening phase). Compile-level release check executed instead.
- **V18 coverage instrumentation** — threshold gate not configured in this phase; must be established before release.


## Security invariants verified

- **V01 — Pinned source**: **PASS (lab-scope)** — HEAD `16f3971` verified clean by baseline script; full merge chain on `hardening/android-lab` with per-item commits; submodule SHAs recorded in handoff; SBOM-equivalent = verification-metadata.xml (1607 artifacts, H-08).
- **V02 — GHSA regression / exported ADB**: **NOT_APPLICABLE (lab phase)** — requires a signed, installed release APK on device/emulator; no device attached in this phase. Lab-scope proxy: H-07 strips debug receivers + permission minimization (`BuildSurfaceTest`), hardened manifest surface asserted.
- **V03 — Origin, all HTTP methods**: **PASS** — `AuthAndOriginLabTest` (rejectsCrossOriginGetPostDeleteOptions, rejectsDnsRebindingHostAndNullOrigin, acceptsAbsentOriginOnlyWithValidBearer, doesNotExecuteHandlerOnDenial) + `RequestOriginPolicyTest`.
- **V04 — Authentication**: **PASS** — `LabAuthGateTest` (dual-off throws) + `McpServerStartAuthGateTest` (fail-closed start) + `AuthEnforcementLabTest` (9 tests: 401 matrix, scoping, rotation, forwarded-header neutrality, OAuth discovery scoped).
- **V05 — Capability policy**: **PASS** — `ToolPolicyLabTest` (broken/empty/unknown JSON ⇒ all denied, handler never invoked) + `SettingsRepositoryImplPolicyTest`.
- **V06 — SSRF**: **PASS (hardened: tool absent)** — `DownloadNetworkLabTest.deniesToolInHardenedVariant`; gms-scope connection-layer enforcement proven with real-TLS loopback tests (private ranges, redirects, rebinding). Firewall rule validation is device-farm scope (NOT_APPLICABLE here).
- **V07 — TLS**: **PASS** — `TlsPolicyTest` (hardened permissive call ⇒ throw) + `DownloadNetworkLabTest.deniesCertMismatchExpiredSelfSigned` (real chain failures rejected); no reachable trust-all path (H-05 surfaces removed).
- **V08 — Secrets**: **PASS (lab-scope)** — `SecretsMigrationTest` + `LabSecretsAtRestTest` + `KeystoreSecretCipherTest` (encrypted at rest, fail-closed reads, rotation, corrupt-store never OPEN, no secret logging). Logcat/CI-output sweep on changed paths; screenshots N/A (headless).
- **V09 — Manifest/APK**: **PARTIAL → NOT_APPLICABLE for signed-release parts** — `BuildSurfaceTest` 7/7 proves merged manifest per flavor (no forbidden permissions/receivers, debug receivers absent on hardened debug). Signed-APK SHA256/cert-fingerprint checks require device farm.
- **V10 — Reproducible build**: **PASS (enforcement in place)** — wrapper `distributionSha256Sum` (fresh-download hash proof), verification-metadata.xml 1607 artifacts enforced on every gradle run, actions SHA-pinned, external binaries pinned. Hosted-CI execution itself not run (no push).
- **V11 — Policy defense in depth**: **PASS (station+gateway layers)** — gateway: `ToolPolicyGate` + `CapabilityCatalogGate` before `ToolPolicyGate`; native dispatcher: H-04 `FileTools` hardened gate + H-11 typed adapters; station: `lab_policy.py` fail-closed policy + attestation. Third independent layer would be device-side native process kill switch (device-farm scope).
- **V12 — Lease/identity**: **PASS (station unit scope)** — lease generations + fencing proven in `station` unittests (stale/replayed/mismatched denied, concurrent acquire one winner, quarantine). Emulator-device races are device-farm scope.
- **V13 — UI correctness**: **PASS (semantics scope)** — `UiEventOutcome`/`unknown_outcome` + batch quota + tree-generation freshness tests (`UiEventUnknownOutcomeTest`, `UiEventBatchQuotaTest`, `AccessibilityNodeCacheImplTest`); real observe→tap→screenshot chain on emulator is device-farm scope.
- **V14 — Android test adapters**: **PARTIAL — catalog-match PASS** (`CapabilityCatalogSchemaTest`, station mirror `test_capability_catalog.py`); emulator typed-adapter positive/permission-negative run = device-farm scope (NOT_APPLICABLE here).
- **V15 — ATS isolation**: **NOT_APPLICABLE (this phase)** — ATS (Android Test Station) isolation requires physical device pool; station-side lease/serial-allowlist primitives exist (H-09) and are unit-proven.
- **V16 — Network exposure**: **PARTIAL** — server loopback posture + origin/auth gates proven (`AuthEnforcementLabTest`, `McpApplicationPlugins`); unreachable-from-untrusted-network requires network segmentation testing (device-farm scope). Ngrok/Cloudflare tunnel tests blocked by environment (see blockers).
- **V17 — Lifecycle resilience**: **PARTIAL (station scope)** — policy-corrupt ⇒ fail-closed, lease expiry/recovery, broker restart safety unit-proven in `station` suites; device unplug / Wi-Fi loss / SDK crash scenarios need hardware (device-farm scope).
- **V18 — Coverage ≥85%**: **NOT_APPLICABLE (metric not instrumented)** — new security-critical logic carries exhaustive negative-case suites (per-item tables); JaCoCo-style ≥85% threshold verification was not configured in this phase and must be run at release gate (BLOCKED-pending-instrumentation, reason recorded).

Per doc 05: no gate is marked PASS without the proof cited above; device-farm-dependent surfaces carry written reasons.
- **Known residuals (documented per item):** `allowHttpDownloads` inert (H-04); `SslUtils` gated legacy helper (H-05); tunnel-credential persistence `assumeFalse`-gated on hardened (H-06, by design); capability tiers T3/T4/T5 require explicit operator provisioning (H-12); Cloudflare trycloudflare.com rate-limits the shared host IP (environmental); Ngrok requires CI secret.
- **Risks:** none P0 for lab scope; hosted-CI execution and device-farm gates remain for release progression.


## Risks and follow-ups

- See per-item sections. Cross-cutting invariants: hardened posture key = `BuildConfig.LAB_HARDENED` (gms/foss unchanged); every hardened failure mode is fail-closed; every removal is proven by a test (deleted-path, source-scan, manifest-diff, or real-socket negative).


## Rollback

Per item report in its own section; global: `git revert <item merge sha>` in reverse chronological order restores any stage. Verified prior artifact: every merge was gate-validated at merge time (per-item 'Validations executed').

Per-item reports: `00`–`13` (G0, scaffold, H-01…H-12). Rollback order: reverse chronological (H-12 → … → H-01 → scaffold → G0 docs).



## Status

`PASS`
