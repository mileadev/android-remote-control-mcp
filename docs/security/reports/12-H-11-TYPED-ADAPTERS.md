UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: H-11 — Typed framework adapters (reflective dispatch removal)
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| Reflective dispatch path | `IntentDispatcherImpl.kt` | `Class.forName` + reflective `flagMap` lookup used for framework actions | agent source scan |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| services/adapters/ package (8 NEW files) | NEW | `AdapterContract`, `FrameworkAdapter`, `FrameworkAdapterRegistry`, `IntentExtraValue`, `IntentFlagCatalog` (**37 known flags**), `IntentFrameworkAction`, `IntentFrameworkAdapter`, `PlatformVersionProvider` | `TypedAdapterSchemasTest`, `TypedAdapterGatingTest` |
| di/FrameworkAdapterModule.kt | NEW | Adapter registry DI | :app suites |
| services/intents/IntentDispatcher.kt / IntentDispatcherImpl.kt | MOD | Dispatch through typed registry; sole reflective path (`flagMap`) removed | `IntentDispatcherImplTest` |
| services/adapters/NoDynamicDispatchTest.kt | NEW | Source-scan guard: fails on forbidden tokens (`Class.forName`, `Runtime.exec`, `app_process`, `service call`, `::class.java`) anywhere in adapters+intents | `NoDynamicDispatchTest` |
| docs/PROJECT.md | MOD | Architecture note | — |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `:app:testLabHardenedDebugUnitTest` (agent run @ 0342c445) | 0* | agent logs; *env gate only | 25 new tests green; reflective path provably absent |
| `:app:testGmsDebugUnitTest` | 0* | agent logs | green |
| `:app:ktlintCheck :app:detekt` | 0 | agent logs | clean |


## Validation NOT executed / blockers

- **NgrokTunnelIntegrationTest — initializationError (both variants)**: requires `NGROK_AUTHTOKEN`, unset on this host by design; CI supplies it via secret (`.github/workflows/ci.yml` ~L147). Identical failure reproduced at pinned baseline — pre-existing environment gate, not a regression. No PASS attributed for the Ngrok tunnel path.
- **CloudflareTunnelIntegrationTest — launch timeout (both variants)**: real `cloudflared` (2026.8.2, `~/.local/bin`) probed directly outside Gradle: trycloudflare.com answers `ERR error code: 1015, status_code=429 Too Many Requests` — provider-side IP rate-limit of the shared host, external to the repo. Test and vendor binary untouched. No PASS attributed for the Cloudflare quick-tunnel path.
- Suite flake note (transient, resolved): shared 32-core box at load 142–315 produced `UncompletedCoroutinesError` clusters during parallel agent runs; final gates were rerun at `--max-workers=3`/`2` and are green apart from the two environment gates above.


## Security invariants verified

- No dynamic class loading, command exec, or reflective flag maps remain in adapter/intent code — enforced by failing source-scan test (`NoDynamicDispatchTest`), not just review.
- Adapter schemas validated (typed intents, known-flag catalog with version gating).


## Risks and follow-ups

- No P0 residual risk identified in lab scope; residual exposure is limited to the documented environment gates (above) and per-item residuals (see invariants).


## Rollback

`git revert 28b8016`.


## Status

`PASS`
