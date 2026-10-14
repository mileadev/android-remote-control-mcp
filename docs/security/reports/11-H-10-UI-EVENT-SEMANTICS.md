UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: H-10 — Explicit outcome semantics for fast UI events
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| Ambiguous outcome on interrupted taps | `McpToolUtils.handleActionResult` | fire-and-forget events could not distinguish completed/failed/unknown | agent baseline probe |
| Unbounded UI event emission | `ActionExecutorImpl` | no quota; replay of identical event state possible (stale tree) | reproduced from 16f3971 |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| services/accessibility/UiEventOutcome.kt | NEW | `completed|failed|unknown_outcome` explicit semantics | `UiEventOutcomeTest` |
| services/accessibility/UiEventBatchQuota.kt | NEW | 16 events / 5000 ms bucket (8 hardened) | `UiEventBatchQuotaTest` |
| services/accessibility/UiEventBatchDispatcher.kt | NEW | Batches fast UI events; no-replay proofs for interrupted taps | `UiEventUnknownOutcomeTest` |
| services/accessibility/AccessibilityTreeGeneration.kt | NEW | Tree generation tracking (renamed from tracker impl) | `AccessibilityNodeCacheImplTest` |
| services/accessibility/AccessibilityNodeCacheImpl.kt / ActionExecutorImpl.kt | MOD | Require generation tracker / quota + tracker (ctor changes merge-documented) | `ActionExecutorImplTest` |
| mcp/tools/McpToolUtils.kt | MOD (suspend) | `handleActionResult` now suspend; emits `outcome=...` tokens + meta | `McpToolUtilsTest` |
| mcp/tools/SystemActionTools.kt / di/AppModule.kt / mcp/tools/LoggedToolRegistration.kt | MOD | Quota wiring, registration metadata | integration suites |
| integration/NotificationToolsIntegrationTest.kt + 4 unit suites | MOD | Outcome-aware assertions | :app suites |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `:app:testLabHardenedDebugUnitTest` (agent run @ 544181f) | 0* | agent logs; *env gates only (Ngrok init + Cloudflare 429/1015 rate limit) | 30+ new tests green |
| `:app:testGmsDebugUnitTest` | 0* | agent logs; *same two env gates | green |
| `:app:ktlintCheck :app:detekt` | 0 | agent logs | clean |


## Validation NOT executed / blockers

- **NgrokTunnelIntegrationTest — initializationError (both variants)**: requires `NGROK_AUTHTOKEN`, unset on this host by design; CI supplies it via secret (`.github/workflows/ci.yml` ~L147). Identical failure reproduced at pinned baseline — pre-existing environment gate, not a regression. No PASS attributed for the Ngrok tunnel path.
- **CloudflareTunnelIntegrationTest — launch timeout (both variants)**: real `cloudflared` (2026.8.2, `~/.local/bin`) probed directly outside Gradle: trycloudflare.com answers `ERR error code: 1015, status_code=429 Too Many Requests` — provider-side IP rate-limit of the shared host, external to the repo. Test and vendor binary untouched. No PASS attributed for the Cloudflare quick-tunnel path.
- Suite flake note (transient, resolved): shared 32-core box at load 142–315 produced `UncompletedCoroutinesError` clusters during parallel agent runs; final gates were rerun at `--max-workers=3`/`2` and are green apart from the two environment gates above.


## Security invariants verified

- Fast-path UI events carry explicit outcome semantics; interrupted/unconfirmable taps ⇒ `unknown_outcome` (never replayed as success); batch quota enforced (tightened on hardened); tree-generation freshness prevents stale-node action replay (V13).
**Cloudflare env gate evidence (both variants, pre-existing of h10 diff)**: `cloudflared tunnel --url …` probed directly ⇒ trycloudflare.com `error code: 1015` / HTTP 429 (host-IP rate limit).


## Risks and follow-ups

- No P0 residual risk identified in lab scope; residual exposure is limited to the documented environment gates (above) and per-item residuals (see invariants).


## Rollback

`git revert 53c314c`.


## Status

`PASS`
