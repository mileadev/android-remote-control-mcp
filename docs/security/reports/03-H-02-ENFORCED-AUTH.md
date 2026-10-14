UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: H-02 — Enforced authentication, fail-closed start gate
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| Auth optional upstream | `McpServer.start()` | bearer-disabled + dual-off config boots OPEN | reproduced from 16f3971 via agent baseline probe |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| mcp/auth/LabAuthGate.kt | NEW | Hardened fail-closed gate: dual-off OPEN config, bearer-disabled, or blank token ⇒ throws before server accepts traffic; pass-through when `LAB_HARDENED=false` | `LabAuthGateTest` (6) |
| mcp/McpServer.kt | MOD | Gate invoked as first statement of `start()` try block | `McpServerStartAuthGateTest` |
| mcp/McpApplicationPlugins.kt | MOD | `configureAuth` trailing-lambda seam (canonical order with H-01) | AuthEnforcementLabTest |
| integration/AuthEnforcementLabTest.kt | NEW (9 tests) | 401 on missing/invalid/malformed bearer; token scoping; rotation staleness; forwarded headers gain nothing; preflight answered by CORS not auth; OAuth discovery public but scoped | `AuthEnforcementLabTest` |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `:app:testLabHardenedDebugUnitTest` (agent run @ aa0520c) | 0* | agent logs; *Ngrok env gate only | LabAuthGate 6/6, gate throws proven via `McpServerStartAuthGateTest` |
| `:app:testGmsDebugUnitTest` | 0* | agent logs | unchanged pass-through |
| `:app:ktlintCheck :app:detekt` | 0 | agent logs | clean |


## Validation NOT executed / blockers

- **NgrokTunnelIntegrationTest — initializationError (both variants)**: requires `NGROK_AUTHTOKEN`, unset on this host by design; CI supplies it via secret (`.github/workflows/ci.yml` ~L147). Identical failure reproduced at pinned baseline — pre-existing environment gate, not a regression. No PASS attributed for the Ngrok tunnel path.
- **CloudflareTunnelIntegrationTest — launch timeout (both variants)**: real `cloudflared` (2026.8.2, `~/.local/bin`) probed directly outside Gradle: trycloudflare.com answers `ERR error code: 1015, status_code=429 Too Many Requests` — provider-side IP rate-limit of the shared host, external to the repo. Test and vendor binary untouched. No PASS attributed for the Cloudflare quick-tunnel path.
- Suite flake note (transient, resolved): shared 32-core box at load 142–315 produced `UncompletedCoroutinesError` clusters during parallel agent runs; final gates were rerun at `--max-workers=3`/`2` and are green apart from the two environment gates above.


## Security invariants verified

- Hardened server cannot start with both auth modes OFF, bearer disabled, or blank token (fail-closed, proven at `start()` level).
- Missing/invalid/malformed bearer ⇒ 401; X-Forwarded-* headers confer no privilege; rotated token invalidates prior token.


## Risks and follow-ups

- No P0 residual risk identified in lab scope; residual exposure is limited to the documented environment gates (above) and per-item residuals (see invariants).


## Rollback

`git revert 0ab49a2`.


## Status

`PASS`
