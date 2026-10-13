UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: H-01 — Origin/Host allowlist enforcement (hardened)
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| No origin policy upstream | `mcp/Cors.kt`, `McpServer.kt` | ACO emitted unconditionally; no Origin/Host validation | reproduced from 16f3971 |
| DNS-rebinding exposure | GET/POST handlers | Host header never cross-checked against Origin | — |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| mcp/RequestOriginPolicy.kt | NEW (497 L) | Strict Origin/Host policy: fail-fast hardened misconfiguration (incl. anyOrigin override refusal), bracketed-IPv6 canonicalization, trailing-dot strip, non-ASCII reject, cross-origin default-deny; evaluate() returns decisions, never throws per-request; gms/foss pass-through | `RequestOriginPolicyTest` (535 L) |
| mcp/RequestOriginPolicyTest.kt | NEW | Unit coverage for canonicalization + denial matrix | `RequestOriginPolicyTest` |
| integration/AuthAndOriginLabTest.kt | NEW (306 L) | Lab gate: cross-origin GET/POST/DELETE/OPTIONS 403; DNS-rebinding/null-Origin Host denial; absent-Origin still needs bearer; handler never executed on denial | `rejectsCrossOriginGetPostDeleteOptions`, `rejectsDnsRebindingHostAndNullOrigin`, `acceptsAbsentOriginOnlyWithValidBearer`, `doesNotExecuteHandlerOnDenial` |
| mcp/Cors.kt | MOD | ACAO predicate now policy-driven | AuthAndOriginLabTest |
| mcp/McpApplicationPlugins.kt / McpServer.kt / ServerConfig.kt | MOD | `configureOriginPolicy` seam, canonical plugin order (origin→CORS→auth), `approvedOrigins` centrally provisioned | AuthAndOriginLabTest |
| integration/AuthEnforcementLabTest.kt | MOD (fixup 8e551bf) | Aligned with H-01 contract: hardened app provisions `approvedPreflightOrigin=http://localhost:6274` via `configureOriginPolicy` | preflight test @ ~L202 |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `:app:testLabHardenedDebugUnitTest` (agent run @ 8057bab) | 0* | agent logs; *sole failure = Ngrok env gate | 2273 tests |
| `:app:testGmsDebugUnitTest` (agent run) | 0* | agent logs; *env gate only | 2318 tests |
| `:app:ktlintCheck :app:detekt` | 0 | agent logs | clean |
| fixup re-run after 8e551bf (filtered classes, `--max-workers=2`) | 0 | coordinator transcript | AuthEnforcementLabTest green |


## Validation NOT executed / blockers

- **NgrokTunnelIntegrationTest — initializationError (both variants)**: requires `NGROK_AUTHTOKEN`, unset on this host by design; CI supplies it via secret (`.github/workflows/ci.yml` ~L147). Identical failure reproduced at pinned baseline — pre-existing environment gate, not a regression. No PASS attributed for the Ngrok tunnel path.
- **CloudflareTunnelIntegrationTest — launch timeout (both variants)**: real `cloudflared` (2026.8.2, `~/.local/bin`) probed directly outside Gradle: trycloudflare.com answers `ERR error code: 1015, status_code=429 Too Many Requests` — provider-side IP rate-limit of the shared host, external to the repo. Test and vendor binary untouched. No PASS attributed for the Cloudflare quick-tunnel path.
- Suite flake note (transient, resolved): shared 32-core box at load 142–315 produced `UncompletedCoroutinesError` clusters during parallel agent runs; final gates were rerun at `--max-workers=3`/`2` and are green apart from the two environment gates above.


## Security invariants verified

- Hardened: any unprovisioned cross-origin denied with 403 for every HTTP method; preflight only answered for allowlisted origin; absent Origin still requires valid bearer; denial short-circuits before handler execution (proven, not just asserted).
- Host header DNS-rebinding shape rejected; non-ASCII/IPv6-canonicalization edge cases unit-tested.
- gms/foss behavior unchanged (pass-through policy).
- Cross-item conflict note: H-02's AuthEnforcementLabTest predated H-01's allowlist contract and expected preflight ACO with default (empty-allowlist) hardened policy — resolved test-side in 8e551bf by provisioning an allowlisted preflight origin. Documented in merge commit.


## Risks and follow-ups

- No P0 residual risk identified in lab scope; residual exposure is limited to the documented environment gates (above) and per-item residuals (see invariants).


## Rollback

`git revert 8e551bf d998299` (order matters: fixup first).


## Status

`PASS`
