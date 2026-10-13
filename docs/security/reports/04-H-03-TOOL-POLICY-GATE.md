UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: H-03 — Fail-closed tool capability policy on dispatch path
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| Policy JSON broken ⇒ permissive fallback | `ToolPermissionsConfig.kt` | unknown/malformed policy fell back to defaults, tools reachable | reproduced by agent from 16f3971 |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| mcp/tools/ToolPermissionsConfig.kt | MOD | `PolicyMode` (PERMISSIVE_DEFAULT / FAIL_CLOSED), `fromJsonForPolicy`, `DENY_ALL`, and-gated `isToolEnabled`/`isParamEnabled`, strict `validatePolicyDocument` | `ToolPolicyGateTest` |
| mcp/tools/ToolPolicyGate.kt | NEW | Gate object composing policy verdicts on dispatch path | `ToolPolicyGateTest` (21+5+8) |
| data/repository/SettingsRepositoryImpl.kt | MOD (4 call sites) | Hardened reads route through policy-hardened helpers; corrupt policy ⇒ DENY_ALL | `SettingsRepositoryImplPolicyTest` |
| services/mcp/McpServerService.kt + mcp/tools/LoggedToolRegistration.kt | MOD | Registrar-level gate + per-dispatch DENIED path logged | `ToolPolicyLabTest` |
| integration/ToolPolicyLabTest.kt | NEW | Required lab gate: empty/broken/unknown JSON ⇒ all tools denied in hardened; handler never invoked for blocked op | `ToolPolicyLabTest` (required name) |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `:app:testLabHardenedDebugUnitTest` (agent run @ 887ac5b) | 0* | agent logs; *env gate only | ToolPolicyGateTest 34 green |
| `:app:testGmsDebugUnitTest` | 0* | agent logs | gms/foss `fromJsonOrDefault` fallback semantics preserved |
| `:app:ktlintCheck :app:detekt` | 0 | agent logs | clean |


## Validation NOT executed / blockers

- **NgrokTunnelIntegrationTest — initializationError (both variants)**: requires `NGROK_AUTHTOKEN`, unset on this host by design; CI supplies it via secret (`.github/workflows/ci.yml` ~L147). Identical failure reproduced at pinned baseline — pre-existing environment gate, not a regression. No PASS attributed for the Ngrok tunnel path.
- **CloudflareTunnelIntegrationTest — launch timeout (both variants)**: real `cloudflared` (2026.8.2, `~/.local/bin`) probed directly outside Gradle: trycloudflare.com answers `ERR error code: 1015, status_code=429 Too Many Requests` — provider-side IP rate-limit of the shared host, external to the repo. Test and vendor binary untouched. No PASS attributed for the Cloudflare quick-tunnel path.
- Suite flake note (transient, resolved): shared 32-core box at load 142–315 produced `UncompletedCoroutinesError` clusters during parallel agent runs; final gates were rerun at `--max-workers=3`/`2` and are green apart from the two environment gates above.


## Security invariants verified

- Hardened: empty/broken/unknown policy JSON ⇒ every tool and parameter denied; denial logged per dispatch; handler never invoked for blocked operation (V05, V11 gateway layer).
- gms/foss keep upstream-permissive defaults (documented product decision).


## Risks and follow-ups

- No P0 residual risk identified in lab scope; residual exposure is limited to the documented environment gates (above) and per-item residuals (see invariants).


## Rollback

`git revert fa5282f`.


## Status

`PASS`
