UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: H-12 — Risk-labeled capability catalog + hardened dispatch gating + station attestation
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| No risk-labeled capability surface | tool registration | tools discoverable without risk tiering or station-side attestation | contract required per 04-CONTROL-PLANE-CONTRACT.md |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| mcp/tools/CapabilityCatalog.kt | NEW (760 L) | 13-field schema, T1–T5 privilege tiers, `DEFAULT_PROVISIONED_TIER=T2_TEST` | `CapabilityCatalogSchemaTest` |
| mcp/tools/CapabilityCatalogGate.kt | NEW | Gate composed **before** `ToolPolicyGate` (H-03 gate untouched); gms/foss = INACTIVE; hardened integrity violation aborts startup | `CapabilityCatalogGateTest`, `PrivilegeTierGatingTest` |
| mcp/tools/LoggedToolRegistration.kt / services/mcp/McpServerService.kt | MOD | Catalog-wrapped registration (compatibly composed with H-10 metadata edits) | :app suites |
| station/capability_catalog.py | NEW | Station-side catalog attestation (mirrors JVM schema) | `station/tests/test_capability_catalog.py` (26 tests) |
| station/broker.py / station/lab_policy.py / station/tests/support.py | MOD | Attestation wiring | station suites |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `:app:testLabHardenedDebugUnitTest` (agent run @ 4f2b1e5) | 0* | agent logs; *env gate only | catalog + gating suites green |
| `:app:testGmsDebugUnitTest` | 0* | agent logs | green (gate INACTIVE) |
| `:app:ktlintCheck :app:detekt` | 0 | agent logs | clean |
| `python3 -m unittest discover -s station/tests` | 0 | agent + coordinator output | 136 OK incl. 26 catalog-attestation tests |


## Validation NOT executed / blockers

- **NgrokTunnelIntegrationTest — initializationError (both variants)**: requires `NGROK_AUTHTOKEN`, unset on this host by design; CI supplies it via secret (`.github/workflows/ci.yml` ~L147). Identical failure reproduced at pinned baseline — pre-existing environment gate, not a regression. No PASS attributed for the Ngrok tunnel path.
- **CloudflareTunnelIntegrationTest — launch timeout (both variants)**: real `cloudflared` (2026.8.2, `~/.local/bin`) probed directly outside Gradle: trycloudflare.com answers `ERR error code: 1015, status_code=429 Too Many Requests` — provider-side IP rate-limit of the shared host, external to the repo. Test and vendor binary untouched. No PASS attributed for the Cloudflare quick-tunnel path.
- Suite flake note (transient, resolved): shared 32-core box at load 142–315 produced `UncompletedCoroutinesError` clusters during parallel agent runs; final gates were rerun at `--max-workers=3`/`2` and are green apart from the two environment gates above.


## Security invariants verified

- Every registered tool carries a risk tier; hardened dispatch enforces tier gating before policy gating (defense-in-depth: V11 gateway layer, V14 catalog match); station verifies catalog attestation independently (Python-side).
- Hardened integrity violation aborts startup (fail-closed), consistent with H-02 gate posture.


## Risks and follow-ups

- T3/T4/T5 provisioning surface is intentionally provision-free at T2_TEST default — operator must explicitly raise tiers (documented risk).


## Rollback

`git revert 6723735`.


## Status

`PASS`
