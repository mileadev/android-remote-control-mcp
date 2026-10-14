UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: H-09 — Station control-plane hardening (device broker)
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| No station control plane upstream | repository tree | ADR/broker/station concept existed only as handoff contract (04-CONTROL-PLANE-CONTRACT.md) | contract reviewed by agents |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| station/ | NEW package (16 files) | `lab_policy.py` (fail-closed own YAML parser), `registry.py`, `leases.py` (lease generations + fencing), `adb_access.py`, `drivers.py`, `broker.py`, `http_api.py` (loopback-only), `config/lab-policy.example.yaml` | 7 unittest files |
| station/tests/ (7 suites) | NEW | Endpoint matrix (200/400/401/404/405/413), lease fencing + races, serial allowlist, auth, policy corruption | `BrokerStationTest` (required name) |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `python3 -m unittest discover -s station/tests` | 0 | agent + coordinator terminal output | 110 OK at merge; **136 OK at final HEAD** (incl. H-12 attestation tests) |


## Validation NOT executed / blockers

- **NgrokTunnelIntegrationTest — initializationError (both variants)**: requires `NGROK_AUTHTOKEN`, unset on this host by design; CI supplies it via secret (`.github/workflows/ci.yml` ~L147). Identical failure reproduced at pinned baseline — pre-existing environment gate, not a regression. No PASS attributed for the Ngrok tunnel path.
- **CloudflareTunnelIntegrationTest — launch timeout (both variants)**: real `cloudflared` (2026.8.2, `~/.local/bin`) probed directly outside Gradle: trycloudflare.com answers `ERR error code: 1015, status_code=429 Too Many Requests` — provider-side IP rate-limit of the shared host, external to the repo. Test and vendor binary untouched. No PASS attributed for the Cloudflare quick-tunnel path.
- Suite flake note (transient, resolved): shared 32-core box at load 142–315 produced `UncompletedCoroutinesError` clusters during parallel agent runs; final gates were rerun at `--max-workers=3`/`2` and are green apart from the two environment gates above.


## Security invariants verified

- Lease fencing: stale/replayed/expired/mismatched lease denied; concurrent acquire ⇒ one winner; quarantining enforced (V12).
- Loopback-only server; explicit endpoint matrix incl. auth failures; stdlib-only (no new Python deps to verify).
- Station policy corruption ⇒ fail-closed state (V17 partial coverage).


## Risks and follow-ups

- No P0 residual risk identified in lab scope; residual exposure is limited to the documented environment gates (above) and per-item residuals (see invariants).


## Rollback

`git revert 8b225ca`.


## Status

`PASS`
