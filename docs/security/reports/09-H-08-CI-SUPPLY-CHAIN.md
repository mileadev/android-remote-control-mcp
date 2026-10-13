UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: H-08 — CI / supply-chain hardening
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| Unpinned wrapper distribution | `gradle/wrapper/gradle-wrapper.properties` | no distributionSha256Sum | reproduced from 16f3971 |
| Actions floating tags | .github/workflows/ci.yml | 33 action refs not SHA-pinned | agent audit |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| gradle/wrapper/gradle-wrapper.properties | MOD | `distributionSha256Sum` for Gradle 9.7.1 — computed and cross-checked against official distribution via fresh `GRADLE_USER_HOME` download proof | every subsequent gradle run (wrapper verifies before executing) |
| gradle/verification-metadata.xml | NEW/REGENERATED | sha256 verification, **1607 artifacts**, full-resolution sweep incl. labHardened flavor | all gradle runs now fail on any unverifiable artifact |
| .github/workflows/ci.yml | MOD | 33 actions pinned to full SHAs; `validate-wrappers` ×4; cloudflared pinned 2026.10.0 + sha256 check; podman socket 666→runner-owned 660 + assertion | workflow YAML + dry-run evidence in agent logs |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| fresh GRADLE_USER_HOME wrapper download + hash compare | 0 | agent transcript | sha256 matches official 9.7.1 |
| `:app:compileGmsDebugKotlin :app:compileLabHardenedDebugKotlin` (post-metadata) | 0 | verification enforcement green | 1607/1607 verified |
| `.github/workflows/ci.yml` action-SHA audit sweep | 0 | agent audit script output | no floating remain |


## Validation NOT executed / blockers

- **NgrokTunnelIntegrationTest — initializationError (both variants)**: requires `NGROK_AUTHTOKEN`, unset on this host by design; CI supplies it via secret (`.github/workflows/ci.yml` ~L147). Identical failure reproduced at pinned baseline — pre-existing environment gate, not a regression. No PASS attributed for the Ngrok tunnel path.
- **CloudflareTunnelIntegrationTest — launch timeout (both variants)**: real `cloudflared` (2026.8.2, `~/.local/bin`) probed directly outside Gradle: trycloudflare.com answers `ERR error code: 1015, status_code=429 Too Many Requests` — provider-side IP rate-limit of the shared host, external to the repo. Test and vendor binary untouched. No PASS attributed for the Cloudflare quick-tunnel path.
- Suite flake note (transient, resolved): shared 32-core box at load 142–315 produced `UncompletedCoroutinesError` clusters during parallel agent runs; final gates were rerun at `--max-workers=3`/`2` and are green apart from the two environment gates above.
- CI workflow changes were not executed on hosted runners (no push authorization); validation limited to local enforcement + audit sweeps.


## Security invariants verified

- Wrapper distribution checksum enforced (tamper ⇒ build abort); dependency verification enforced on every Gradle invocation (incl. coordinator's own runs: any new dependency requires curated metadata regeneration).
- CI runners: no floating third-party action, pinned external binary, least-privilege podman socket.
- V10 reproducibility: within-repo evidence complete; hosted-CI execution itself was not run (no push performed).


## Risks and follow-ups

- No P0 residual risk identified in lab scope; residual exposure is limited to the documented environment gates (above) and per-item residuals (see invariants).


## Rollback

`git revert 4b6d62b`.


## Status

`PASS`
