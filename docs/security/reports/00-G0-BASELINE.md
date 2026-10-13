UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: G0 — pre-hardening security baseline recording
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| Pinned source state | `check_source_baseline.sh` against 16f3971 | PASS w/ 3 PRESENT findings; workspace clean | SHA verified by script |
| Finding inventory | `docs/security/BASELINE.md` | 10 enumerated findings + toolchain table | Gradle 9.7.1, AGP 9.3.2, Kotlin 2.4.10, JDK 21, compileSdk 37, android-37.2-beta3, flavors gms/foss/labHardened |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| docs/security/BASELINE.md | Added | Record G0 evidence before any hardening change | — |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `bash handoff/scripts/check_source_baseline.sh` (at pinned SHA) | 0 | agent transcript of h01 origin run | PASS with 3 PRESENT findings |


## Validation NOT executed / blockers

- None. Documentation-only stage.


## Security invariants verified

- G0 is evidence-recording only; no runtime invariants introduced.
- BASELINE.md enumerates weaknesses later closed by H-01..H-12; it documents insecure-by-design default surfaces (permissive SSL toggles, optional auth, reflective dispatch) that remain on gms/foss flavors by product decision.


## Risks and follow-ups

- No P0 residual risk identified in lab scope; residual exposure is limited to the documented environment gates (above) and per-item residuals (see invariants).


## Rollback

`git revert 5199778` (documentation revert; no code surface).


## Status

`PASS`
