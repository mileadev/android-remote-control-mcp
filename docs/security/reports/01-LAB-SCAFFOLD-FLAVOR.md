UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: LAB-SCAFFOLD — labHardened distribution flavor
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| No labHardened flavor upstream | `app/build.gradle.kts` flavor block | gms/foss only pre-scaffold | — |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| app/build.gradle.kts | Added labHardened productFlavor + `BuildConfig.LAB_HARDENED` flag | Single switch for all hardened postures (H-01..H-12 key on it) | `BuildSurfaceTest` |
| app/build.gradle.kts | variant-API `addStaticSourceDirectory("src/foss/kotlin")` wiring for labHardened | AGP 9.3.2 removed deprecated DSL form; confirmed via gradle-api-9.3.2.jar introspection | compile task |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `./gradlew :app:compileGmsDebugKotlin :app:compileLabHardenedDebugKotlin` | 0 | agent build log (scaffold run) | both flavors green ~4s |


## Validation NOT executed / blockers

- None.


## Security invariants verified

- `BuildConfig.LAB_HARDENED=true` only on labHardened flavor; gms/foss semantics byte-identical pre-H-*.
- labHardened reuses foss Kotlin sources; any future gms-only source split must re-check the wiring.


## Risks and follow-ups

- No P0 residual risk identified in lab scope; residual exposure is limited to the documented environment gates (above) and per-item residuals (see invariants).


## Rollback

`git revert c51d832` (removes flavor + source wiring).


## Status

`PASS`
