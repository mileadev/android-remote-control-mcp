# Security Baseline (G0 evidence)

Pre-hardening evidence for the hardening backlog (H-01..H-12). This document records the
**unhardened state at the pinned upstream SHA** so the post-hardening delta is auditable.

## Provenance

| Item | Value |
| --- | --- |
| Repository | mileadev/android-remote-control-mcp |
| Pinned baseline SHA | `16f39717ce0969aa81a4ec132ba1cad861ba46cc` |
| Lab branch | `hardening/android-lab` (baseline + labHardened flavor scaffold `c51d832`) |
| Verified | `handoff/scripts/check_source_baseline.sh` → PASS at pinned SHA (see capture below) |

## Toolchain

| Tool | Version |
| --- | --- |
| Gradle wrapper | 9.7.1 (no `distributionSha256Sum` at baseline — fixed by H-08) |
| Android Gradle Plugin | 9.3.2 |
| Kotlin | 2.4.10 |
| JDK (build host) | 21.0.12.1 (Homebrew), Java target 17 |
| compileSdk / minSdk / targetSdk | 37 / 33 / 34 |
| Flavors | gms / foss (dimension `distribution`); lab adds `labHardened` |

## Baseline checker capture (pinned SHA)

```text
HEAD: 16f39717ce0969aa81a4ec132ba1cad861ba46cc
Pinned source files:
  app/src/main/AndroidManifest.xml
  app/build.gradle.kts
  gradle/wrapper/gradle-wrapper.properties
  app/src/main/kotlin/com/danielealbano/androidremotecontrolmcp/mcp/Cors.kt
  app/src/main/kotlin/com/danielealbano/androidremotecontrolmcp/mcp/auth/BearerTokenAuth.kt
  app/src/main/kotlin/com/danielealbano/androidremotecontrolmcp/data/model/ToolPermissionsConfig.kt
  app/src/main/kotlin/com/danielealbano/androidremotecontrolmcp/services/storage/SslUtils.kt
Expected findings on UNHARDENED baseline (informational, NOT security approvals):
  PRESENT: permissive CORS (must be removed in hardened variant)
  PRESENT: trust-all hostname verifier (must be removed/blocked in hardened variant)
  PRESENT: DUMP protection in source manifest (APK still requires verification)
Source baseline check complete. This check does NOT build, scan or certify an APK.
```

## Source-level findings reproduced by hand (file:line at pinned SHA)

1. **Permissive CORS** — `mcp/Cors.kt:62` calls `anyHost()`; any origin may call the HTTP surface
   (auth still applies, but the browser-adjacent trust boundary is intentionally open; the hardened
   variant must enforce a strict origin policy — H-01).
2. **Fail-open auth configuration** — `mcp/auth/BearerTokenAuth.kt` `McpAuthPlugin` returns `OPEN`
   when BOTH auth methods (bearer token, OAuth) are disabled; server starts with no auth (H-02).
3. **Fail-open tool policy** — `data/model/ToolPermissionsConfig.kt` `fromJsonOrDefault` maps
   `null`/corrupt JSON to ALL tools enabled; persisted prefs fallback path repeats this
   (`SettingsRepositoryImpl.kt` — H-03).
4. **SSRF-facing download validator** — `services/storage/DownloadUrlValidator.kt`
   `parseAndValidateDownloadUrl` checks scheme + `allowHttpDownloads` only; no host/IP policy,
   so private/link-local/metadata targets and redirects to them are accepted (H-04).
5. **Trust-all TLS** — `services/storage/SslUtils.kt` installs a permissive `X509TrustManager`
   plus trust-all `HostnameVerifier`; used by `MediaStoreDownloader.kt:64` and
   `FileOperationProviderImpl.kt:343`; gated by `ServerConfig.allowUnverifiedHttpsCerts` (H-05).
6. **Secrets in plaintext prefs** — tokens/keys stored via `SettingsRepositoryImpl` DataStore
   preferences without at-rest encryption; log redaction not enforced centrally (H-06, wave 2).
7. **Variant surface** — debug-only receivers in the debug manifest; permission set inherited by
   all flavors incl. `QUERY_ALL_PACKAGES` (lint-documented); no hardened variant overlay (H-07).
8. **Supply chain** — wrapper properties has no `distributionSha256Sum`; workflow actions not
   SHA-pinned; cloudflared installer not version-pinned (H-08).
9. **Station/ADB** — no serial allowlist / lease enforcement in repo (station pieces live in the
   handoff package; H-09 introduces them).
10. **Slow-path surfaces** — outcomes/events/UI batching and reflection-based framework adapters
    are unhardened (H-10/H-11, wave 2); capability catalog not risk-labeled (H-12, wave 2).

## Scope note

The `labHardened` flavor (`BuildConfig.LAB_HARDENED=true`) is the target enforcement surface for
the hardening items; gms/foss upstream privilege boundaries are preserved unless a backlog item
mandates an upstream-wide fix (each item report cites the governing doc line).