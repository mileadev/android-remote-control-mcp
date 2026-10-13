UTC timestamp: 2026-10-13T02:11:42Z
Phase/task: H-06 — Secrets at rest (Keystore AES-GCM encryption, fail-closed hardened)
Repo URL and baseline SHA: https://github.com/mileadev/android-remote-control-mcp @ 16f39717ce0969aa81a4ec132ba1cad861ba46cc (pinned, verified clean)
Current HEAD / branch: `hardening/android-lab` @ `1e1a25c` (validated HEAD = merge of H-06; this report series committed on the same branch)
Workspace state: clean (report set committed; vendor/ngrok-java and __pycache__ gitignored artifacts only)
Human authorization boundaries: local shared lab host (Linux, JDK 21, Android SDK android-37.2-beta3, Gradle 9.7.1 wrapper SHA-pinned, AGP 9.3.2, Kotlin 2.4.10); no device hardware attached; no push performed; no installs outside project/Gradle caches; no root required.


## Reproduced baseline evidence

| Observation | File/line or command | Captured result | Known uncertainty |
|---|---|---|---|
| Secrets stored plaintext | `SettingsRepositoryImpl.kt` (shared prefs) | bearer tokens, JWT secret, tunnel creds in cleartext XML | agent reproduced from 16f3971; BASELINE.md finding |


## Changes actually made

| Path | Change | Reason | Test ID |
|---|---|---|---|
| data/crypto/SecretCipher.kt | NEW | Cipher contract; fail-closed reads: integrity failure refuses release, never decrypt-then-ignore-silently, never wipes data on failed read | `FakeSecretCipher` consumers |
| data/crypto/KeystoreSecretCipher.kt | NEW | Android Keystore AES-256/GCM implementation | `KeystoreSecretCipherTest` (136 L) |
| data/repository/SecretsAtRest.kt | NEW | Authenticated + atomic one-time migration (abort on encrypt failure); hardened migration drops tunnel credentials in-transaction; persist/read helpers | `SecretsMigrationTest` (307 L), `LabSecretsAtRestTest` (283 L) |
| di/SecretCipherModule.kt | NEW | Hilt binding: `LAB_HARDENED` ⇒ Keystore cipher, otherwise plaintext pass-through (gms/foss behavior preserved) | flavor-aware suites |
| data/repository/SettingsRepositoryImpl.kt | MOD (4th ctor param `SecretCipher`) | Secret reads/writes routed through helpers; private JWT bytes + 3 members moved out (surgical, ~126-line hunks) | `SettingsRepositoryImplTest` + 6 MOD suites |
| integration/ToolPolicyLabTest.kt + 7 test suites + testGms GeofenceConfigRepositoryTest | MOD | Ctor call sites updated; 3 tunnel tests `assumeFalse(BuildConfig.LAB_HARDENED)`-gated (unpersistable creds by design) | :app suites |


## Validations executed (not proposed)

| Command | Exit status | Evidence/log location | Result |
|---|---|---|---|
| `:app:testGmsDebugUnitTest` (agent run @ 75b1279) | 0* | agent logs; *env gates only | 2455 tests / 26 crypto / 0 fail / 2 skip |
| `:app:testLabHardenedDebugUnitTest` | 0* | agent logs; *env gates only | 2417 tests / 26 crypto / 13 skip |
| `:app:ktlintCheck :app:detekt` | 0 | agent logs | clean incl. LargeClass 585 < 600 |


## Validation NOT executed / blockers

- **NgrokTunnelIntegrationTest — initializationError (both variants)**: requires `NGROK_AUTHTOKEN`, unset on this host by design; CI supplies it via secret (`.github/workflows/ci.yml` ~L147). Identical failure reproduced at pinned baseline — pre-existing environment gate, not a regression. No PASS attributed for the Ngrok tunnel path.
- **CloudflareTunnelIntegrationTest — launch timeout (both variants)**: real `cloudflared` (2026.8.2, `~/.local/bin`) probed directly outside Gradle: trycloudflare.com answers `ERR error code: 1015, status_code=429 Too Many Requests` — provider-side IP rate-limit of the shared host, external to the repo. Test and vendor binary untouched. No PASS attributed for the Cloudflare quick-tunnel path.
- Suite flake note (transient, resolved): shared 32-core box at load 142–315 produced `UncompletedCoroutinesError` clusters during parallel agent runs; final gates were rerun at `--max-workers=3`/`2` and are green apart from the two environment gates above.


## Security invariants verified

- Stored values encrypted (Keystore AES-256/GCM on hardened); fail-closed reads (integrity failure ⇒ refuse release, data preserved); migration authenticated + atomic (abort on failure); key invalidation renders stored data unusable (fake-rotation test); no secrets in logs (render callbacks ignore values, ciphertext never logged); tunnel credentials unpersistable on labHardened (BuildConfig-based, no reflection); `allowBackup` untouched (H-07 owns manifest surface).
- V08 logcat/screenshots/CI-output sweep performed at agent level for changed paths.
- Corrupt store / process-restart / credential-rotation covered by `SecretsMigrationTest` + `LabSecretsAtRestTest` (incl. corrupted-store never defaults to OPEN — asserted with H-02 gate).


## Follow-up hardening (post-merge, CI JDK 17)

- CI runs Temurin 17 while this host defaults to JDK 21. On JDK 17 SunJCE, a GCM body **shorter than the 16-byte tag** (truncated or partly overwritten preference) is reported as `java.security.ProviderException`(wrapping `ShortBufferException`) instead of `AEADBadTagException`. `ProviderException` extends `RuntimeException`, not `GeneralSecurityException`, so it escaped `KeystoreSecretCipher.decrypt` and `FakeSecretCipher.decrypt`, reached `SecretsAtRest.readStoredSecret` (which catches only `SecretCipherException`), and crashed a settings read instead of refusing the value — a real violation of the fail-closed invariant above. Both `decrypt` implementations now catch `ProviderException` and fail closed.
- Two test helpers tampered the **IV** instead of the ciphertext (`"enc.v1.<iv>.<ct>".split('.')` yields 4 parts, so index `[2]` is the IV) and discarded the real ciphertext, so the "tampered envelope" tests never exercised a tampered ciphertext. Replaced by shared `SecretEnvelopeFixtures` helpers; the tamper now flips the **first** ciphertext character, because flipping the last one is a no-op whenever the unpadded base64 length is `mod 4 == 2` (e.g. the 37-byte `secret-bearer-value-1` ciphertext).
- Regression tests added: `KeystoreSecretCipherTest."a body shorter than the authentication tag fails integrity verification"` and `LabSecretsAtRestTest."a body shorter than the authentication tag reads as empty and is not cleared"`. Both fail on JDK 17 without the catch (verified by temporary removal) and pass on JDK 21 either way, which is why the pre-existing gates missed this.
- `encrypt` had the same asymmetry (`IOException` from `KeyStore.load` and provider-level `ProviderException` both escaped, despite the interface promising `SecretCipherException` "if the backing key is unavailable"); it now catches both. These two clauses are not reachable from a JVM unit test because `AndroidKeyStore` is absent there (`KeyStoreException` fires first); they are asserted only by inspection.


## Risks and follow-ups

- No P0 residual risk identified in lab scope; residual exposure is limited to the documented environment gates (above) and per-item residuals (see invariants).


## Rollback

`git revert 1e1a25c`.


## Status

`PASS`
