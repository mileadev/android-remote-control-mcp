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


## Follow-up hardening (audit findings 8 and 9, deferred decisions now made)

Findings 8 and 9 of the whole-repo audit were recorded as deliberately deferred because each
resolved to a policy decision rather than a patch. Both decisions are now made and implemented.

- **A permanently unusable Keystore no longer bricks the app (finding 9).** The migration aborts
  atomically and rethrows while a retry budget lasts, which is right for a transient failure;
  nothing recorded that an attempt had happened, so a *permanent* one (restored backup, cleared
  Keystore, rotated hardware key) made every later `getServerConfig()` throw forever — the app
  could not start and no in-app action could clear it. **Policy chosen: fail closed and bound
  the retry.** A durable counter (`secret_migration_failures`, no secret material) budgets
  `MAX_SECRET_MIGRATION_FAILURES = 3` *launches*. Inside the budget the failure keeps being
  rethrown to the caller and the plaintext is left untouched (unchanged fail-loud behaviour,
  pinned by `SecretsMigrationTest`). Once the budget is spent the migration is abandoned: it is
  not retried per call, it no longer throws, so the app starts and `getServerConfig()` returns. A
  completed transform clears the counter, so a transient failure still heals by itself.
- **The budget is counted in launches, not calls (finding 9, review of the fix above).** Counting
  every call re-created the bug it was meant to fix: one launch retries from `Application.onCreate`,
  from both settings screens and from every `getServerConfig()` — and `getServerConfig()` is read
  per tool call (`McpServerService`, `PrivacyModeManager`, the file-operation providers), so a
  keystore hiccup of about a second spent all three attempts and turned a transient outage into a
  permanent one, exactly the outcome the budget exists to prevent. `SecretPersistenceContext`
  (one per repository, i.e. one per process) now records at most one failure per launch
  (`attemptedMigrationInThisProcess`), and extra callers inside that launch rethrow without
  counting. An abandoned install stays callable and **probes once per launch**, so a key that comes
  back (restored backup, unlocked keystore) clears the counter and the install heals; the probe is
  bounded to one attempt per launch so the encrypting transform never runs on the read path.
- **The failure no longer escapes into a crash (finding 9, caller half).** Rethrowing is only
  useful where a caller can act on it. Every production caller outside the server path reached the
  migration unguarded — `Application.onCreate`, `MainViewModel.init`, `AccessViewModel.init` — so
  on a device with an unusable at-rest key the process died on every launch and no screen could say
  why. Those three sites now call `startup/AuthModelMigration.applyAuthModelMigration`, which
  contains the failure, logs it (`Log.w`, no secret material) and still lets `CancellationException`
  through. The repository contract is untouched: `getServerConfig()` still surfaces the failure to
  the server start path, which is the caller that acts on it.
- **Why the other option was rejected.** The audit offered "skip the migration after N failures"
  as the cheaper fix. It is not safe here: `readStoredSecret` would then release the *unmigrated
  plaintext* — the at-rest protection would silently stop applying to exactly the secrets it
  exists to cover, which is a downgrade, not a recovery.
- **Consequence, accepted and deliberate.** Once the counter is non-zero, `readStoredSecret`
  refuses unmigrated plaintext instead of releasing it (`""`, with a throttled-free `Log.w` per
  read, no value in the message) — and only on a cipher that encrypts at rest, so a pass-through
  flavor sharing the app data is never suppressed by a counter it did not record and cannot spend
  (it clears the inherited counter in its own migration edit). With an unusable at-rest key the
  bearer token therefore reads
  empty while `bearer_token_enabled` stays true, and `LabAuthGate` refuses to start with
  `BLANK_TOKEN_REFUSAL` — the server does not serve rather than serving unprotected. This is the
  terminal correct state: every secret *write* also fails under a dead key, so there is no way
  back other than re-provisioning the app data, and the abandon is recorded once in the operator
  log (`Log.e` + a coalesced `SettingsChangeLogger` entry, no secret material) so it is
  diagnosable from the app's own log instead of only from logcat.
- **Ciphertext is never released as a secret (finding 8).** `PlaintextSecretCipher.decrypt`
  returned its input verbatim, so an `enc.v1.` envelope written by a hardened install and then
  read by another flavor of the same `applicationId` (same app data, different cipher) was
  released as the bearer token verbatim and used as the HMAC-256 JWT signing key verbatim — both
  derivable from the at-rest preferences file. It now throws `SecretCipherException` for an
  `isSecretEnvelope`-shaped value, so the reader reports an unusable secret and the store is left
  intact.
- **The unreadable-JWT-envelope condition is now observable.** The audit's suggested fix was to
  regenerate the JWT signing key when its envelope cannot be decrypted. **Not adopted**: the
  stored key cannot be distinguished from a key protected by a *rotated* Keystore, and
  regenerating a rotated-key secret would silently invalidate every already-issued token, which
  the suite pins as a deliberate decision (`LabSecretsAtRestTest."an invalidated key makes jwt
  issuance fail loudly instead of regenerating"`). Instead issuance still fails loudly and the
  condition is recorded without secret material (`Log.e` + coalesced `SettingsChangeLogger`
  entry), so a corrupt store is diagnosable instead of surfacing only as a failed OAuth call.
  `JwtTokenServiceImpl` memoizes the secret on first use — OAuth routes, not boot — so this
  never blocked startup.
- **Tests.** `SecretsMigrationTest.BoundedRetryOfAnUnusableKey` (a spent budget of three failing
  launches stops retrying, keeps the app callable, refuses the plaintext, records the abandon once,
  leaves the plaintext in place, and a second caller inside one launch does not spend more of the
  budget; a transient failure stays recoverable and clears the budget; an abandoned install probes
  once per launch and heals when the key returns; a pass-through flavor neither inherits the budget
  nor loses its plaintext secrets);
  `LabSecretsAtRestTest.CiphertextIsNeverReleasedAsASecret` (a pass-through cipher reads hardened
  envelopes as unusable, never as the ciphertext, for both the bearer token and JWT issuance);
  `KeystoreSecretCipherTest."pass-through cipher refuses an envelope instead of returning its
  ciphertext"`; and the existing invalidated-key JWT test now also asserts the operator-log
  record. All fail with the fixes temporarily reverted and pass with them, which is recorded
  in the audit-fix evidence for the branch. Each of the four behaviours added by the review of the
  budget (per-launch counting, the pass-through counter removal, the `encryptsAtRest` read guard,
  the post-abandonment probe) was verified the same way: mutating exactly that behaviour fails
  exactly its own test.
- **Tests for the guarded callers.** `startup/AuthModelMigrationTest` (the migration is applied
  exactly once; a `SecretCipherException` and any other failure are logged and do not escape) plus
  one regression test in `MainViewModelTest` and one in `AccessViewModelTest` proving the screens
  still construct. All four fail when the guard is removed — verified by temporary removal, and the
  two ViewModel tests fail as *uncaught exceptions*, which is the crash the finding describes.


## Risks and follow-ups

- No P0 residual risk identified in lab scope; residual exposure is limited to the documented environment gates (above) and per-item residuals (see invariants).


## Rollback

`git revert 1e1a25c`.


## Status

`PASS`
