# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.6] - 2026-11-04

### Changed
- The tool writes stores for Stalwart v1.0.3, which it now requires.
- Encryption at rest stays on for the accounts that had it in v0.16: the cipher choice becomes `Enabled` with the account's public key, AES-256-GCM and ChaCha20-Poly1305 accounts get authenticated encryption on their S/MIME key, `Email.encryptAtRest` moves to `Encryption.atRestEnable`, and `Email.encryptOnAppend` is folded into each account's setting. `prepare` asks whether newly encrypted messages carry protected headers. Rollback restores the v0.16 cipher and switches.
- Public keys that v1 cannot encrypt with are reported with a warning.
- `prepare` asks which scopes migrated OAuth clients may request (mail, contacts, calendars and files by default, full access, or sign-in only). v0.16 clients had no scopes, so in v1 they were limited to sign-in.
- The v0.16 email compression setting is also applied to file blobs, which v1.0.3 configures separately.
- Rollback decrypts and decompresses the blobs v1.0.3 encrypted or compressed with zstd, using the v1 symmetric keys, and writes them back in the v0.16 format.

### Fixed
- Default roles migrated from a store first set up by an older v0.16 release lacked permissions that v1 seeds, such as `scimAccess` on System Administrator. The roles listed as default roles now get every permission the v1 default role of their kind holds and that a v0.16.0 role lacks, whatever the new permissions answer.
- Users could not list or revoke the OAuth applications they authorized unless a role already granted app password permissions and the new permissions were granted. Every role and permission list that allows sign-in now gets them.
- Custom roles with `sysEmailGet` or `sysEmailUpdate` get the matching encryption settings permission when the new permissions are granted, and `sysOAuthClient*` no longer grants the OAuth consent permissions to tenant administrators.
- `prepare` now reports an error when an account, DKIM key or other tenant-scoped object references a domain in another tenant, instead of passing and having v1 reject the object during `run`.

## [1.0.5] - 2026-11-01

### Added
- `verify` prints progress lines, also during the verification after `run --final`, and accepts `--progress-interval`.

### Changed
- The tool raises its soft open file limit to the hard limit when it starts, so large RocksDB migrations no longer stop with `Too many open files` under a low soft limit.

### Fixed
- Verify no longer reports `VanishedEmail` changelog rows holding duplicate entries as mismatched, which blocked finalising the migration.
- A stalled blob store request no longer stops verify: each blob is retried on its own, and a blob that keeps failing is reported as `could not be verified` while verify carries on.

## [1.0.4] - 2026-10-29

### Fixed
- Verify no longer reports emails whose 0.16 keywords include a `\`-prefixed system flag such as `\seen` as mismatched, which blocked finalising the migration.
- Verify no longer reports contact cards whose vCard 3.0 `N` or `ADR` has extra trailing components as mismatched.
- Removed the OpenTelemetry exporters; the release failed to build because their dependency repository was deleted.
- Registered accounts without a ChangeId counter (data predating the counter, or never used) were not listed, so run, run --final and verify skipped them silently; rollback had the same gap.
- With a shared blob store, run --final and rollback now delete the application bundle cached by the other version, so v1 no longer finds v0.16's WebUI and v0.16 no longer serves v1's after a rollback.

## [1.0.3] - 2026-10-28

### Changed
- See the [full comparison](https://github.com/stalwartlabs/stalwart-migrate/compare/v1.0.2...v1.0.3).

## [1.0.2] - 2026-10-27

### Changed
- See the [full comparison](https://github.com/stalwartlabs/stalwart-migrate/compare/v1.0.1...v1.0.2).

## [1.0.1] - 2026-10-27

### Changed
- See the [full comparison](https://github.com/stalwartlabs/stalwart-migrate/compare/v1.0.0...v1.0.1).

## [1.0.0] - 2026-10-26

### Added
- Initial release.
