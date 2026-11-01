# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](https://semver.org/).

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
