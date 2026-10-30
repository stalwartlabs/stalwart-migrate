# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.4] - 2026-10-29

### Fixed
- Verify no longer reports emails whose 0.16 keywords include a `\`-prefixed system flag such as `\seen` as mismatched, which blocked finalising the migration.
- Verify no longer reports contact cards whose vCard 3.0 `N` or `ADR` has extra trailing components as mismatched.
- Removed the OpenTelemetry exporters; the release failed to build because their dependency repository was deleted.

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
