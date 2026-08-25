# Changelog

Notable project changes are recorded here. Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Clarified copyright ownership and third-party trademark attribution.

## [0.1.1] - 2026-08-25

### Changed

- Updated `sha2` from 0.10.9 to 0.11.0 while preserving Rust 1.85 compatibility.
- Added native GitHub Sponsors metadata, a README badge, and a support section.

There are no changes to registry discovery, backup compatibility, fix values, restore validation, or elevation behavior in this release.

## [0.1.0] - 2026-08-25

### Added

- Windows GUI for scanning one or many Realtek audio registry entries.
- Automatic backups before applying the power-management workaround.
- Restore from the latest backup or a user-selected backup.
- Advanced operation log with registry paths, values, and backup locations.
- Strict backup schema, content fingerprinting, path validation, and write verification.
- Narrow elevated helper with rollback on partial failure.
- Embedded application icon and Windows Common Controls manifest.
- Portable Windows x64 release packaging and checksums.

[Unreleased]: https://github.com/shoon/audio-fade-fixer/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/shoon/audio-fade-fixer/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/shoon/audio-fade-fixer/releases/tag/v0.1.0
