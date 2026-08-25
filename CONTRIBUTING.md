# Contributing

Bug reports and focused pull requests are welcome. This application writes to the Windows Registry, so changes to target discovery, backup files, elevation, or restore behavior need careful review and tests.

## Before opening an issue

- Check the latest release and existing issues.
- Include the application version, Windows version, and exact Realtek device description.
- Copy the relevant Advanced log text after removing anything you consider private.
- Do not attach backup files to public issues.
- Report suspected security problems through the private process in [SECURITY.md](SECURITY.md).

## Development setup

Use 64-bit Windows and the stable Rust toolchain. Run the full local check before submitting a pull request:

```powershell
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release
cargo audit
```

Tests and builds must use the committed `Cargo.lock` file.

## Registry safety rules

Changes must preserve these boundaries unless a proposal includes a specific threat analysis and migration plan:

- The GUI remains unelevated except for a user-confirmed helper operation.
- Registry targets remain restricted to the audio class GUID, a four-digit device key, and `PowerSettings`.
- The live driver description must identify Realtek before any write.
- Backup files cannot choose arbitrary registry value names.
- All entries are preflighted before the first write.
- Every write is verified and partial operations are rolled back.
- Restore files are untrusted and remain subject to size, path, schema, checksum, and content validation.

Avoid adding general registry import support, command execution, remote backup sources, or a broad elevated mode.

## Pull requests

Keep each pull request focused. Explain the user-visible behavior, tests performed, and any effect on backup compatibility or privilege boundaries. Update the README and changelog when behavior changes.

By contributing, you agree that your contribution is licensed under the Apache License 2.0.
