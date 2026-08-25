## Summary

Describe the user-visible change and why it is needed.

## Safety impact

- Registry targets changed: yes/no
- Backup schema or compatibility changed: yes/no
- Restore-file validation changed: yes/no
- Elevation or privilege boundary changed: yes/no

Explain every `yes` answer.

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo test --locked --all-targets`
- [ ] `cargo clippy --locked --all-targets -- -D warnings`
- [ ] `cargo build --locked --release`
- [ ] Relevant behavior tested on Windows
- [ ] Documentation and changelog updated when needed
