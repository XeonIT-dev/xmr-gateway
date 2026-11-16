## Summary
Briefly describe what this PR changes and why.

## Security & Financial Invariants Checklist
- [ ] Zero floating-point (`f32`/`f64`) arithmetic in monetary logic (`Piconero(u64)` only).
- [ ] No hardcoded secrets, keys, credentials, or local filesystem paths.
- [ ] All SQLite state transitions and webhook outbox writes remain atomic and idempotent.
- [ ] Monero 10-block unlock rules (`confirmations >= 10` & unlocked) remain strictly enforced for sweeps.

## Verification
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test --all-targets`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`
