# ConfigDeck Release Checklist

## Build and supply chain

- [x] `cargo fmt --check`
- [x] `cargo clippy --all-targets --all-features -- -D warnings`
- [x] `cargo test`
- [x] `cargo build --release`
- [x] declared MSRV check passes
- [x] `cargo audit` with a freshly updated advisory database passes
- [x] dependency/license review is current
- [x] Docker image builds without cache; each published release records an immutable image digest

## Container and configuration

- [x] Compose configuration validates with no real credential printed or committed
- [x] process runs as UID/GID 10001 and root filesystem is read-only
- [x] capabilities are empty and `no-new-privileges` is active
- [x] `/data` and `/backup` are separate persistent volumes
- [x] supplied port binding is loopback-only; production TLS proxy remains a deployment prerequisite
- [ ] trusted proxy CIDRs contain only the actual proxy network
- [x] resource limits and log rotation are active
- [x] `/health` and `/ready` pass after restart

## Identity and authorization

- [ ] bootstrap Administrator completed TOTP, initial password change, and organization setup
- [ ] bootstrap variables were removed after provisioning
- [ ] a second Administrator exists before production operations
- [x] automated negative suite proves Contributor only sees assigned Apps and never receives restricted plaintext
- [x] automated capability suite proves Operator can review/apply but cannot manage users or rotate keys
- [x] automated suite proves Administrator high-impact operations require recent password + TOTP
- [x] automated suite covers logout, session expiry, role change, disable, password change, and TOTP reset revocation

## Workflow and data safety

- [x] `.env` import edge cases and type/visibility review pass
- [x] change request add/update/delete, fulfillment, approval, preview, and atomic apply pass
- [x] stale preview and overlapping request negative tests pass
- [x] App comparison/global search expose metadata only
- [x] secret reveal/export pages use no-store and close safely
- [x] audit viewer renders allowlisted primitive metadata only

## Recovery and maintenance

- [ ] backup created, checksum verified, and copied off-host
- [x] automated offline restore drill completed using disposable data
- [ ] KEK two-file rotation drill completed or scheduled before first planned rotation
- [x] automated and real-data DEK rotation drills prove current/history/proposal migration and old material destruction
- [ ] free-space alerting covers both data and backup volumes
- [ ] master key backup is protected separately from database backups

## Release acceptance

- [x] dark/light and desktop/mobile functional smoke accepted; remaining visual improvements are tracked in `ROADMAP.md`
- [x] outstanding visual and localization work is documented without weakening the production security baseline
- [ ] known limitations and non-goals are understood
- [ ] production operator, backup custodian, and incident contact are recorded outside ConfigDeck
