# Changelog

## 0.1.2

### Added

- Archive and restore default environments, protecting the last active environment and environments with open requests.
- Inherit consistent deployed-import visibility from the same App, highlight new/historical keys and conflicts, and reject stale previews or incompatible overrides atomically.
- Display the package version, source build identifier, and available Git revision in the sidebar/account menu.
- Show physical line numbers in dotenv previews and paste editors without modifying copied/downloaded content.
- Archive audit events older than 180 days through Administrator maintenance, in verified batches of up to 1,000 records.

### Fixed

- Preserve key positions and groups during value/visibility updates, reimports, and renames.
- Bound audit and version-history reads using cursor navigation; avoid full audit counts and deep offsets.
- Reduce successful health/readiness/static request logging to debug level.

### Upgrade

- Migration `0002_audit_cursor_indexes.sql` replaces audit filter indexes without changing stored values or encryption formats. Back up the database before upgrading.
- Preserve existing data/backup volumes and the exact master key.
- Audit archival is an explicit Administrator action. Archive files require an off-host backup lifecycle.
- Refresh the browser with Ctrl+Shift+R after deployment.

## 0.1.1

### Added

- Full-text redacted environment preview for users with service access, including Contributors. Restricted values remain masked.
- Import of quoted multiline environment values, including PEM-shaped blocks.

### Fixed

- Preserve actual line breaks in environment previews, copy, downloads, and API exports. Literal backslash-n stays literal.
- Copy Selected includes complete multiline values and derives selectable keys from variable metadata.
- Cancel and go back exits identity confirmation to the relevant ordinary page instead of looping back through protected export/import.
- Align Users & Access action buttons and preserve Reset TOTP icon visibility on hover and keyboard focus.
- Align Group and Type controls in Add configuration keys, including dynamically added rows and small screens.

### Upgrade

- No database migration or encryption-format change from the published v0.1.0 baseline.
- Preserve existing data/backup volumes and the exact master key; do not reinitialize the database.
- Full export and restricted-value actions still require the existing role, service access, and recent authentication.
- Refresh the browser with Ctrl+Shift+R after deployment to load updated static assets.
