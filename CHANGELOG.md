# Changelog

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
