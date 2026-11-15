# Changelog

## 0.1.5

- Make custom dropdown validation visible and keyboard-focusable; add contextual field labels in comparison, import reviews, and manual-copy preview.
- Improve action/input contrast in both themes, touch targets, reduced-motion handling, and narrow comparison layouts. Keep the current breadcrumb visible with a parent-page menu when needed.
- Explain invalid requested values without reflecting plaintext; align browser URL validation with HTTP(S), announce search progress, and ignore stale search responses.
- Replace ambiguous table placeholders and remove the decorative dot background.

- Fix multi-key request submission after changing the type of an operator-provided value.
- Let bulk request reviewers explicitly choose operator fulfillment per key while preserving literal empty pasted values.
- Keep header breadcrumbs on one line and give search its own row at intermediate screen widths.
- Patch ctutils, Tokio, rustix and SQLite audit findings; remove unused Askama config-file support. Temporarily pin official SQLx revision 10462fa4414c6c7f1ed1d39bb31678e3b726878c until a compatible registry release is available.

- Skip identical public UPDATE items from manual and bulk requests; retain existing type, visibility, description, and group defaults during request import. Entirely unchanged submissions create no request or mutation audit.
- Keep each group together when group positions tie. Preserve different per-environment types/visibility until explicitly changed.
- Reduce comparison-page startup work by initializing expanded controls and dropdown choices only when needed, and sharing event handlers. Reuse environment keys during public list rendering and aggregate group positions once.

## 0.1.4

- Request updates from the comparison workspace only for changed environments. Skip identical public values and untouched masked values, show the affected environment count, and reject stale form versions before recording requests.
- Highlight new and updated assignments in resulting preview, including complete multiline values, and list deleted keys separately. Copy keeps the canonical final `.env` without review markers or removed keys.

- Offer existing groups and new group names when preparing configuration requests; confirm receipt of encrypted imported values without revealing them back to Contributors.
- Let Operators and Administrators correct requested values, groups, and ordering from resulting preview, with explicit approval, audit, and a fresh deployment checkpoint.
- Skip identical rows when recording deployed configuration, preserving existing versions, timestamps, and audit history. Mixed imports record only real changes and retain existing type/description defaults.

## 0.1.3

- Refresh static assets automatically per build; simplify version details and tighten preview line-number spacing.
- Separate password and authenticator login steps with a short-lived, restricted challenge session.
- Count completed MFA sign-in as five-minute standard recent authentication; retain explicit two-minute verification for restore/key rotation.
- Rate-limit authenticator and reauthentication attempts, rotate sessions after verification, and expand safe cancellation navigation.

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

### Maintenance

- Update Askama, ipnet, thiserror, and uuid dependencies and pinned Docker GitHub Actions.
- Align container builds and CI/release verification on Rust 1.98.1; minimum supported Rust remains 1.94.0.
- Group routine Dependabot updates to reduce separate maintenance pull requests.

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
