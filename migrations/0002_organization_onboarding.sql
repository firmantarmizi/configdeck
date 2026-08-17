-- Organization onboarding and locally stored branding.
-- Existing installations are considered onboarded; a brand-new database is
-- migrated before bootstrap and therefore receives a NULL completion marker.

ALTER TABLE organizations
ADD COLUMN onboarding_completed_at TEXT;

ALTER TABLE organizations
ADD COLUMN logo_mime_type TEXT
CHECK (logo_mime_type IS NULL OR logo_mime_type IN ('image/png', 'image/webp'));

ALTER TABLE organizations
ADD COLUMN logo_data BLOB
CHECK (logo_data IS NULL OR (length(logo_data) > 0 AND length(logo_data) <= 262144));

ALTER TABLE organizations
ADD COLUMN logo_updated_at TEXT;

UPDATE organizations
SET onboarding_completed_at = updated_at
WHERE EXISTS (SELECT 1 FROM users);

CREATE TRIGGER organizations_validate_logo_insert
BEFORE INSERT ON organizations
WHEN (NEW.logo_data IS NULL) <> (NEW.logo_mime_type IS NULL)
  OR (NEW.logo_data IS NULL) <> (NEW.logo_updated_at IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'organization logo metadata must be complete');
END;

CREATE TRIGGER organizations_validate_logo_update
BEFORE UPDATE OF logo_data, logo_mime_type, logo_updated_at ON organizations
WHEN (NEW.logo_data IS NULL) <> (NEW.logo_mime_type IS NULL)
  OR (NEW.logo_data IS NULL) <> (NEW.logo_updated_at IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'organization logo metadata must be complete');
END;
