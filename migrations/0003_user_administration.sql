-- Phase 4A: initial-password lifecycle.
-- Existing accounts remain unaffected during upgrade. Newly bootstrapped and
-- UI-created accounts set this flag explicitly in application code.

ALTER TABLE users
ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0
CHECK (must_change_password IN (0, 1));
