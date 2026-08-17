-- Remove superseded registry tables. Backup discovery is filesystem-backed and
-- restore intent durability is provided by the external marker by design.
DROP TABLE restore_intents;
DROP TABLE backups;

-- Support bounded cleanup and growing audit filters without full-table scans.
CREATE INDEX ix_login_attempts_time ON login_attempts (attempted_at);
CREATE INDEX ix_audit_action_time ON audit_logs (action, occurred_at DESC);
CREATE INDEX ix_audit_outcome_time ON audit_logs (outcome, occurred_at DESC);
