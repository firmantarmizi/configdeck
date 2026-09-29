-- Cursor navigation avoids deep offsets and full-history counts.
DROP INDEX ix_audit_action_time;
DROP INDEX ix_audit_outcome_time;
CREATE INDEX ix_audit_action_id ON audit_logs(action, id DESC);
CREATE INDEX ix_audit_outcome_id ON audit_logs(outcome, id DESC);
DROP INDEX ix_audit_actor_time;
CREATE INDEX ix_audit_actor_id ON audit_logs(actor_user_id, id DESC);
