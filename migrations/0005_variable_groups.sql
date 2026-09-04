ALTER TABLE variables
    ADD COLUMN group_name TEXT
    CHECK (group_name IS NULL OR (length(trim(group_name)) BETWEEN 1 AND 80));

ALTER TABLE variables
    ADD COLUMN display_order INTEGER NOT NULL DEFAULT 0
    CHECK (display_order >= 0);

ALTER TABLE variable_versions
    ADD COLUMN group_name TEXT
    CHECK (group_name IS NULL OR (length(trim(group_name)) BETWEEN 1 AND 80));

ALTER TABLE variable_versions
    ADD COLUMN display_order INTEGER NOT NULL DEFAULT 0
    CHECK (display_order >= 0);

ALTER TABLE change_request_items
    ADD COLUMN proposed_group_name TEXT
    CHECK (proposed_group_name IS NULL OR (length(trim(proposed_group_name)) BETWEEN 1 AND 80));

ALTER TABLE change_request_items
    ADD COLUMN proposed_display_order INTEGER NOT NULL DEFAULT 0
    CHECK (proposed_display_order >= 0);

CREATE INDEX idx_variables_environment_group_order
    ON variables(environment_id, lifecycle_status, group_name, display_order, key);
