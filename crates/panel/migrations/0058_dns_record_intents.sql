ALTER TABLE dns_record_history
    ADD COLUMN requested_by BIGINT REFERENCES admins(id),
    ADD COLUMN account_snapshot JSONB,
    ADD COLUMN credential_version BIGINT,
    ADD COLUMN preview_id UUID,
    ADD COLUMN rollback_of UUID,
    ADD COLUMN write_started_at BIGINT,
    ADD COLUMN rollback_started_at BIGINT;

CREATE UNIQUE INDEX dns_record_history_preview_intent
    ON dns_record_history(preview_id) WHERE preview_id IS NOT NULL;
CREATE UNIQUE INDEX dns_record_history_rollback_intent
    ON dns_record_history(rollback_of) WHERE rollback_of IS NOT NULL;
CREATE INDEX dns_record_history_unresolved_account
    ON dns_record_history(account_id) WHERE status IN ('unknown','submitted','observed');
