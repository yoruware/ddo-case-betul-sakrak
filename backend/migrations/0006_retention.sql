-- +goose Up
CREATE TABLE document_types (
    code           TEXT PRIMARY KEY CHECK (code ~ '^[a-z][a-z0-9_]{1,31}$'),
    name           TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    retention_days INT  NOT NULL CHECK (retention_days BETWEEN 0 AND 36500),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO document_types (code, name, retention_days) VALUES
    ('contract', 'Sözleşme', 3650),
    ('report', 'Rapor', 1825),
    ('correspondence', 'Yazışma', 730);

ALTER TABLE nodes ADD COLUMN destroyed_at TIMESTAMPTZ;

CREATE TABLE retention_records (
    node_id         UUID PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    doc_type        TEXT NOT NULL REFERENCES document_types(code),
    retention_until TIMESTAMPTZ NOT NULL,
    assigned_by     UUID NOT NULL REFERENCES users(id),
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    hold_blocked_at TIMESTAMPTZ
);
CREATE INDEX idx_retention_due ON retention_records (retention_until);

CREATE TABLE legal_holds (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id     UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    case_ref    TEXT NOT NULL CHECK (length(case_ref) BETWEEN 1 AND 200),
    reason      TEXT NOT NULL DEFAULT '',
    placed_by   UUID NOT NULL REFERENCES users(id),
    placed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_by UUID REFERENCES users(id),
    released_at TIMESTAMPTZ,
    CHECK ((released_at IS NULL) = (released_by IS NULL))
);
CREATE INDEX idx_legal_holds_active ON legal_holds (node_id) WHERE released_at IS NULL;

CREATE TABLE destruction_certificates (
    id         UUID PRIMARY KEY,
    node_id    UUID NOT NULL UNIQUE REFERENCES nodes(id),
    node_name  TEXT NOT NULL,
    doc_type   TEXT NOT NULL,
    body       TEXT NOT NULL,
    body_hash  TEXT NOT NULL CHECK (body_hash ~ '^[0-9a-f]{64}$'),
    audit_seq  BIGINT NOT NULL,
    audit_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE destruction_certificates;
DROP TABLE legal_holds;
DROP TABLE retention_records;
ALTER TABLE nodes DROP COLUMN destroyed_at;
DROP TABLE document_types;