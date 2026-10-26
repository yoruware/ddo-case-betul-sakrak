-- +goose Up
CREATE TABLE node_tags (
    node_id    UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    tag        TEXT NOT NULL CHECK (tag ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, tag)
);
CREATE INDEX idx_node_tags_tag ON node_tags (tag, node_id);

CREATE TABLE approval_requests (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id          UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    requested_by     UUID NOT NULL REFERENCES users(id),
    note             TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
    decided_by       UUID REFERENCES users(id),
    decided_at       TIMESTAMPTZ,
    decision_comment TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((status = 'pending') = (decided_by IS NULL)),
    CHECK (decided_by IS NULL OR decided_by <> requested_by)  -- görev ayrılığı
);
CREATE UNIQUE INDEX uq_approval_pending ON approval_requests (node_id) WHERE status = 'pending';
CREATE INDEX idx_approval_status ON approval_requests (status, created_at);

-- +goose Down
DROP TABLE approval_requests;
DROP TABLE node_tags;