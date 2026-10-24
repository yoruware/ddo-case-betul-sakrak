-- +goose Up
CREATE TABLE groups (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE group_members (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  UUID NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX idx_group_members_user ON group_members (user_id);

CREATE TABLE nodes (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id    UUID REFERENCES nodes(id) ON DELETE RESTRICT,
    kind         TEXT NOT NULL CHECK (kind IN ('folder','file')),
    name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    owner_id     UUID NOT NULL REFERENCES users(id),
    -- kökten kendisine kadar atalar (kendisi dahil, sıralı)
    ancestor_ids UUID[] NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (ancestor_ids[array_upper(ancestor_ids, 1)] = id)
);
-- aynı klasörde aynı ad tekrar edemez
CREATE UNIQUE INDEX uq_nodes_parent_name
    ON nodes (COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid), name);
CREATE INDEX idx_nodes_parent    ON nodes (parent_id);
CREATE INDEX idx_nodes_ancestors ON nodes USING GIN (ancestor_ids);

CREATE TABLE acl_entries (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id      UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('user','group')),
    subject_id   UUID NOT NULL,
    permission   TEXT NOT NULL CHECK (permission IN ('read','write','delete','share','manage')),
    effect       TEXT NOT NULL CHECK (effect IN ('allow','deny')),
    created_by   UUID NOT NULL REFERENCES users(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (node_id, subject_type, subject_id, permission)
);
CREATE INDEX idx_acl_node    ON acl_entries (node_id);
CREATE INDEX idx_acl_subject ON acl_entries (subject_type, subject_id);

-- +goose Down
DROP TABLE acl_entries;
DROP TABLE nodes;
DROP TABLE group_members;
DROP TABLE groups;