-- Studio-wide settings, one JSON document per key (e.g. "bake": where bakes run).
CREATE TABLE settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- Every bake that produced (or tried to produce) a gold. A gold is a PVE template; a
-- rebake makes a new one and never touches the old, as on Hyper-V.
CREATE TABLE golds (
    id          TEXT PRIMARY KEY,
    image_id    TEXT NOT NULL,          -- catalog id: debian13, ws2025-datacenter-core...
    os          TEXT NOT NULL,          -- linux | windows
    name        TEXT NOT NULL,          -- the template's name in PVE
    node        TEXT NOT NULL,
    vmid        INTEGER,
    storage     TEXT NOT NULL,          -- where its disk lives - clones need the same one
    status      TEXT NOT NULL,          -- baking | ready | failed | removed
    options     TEXT NOT NULL DEFAULT '{}',
    manifest    TEXT NOT NULL DEFAULT '{}',
    job_id      TEXT,
    created_at  TEXT NOT NULL
);

CREATE INDEX golds_image ON golds (image_id, created_at DESC);
