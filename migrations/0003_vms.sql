-- VMs the studio built. PVE is the truth for what exists; this is what the studio knows
-- about each one: which gold, which lab, what it was asked to be.
CREATE TABLE vms (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    lab_id      TEXT,
    gold_id     TEXT NOT NULL,
    node        TEXT NOT NULL DEFAULT '',
    vmid        INTEGER,
    status      TEXT NOT NULL,          -- building | ready | failed | removed
    spec        TEXT NOT NULL,          -- the request, secrets removed
    ip          TEXT,
    job_id      TEXT,
    created_at  TEXT NOT NULL
);

CREATE INDEX vms_gold ON vms (gold_id);
CREATE INDEX vms_lab ON vms (lab_id);
