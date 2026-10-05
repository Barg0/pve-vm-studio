-- One Windows auto-update: a newer Patch Tuesday build of the product a built ISO came
-- from, carried from "found" to "done" over as many maintenance windows as it takes. The
-- row is what lets the chain go on after a restart.
CREATE TABLE update_runs (
    id            TEXT PRIMARY KEY,
    source_iso    TEXT NOT NULL,          -- the built ISO the followers were baked from
    product       TEXT NOT NULL,          -- uup product id: ws2025
    from_build    TEXT NOT NULL,          -- 26100.4061
    to_build      TEXT NOT NULL,
    to_uuid       TEXT NOT NULL,          -- the UUP dump build id of to_build
    release       TEXT NOT NULL DEFAULT '', -- "2026-10 B"
    step          TEXT NOT NULL,          -- pending | iso | bake | cleanup | done | failed | stopped
    new_iso       TEXT,
    golds         TEXT NOT NULL DEFAULT '[]', -- [{ "from": id, "to": id|null }]
    job_id        TEXT,                   -- the step's job while it runs
    error         TEXT,
    failed_step   TEXT,                   -- where a failed run stopped, for Retry
    force         INTEGER NOT NULL DEFAULT 0, -- "Start now": the next step does not wait for a window
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
