-- Every long-running action is a job: bake, deploy, destroy... Its log is a file under
-- <data_dir>/jobs/<id>.log; this table holds what the job list needs.
CREATE TABLE jobs (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    title       TEXT NOT NULL,
    status      TEXT NOT NULL,          -- queued | running | succeeded | failed | interrupted
    created_by  TEXT NOT NULL,          -- PVE user id, e.g. root@pam
    params      TEXT NOT NULL DEFAULT '{}',
    error       TEXT,
    created_at  TEXT NOT NULL,
    started_at  TEXT,
    ended_at    TEXT
);

CREATE INDEX jobs_created_at ON jobs (created_at DESC);
