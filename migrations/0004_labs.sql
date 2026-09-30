-- A lab is what the Hyper-V studio kept in its state token: the designed VMs, networks,
-- identity catalogs and defaults. Stored whole, as the studio's own JSON; `revision`
-- goes up with every save, so two people editing one lab get a conflict, not a silent
-- overwrite.
CREATE TABLE labs (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT '{}',
    revision    INTEGER NOT NULL DEFAULT 0,
    updated_by  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
