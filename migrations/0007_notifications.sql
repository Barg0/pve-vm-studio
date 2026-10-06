-- What happened, for the topbar's bell: every event the studio can mail about, recorded
-- whether or not a mail goes out for it. Only the newest rows are kept (src/notify.rs).
CREATE TABLE notifications (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        TEXT NOT NULL,
    event     TEXT NOT NULL,              -- the notification's key (bake_done, vm_provisioned, ...)
    icon      TEXT NOT NULL,              -- a glyph name without .svg
    title     TEXT NOT NULL,
    subtitle  TEXT NOT NULL DEFAULT '',
    status    TEXT NOT NULL,              -- the mail's status word (DONE, FAILED, ...)
    tone      TEXT NOT NULL,              -- success | danger | warn | accent | neutral
    link      TEXT NOT NULL DEFAULT ''    -- where in the studio it can be looked at (#/golds)
);
