-- Every mail the studio handed to the smart host, with what the smart host answered: the
-- Mail card's log. Only the newest rows are kept (src/mail.rs).
CREATE TABLE mail_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    event       TEXT NOT NULL,              -- the notification's key, or "test"
    subject     TEXT NOT NULL,
    sender      TEXT NOT NULL,
    recipients  TEXT NOT NULL DEFAULT '[]', -- JSON array
    host        TEXT NOT NULL,              -- host:port
    security    TEXT NOT NULL,              -- none | starttls | tls
    ok          INTEGER NOT NULL,
    code        INTEGER,                    -- the SMTP reply code, when there was a reply
    reply       TEXT NOT NULL DEFAULT '',   -- the reply's lines, one per line
    error       TEXT NOT NULL DEFAULT '',   -- why it did not go out
    took_ms     INTEGER NOT NULL
);
CREATE INDEX mail_log_at ON mail_log (at);
