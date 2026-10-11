-- The queue's order: a waiting job starts before the ones with a higher number. Kept with
-- the job, so the queue comes back in the same order after a restart.
ALTER TABLE jobs ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;
