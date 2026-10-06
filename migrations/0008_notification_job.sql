-- The job an event came from (a bake, a build): the bell opens its log.
ALTER TABLE notifications ADD COLUMN job TEXT NOT NULL DEFAULT '';
