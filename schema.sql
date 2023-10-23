CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE logs (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  timestamp INTEGER NOT NULL,
  contents TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE journals (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  -- The timestamp (day) the journal is for
  timestamp INTEGER NOT NULL,
  -- When the journal was added
  added_at INTEGER NOT NULL,
  -- Path relative to the journals directory
  path TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
