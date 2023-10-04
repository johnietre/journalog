CREATE TABLE users (
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(60) NOT NULL,
);
