
CREATE TABLE credentials (
 id TEXT PRIMARY KEY, label TEXT NOT NULL, lookup TEXT NOT NULL,
 salt TEXT NOT NULL, verifier TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL,
 expires_at DOUBLE PRECISION, revoked_at DOUBLE PRECISION, scopes TEXT NOT NULL,
 all_business INTEGER NOT NULL, last_login DOUBLE PRECISION, last_used DOUBLE PRECISION
);
CREATE INDEX credentials_lookup ON credentials(lookup);
CREATE TABLE sessions (
 digest TEXT PRIMARY KEY, credential_id TEXT NOT NULL REFERENCES credentials(id),
 created_at DOUBLE PRECISION NOT NULL, absolute_expires DOUBLE PRECISION NOT NULL,
 last_activity DOUBLE PRECISION NOT NULL, invalidated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX sessions_credential ON sessions(credential_id);
