
CREATE TABLE users (
 id TEXT PRIMARY KEY, label TEXT NOT NULL, scopes TEXT NOT NULL,
 created_at DOUBLE PRECISION NOT NULL, expires_at DOUBLE PRECISION, disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE external_identities (
 issuer TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id),
 PRIMARY KEY(issuer,subject)
);
CREATE TABLE user_sessions (
 digest TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 created_at DOUBLE PRECISION NOT NULL, absolute_expires DOUBLE PRECISION NOT NULL, last_activity DOUBLE PRECISION NOT NULL,
 invalidated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX user_sessions_user ON user_sessions(user_id);
CREATE TABLE agent_grants (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 issuer TEXT NOT NULL, client_id TEXT NOT NULL, client_name TEXT NOT NULL,
 resource TEXT NOT NULL, scopes TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL,
 expires_at DOUBLE PRECISION NOT NULL, revoked_at DOUBLE PRECISION
);
CREATE INDEX agent_grants_user ON agent_grants(user_id);
