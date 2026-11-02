-- Multi-user accounts: user roles, provider visibility, invite codes,
-- usage counters, and shared-pool global settings.
--
-- SQLite `ALTER TABLE ADD COLUMN` accepts a CHECK constraint only while the
-- default value satisfies it (both defaults here do), so the plain ALTERs
-- below are safe without a table rebuild.

-- Every existing account becomes a member; the built-in system default user
-- (login name `admin`) is promoted to admin — it is the bootstrap account and
-- must be able to administer the deployment. Fresh installs get the same
-- outcome because the seed INSERT in `ensure_system_user` specifies the role
-- explicitly.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('admin', 'member'));
UPDATE users SET role = 'admin' WHERE id = 'system_default_user';

-- Providers are private to their owner unless explicitly shared with the
-- shared-key pool. Existing rows keep their current effective visibility.
ALTER TABLE providers ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private' CHECK(visibility IN ('private', 'shared'));

-- Invite codes for `POST /api/auth/register`. Only the SHA-256 hash of a code
-- is stored; the plaintext is shown to the creating admin exactly once.
CREATE TABLE IF NOT EXISTS invite_codes (
    id         TEXT PRIMARY KEY NOT NULL,
    code_hash  TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    used_by    TEXT,
    used_at    INTEGER,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_invite_codes_created_at ON invite_codes(created_at DESC);

-- Per-user, per-provider, per-day request counters backing the shared-pool
-- daily cap. `day` is a `YYYY-MM-DD` UTC string.
CREATE TABLE IF NOT EXISTS usage_counters (
    user_id     TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    day         TEXT NOT NULL,
    requests    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, provider_id, day)
);

-- Singleton row (id = 1) for shared-key-pool settings. Seeded immediately so
-- `get` never sees an empty table.
CREATE TABLE IF NOT EXISTS global_settings (
    id                            INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
    shared_key_service_enabled    INTEGER NOT NULL DEFAULT 0,
    shared_pool_daily_request_cap INTEGER NOT NULL DEFAULT 100
);
INSERT OR IGNORE INTO global_settings (id, shared_key_service_enabled, shared_pool_daily_request_cap) VALUES (1, 0, 100);
