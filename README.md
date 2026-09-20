# Toolframe Auth

Authentication and grant decisions for named access passwords, without user
accounts. This independent provider owns `auth`'s managed SQLite; it never opens
database files itself. It requires SDK 0.2 and `toolframe.storage.sql`.

Core supplies the private `password-lookup` key separately from configuration.
Credential records store a keyed HMAC-SHA256 lookup plus a per-record salted
scrypt verifier (`N=131072`, `r=8`, `p=1`, 32-byte output). At most two hashes run
concurrently. Core also limits login attempts. Sessions use random opaque tokens;
only SHA-256 digests of those high-entropy tokens are persisted. Metadata/list
responses exclude lookup values, salts and verifiers.

The internal `toolframe.auth` service implements login, resolve/touch, logout,
create/list/update/revoke. Core admits administrators and passes their trusted
principal/catalog. These methods are not directly published business APIs.
`toolframe-dashboard-auth` supplies presentation through core's protected API.

New passwords accept 8–32 characters; omitted passwords generate a random
32-character secret. Existing longer passwords issued by 0.1.0 can still log in.
This policy change requires no data migration and retains active sessions.

Active secret uniqueness is transactional. Expired/revoked secrets can be reused
in a new record with a new grant; old sessions remain tied to the old record.
Revoked records cannot be restored. Editing a grant invalidates its sessions.
Delegation is limited by the administrator's own scopes, dynamic-business selector
and expiry. Issued grants do not inherit a revocation dependency on their creator.

Configuration: `session_max_seconds` defaults to 604800; `session_idle_seconds`
defaults to 86400. Password expiry caps both. Successful logins and authorized
functional activity update usage; polling and denied attempts do not.

Back up the consistent auth SQLite store and retained private key together. A
missing key with an existing store is a recovery error, not a reason to regenerate
the key. Removing/reloading the plugin retains both. Runtime validation uses
temporary storage and secrets.

```sh
uv sync
uv run pytest -q
uv run ruff check src tests
uv build --wheel
```

Core 0.3's authentication documentation specifies public-by-default behavior,
explicit public fallback on active auth failure/disablement, normal reload waits,
local control and the independently public MCP/llms/business API entrances.
