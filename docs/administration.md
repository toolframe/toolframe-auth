# Passwords, users and grants

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
The password-length policy preserves existing password records and sessions.

## Federated users and agent grants

Enable `toolframe-oidc-auth` for OIDC login. Auth remains the local identity and
permission authority; it does not implement provider discovery or OAuth endpoints.
Configure the trusted plugin ID with `identity_provider` (default `oidc-auth`) and
initial admission with exact `federated_identities` entries:

```toml
[plugins.auth.config]
identity_provider = "oidc-auth"
federated_identities = [
  { issuer = "https://accounts.google.com", subject = "VERIFIED_SUB", label = "Alice", scopes = ["notes.read"] },
]
```

The trusted plugin must supply verified issuer/subject claims. No email matching
or automatic account merging occurs. The admission entry creates a local user
once; later permission/disablement changes use the protected user-management API.
Changing admission configuration does not overwrite existing users. Every user
gets `system.auth.self`; `system.auth.users` permits bounded administration.

The internal service additionally implements `federated_login`, `users`,
`user_update`, `grant_create`, `grant_check`, `grants` and `revoke_grant`.
Core verifies administrative/self-service callers; only the configured identity
provider may admit external identities or issue/check delegated grants.
Agent grants include user, issuer, client, resource, explicit business scopes and
expiry. Grant checks intersect current user permissions. Revocation does not end
the browser session; disabling a user invalidates sessions and revokes all their
agent grants. Password and MCP-key credentials retain their independent behavior.

This feature introduces additive **store revision v2**. Existing v1 stores require
Core's explicit `migrate plan auth` / `migrate apply auth --plan-id ...` workflow
after staging a compatible Auth build. Back up the store and retained secrets
first. The migration leaves existing password/session tables intact.

Active secret uniqueness is transactional. Expired/revoked secrets can be reused
in a new record with a new grant; old sessions remain tied to the old record.
Revoked records cannot be restored. Editing a grant invalidates its sessions.
Delegation is limited by the administrator's own scopes, dynamic-business selector
and expiry. Issued grants do not inherit a revocation dependency on their creator.

Configuration: `session_max_seconds` defaults to 604800; `session_idle_seconds`
defaults to 86400. Password expiry caps both. Successful logins and authorized
functional activity update usage; polling and denied attempts do not.

Back up the consistent auth store with its provider’s backup procedure, and retain
the private key with that backup. A
missing key with an existing store is a recovery error, not a reason to regenerate
the key. Removing/reloading the plugin retains both. Runtime validation uses
temporary storage and secrets.

Core owns access policy. Its compatible OIDC integration supports
`access.failure_mode = "closed"` for protected deployments; the default preserves
legacy public business fallback. MCP, llms and explicitly public business APIs
have independent policies.

## PostgreSQL storage

Version 0.3 requires SDK 0.4 and declares PostgreSQL migration SQL alongside the
unchanged SQLite history. Provision this plugin’s stable store owner with the
PostgreSQL provider before enabling it. The application still runs one Core;
retain its private keys and configuration with the application home. Existing
SQLite records are not imported automatically.
