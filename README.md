# Toolframe Auth

Authentication and grant decisions for access passwords, federated users and
revocable agent delegation. This provider owns `auth`'s managed SQL store; it never opens
database files itself. It requires SDK 0.3.0 and `toolframe.storage.sql`.

## Install

With a running Toolframe application and an active SQL storage provider:

```sh
toolframe --home APP plugin add pypi:toolframe-auth==0.2.0 --enable
```

The [Entry Register template](https://github.com/toolframe/toolframe-core#readme)
includes Auth and Dashboard Auth. The host resolves the SDK and the plugin's
isolated environment automatically.

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

For the same isolated lint, tests, distribution and wheel-install checks used by
GitHub Actions, run `python3.14 scripts/ci.py`. See [CI and publishing](docs/ci.md)
for pinned sibling sources, local requirements and TestPyPI/PyPI setup.

Core owns access policy. Its compatible OIDC integration supports
`access.failure_mode = "closed"` for protected deployments; the default preserves
legacy public business fallback. MCP, llms and explicitly public business APIs
have independent policies.

For release validation and Trusted Publisher setup, see [releasing](docs/releasing.md).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## PostgreSQL storage

Version 0.2 requires SDK 0.3 and declares PostgreSQL migration SQL alongside the
unchanged SQLite history. Provision this plugin’s stable store owner with the
PostgreSQL provider before enabling it. The application still runs one Core;
retain its private keys and configuration with the application home. Existing
SQLite records are not imported automatically.

For development hooks and contribution rules, see [Contributing](CONTRIBUTING.md).
