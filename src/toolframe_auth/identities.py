"""Local identities, browser sessions and revocable delegation authority."""

import json
import math
import secrets
import time
import uuid

from toolframe_sdk import PluginError, Principal

from .crypto import session_digest

SCHEMA = """
CREATE TABLE users (
 id TEXT PRIMARY KEY, label TEXT NOT NULL, scopes TEXT NOT NULL,
 created_at REAL NOT NULL, expires_at REAL, disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE external_identities (
 issuer TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL REFERENCES users(id),
 PRIMARY KEY(issuer,subject)
);
CREATE TABLE user_sessions (
 digest TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 created_at REAL NOT NULL, absolute_expires REAL NOT NULL, last_activity REAL NOT NULL,
 invalidated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX user_sessions_user ON user_sessions(user_id);
CREATE TABLE agent_grants (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 issuer TEXT NOT NULL, client_id TEXT NOT NULL, client_name TEXT NOT NULL,
 resource TEXT NOT NULL, scopes TEXT NOT NULL, created_at REAL NOT NULL,
 expires_at REAL NOT NULL, revoked_at REAL
);
CREATE INDEX agent_grants_user ON agent_grants(user_id);
"""

METHODS = (
    "federated_login",
    "users",
    "user_update",
    "grant_create",
    "grant_check",
    "grants",
    "revoke_grant",
)


def public(record):
    return {**record, "scopes": json.loads(record["scopes"])}


def text(value, maximum=2048):
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and not any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value)
    )


class IdentityAuthority:
    def __init__(self, authority):
        self.auth = authority
        self.context = authority.context
        self.store = authority.store

    def trusted_provider(self):
        if self.context.call_info.get("owner") != self.context.config.get(
            "identity_provider", "oidc-auth"
        ):
            raise PluginError(
                "forbidden",
                "Only the configured identity provider may authenticate users",
            )

    def actor(self):
        value = self.context.call_info.get("principal")
        if not value:
            raise PluginError(
                "authentication_required", "Sign in to manage your account"
            )
        return Principal.model_validate(value)

    def administrator(self):
        actor = self.actor()
        if not actor.unrestricted and "system.auth.users" not in actor.scopes:
            raise PluginError("forbidden", "User administration permission required")
        return actor

    async def user(self, identifier, store=None):
        if not text(identifier, 128):
            raise PluginError("invalid_credentials", "User is unavailable")
        rows = await (store or self.store).query(
            "SELECT * FROM users WHERE id=?", [identifier]
        )
        if not rows:
            raise PluginError("invalid_credentials", "User is unavailable")
        return rows[0]

    def active(self, user):
        if user["disabled"] or (
            user["expires_at"] is not None and user["expires_at"] <= time.time()
        ):
            raise PluginError("invalid_credentials", "User is unavailable")

    def principal(self, user):
        self.active(user)
        return Principal(
            kind="user",
            credential_id=user["id"],
            user_id=user["id"],
            scopes=tuple(
                sorted(set(json.loads(user["scopes"])) | {"system.auth.self"})
            ),
            expires_at=user["expires_at"],
        )

    def scopes(self, values, *, business=False):
        catalog = self.context.call_info.get("scope_catalog", {})
        if not isinstance(values, list) or not all(
            isinstance(s, str)
            and s in catalog
            and (not business or catalog[s].get("category") == "business")
            for s in values
        ):
            raise PluginError("invalid_request", "Supply declared permissions")
        return sorted(set(values))

    async def login(self, params):
        self.trusted_provider()
        issuer, subject = params.get("issuer"), params.get("subject")
        if not text(issuer) or not text(subject, 255):
            raise PluginError("invalid_credentials", "Invalid external identity")
        async with self.store.transaction() as store:
            links = await store.query(
                "SELECT user_id FROM external_identities WHERE issuer=? AND subject=?",
                [issuer, subject],
            )
            if links:
                user = await self.user(links[0]["user_id"], store)
            else:
                admission = next(
                    (
                        rule
                        for rule in self.context.config.get("federated_identities", [])
                        if rule["issuer"] == issuer and rule["subject"] == subject
                    ),
                    None,
                )
                if admission is None:
                    raise PluginError(
                        "forbidden",
                        "This identity has not been admitted by an administrator",
                    )
                scopes = self.scopes(admission["scopes"])
                identifier = uuid.uuid4().hex
                await store.execute(
                    "INSERT INTO users(id,label,scopes,created_at) VALUES(?,?,?,?)",
                    [identifier, admission["label"], json.dumps(scopes), time.time()],
                )
                await store.execute(
                    "INSERT INTO external_identities VALUES(?,?,?)",
                    [issuer, subject, identifier],
                )
                user = await self.user(identifier, store)
            actor = self.principal(user)
            now = time.time()
            expiry = min(now + self.auth.lifetime, user["expires_at"] or float("inf"))
            token = "tf_user_" + secrets.token_urlsafe(32)
            await store.execute(
                "INSERT INTO user_sessions(digest,user_id,created_at,absolute_expires,last_activity) VALUES(?,?,?,?,?)",
                [session_digest(token), user["id"], now, expiry, now],
            )
        return {"token": token, "expires_at": expiry, "principal": actor.model_dump()}

    async def resolve(self, params):
        token = params.get("token")
        if not isinstance(token, str) or len(token) > 256:
            raise PluginError("session_invalid", "Sign in again")
        rows = await self.store.query(
            "SELECT * FROM user_sessions WHERE digest=?", [session_digest(token)]
        )
        if not rows:
            raise PluginError("session_invalid", "Sign in again")
        session, now = rows[0], time.time()
        if (
            session["invalidated"]
            or now >= session["absolute_expires"]
            or now >= session["last_activity"] + self.auth.idle
        ):
            raise PluginError("session_invalid", "Sign in again")
        try:
            actor = self.principal(await self.user(session["user_id"]))
        except PluginError:
            raise PluginError("session_invalid", "Sign in again") from None
        if params.get("activity", False):
            await self.store.execute(
                "UPDATE user_sessions SET last_activity=? WHERE digest=?",
                [now, session["digest"]],
            )
        return {"principal": actor.model_dump()}

    async def invoke(self, method, params):
        if method == "federated_login":
            return await self.login(params)
        if method == "users":
            actor = self.administrator()
            rows = await self.store.query(
                "SELECT * FROM users ORDER BY created_at DESC"
            )
            return {
                "users": [
                    public(r)
                    for r in rows
                    if actor.unrestricted
                    or actor.allows(
                        json.loads(r["scopes"]),
                        self.context.call_info.get("scope_catalog", {}),
                    )
                ]
            }
        if method == "user_update":
            actor = self.administrator()
            user = await self.user(params.get("id"))
            scopes = self.scopes(params.get("scopes"))
            expiry, disabled = params.get("expires_at"), params.get("disabled", False)
            if not isinstance(disabled, bool) or (
                expiry is not None
                and (
                    type(expiry) not in (int, float)
                    or not math.isfinite(expiry)
                    or expiry <= time.time()
                )
            ):
                raise PluginError(
                    "invalid_request", "Supply a valid user expiry and disabled flag"
                )
            self.auth.bounds(
                actor, json.loads(user["scopes"]), False, user["expires_at"]
            )
            self.auth.bounds(actor, scopes, False, expiry)
            async with self.store.transaction() as store:
                await store.execute(
                    "UPDATE users SET scopes=?,expires_at=?,disabled=? WHERE id=?",
                    [json.dumps(scopes), expiry, int(disabled), user["id"]],
                )
                if disabled:
                    await store.execute(
                        "UPDATE user_sessions SET invalidated=1 WHERE user_id=?",
                        [user["id"]],
                    )
                    await store.execute(
                        "UPDATE agent_grants SET revoked_at=COALESCE(revoked_at,?) WHERE user_id=?",
                        [time.time(), user["id"]],
                    )
            return {"user": public(await self.user(user["id"]))}
        if method == "grant_create":
            self.trusted_provider()
            user = await self.user(params.get("user_id"))
            actor = self.principal(user)
            scopes = self.scopes(params.get("scopes"), business=True)
            expiry = params.get("expires_at")
            if (
                not scopes
                or type(expiry) not in (int, float)
                or not math.isfinite(expiry)
                or not time.time() < expiry <= time.time() + 31536000
            ):
                raise PluginError(
                    "invalid_request",
                    "Supply business scopes and a bounded grant expiry",
                )
            if not all(
                text(params.get(k))
                for k in ("issuer", "client_id", "client_name", "resource")
            ):
                raise PluginError(
                    "invalid_request", "Supply the client, issuer and resource"
                )
            self.auth.bounds(actor, scopes, False, expiry)
            identifier = uuid.uuid4().hex
            await self.store.execute(
                "INSERT INTO agent_grants(id,user_id,issuer,client_id,client_name,resource,scopes,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
                [
                    identifier,
                    user["id"],
                    params["issuer"],
                    params["client_id"],
                    params["client_name"],
                    params["resource"],
                    json.dumps(scopes),
                    time.time(),
                    expiry,
                ],
            )
            return {"id": identifier}
        if method == "grant_check":
            self.trusted_provider()
            if not text(params.get("id"), 128):
                raise PluginError("invalid_credentials", "Grant is unavailable")
            rows = await self.store.query(
                "SELECT * FROM agent_grants WHERE id=?", [params.get("id")]
            )
            if not rows:
                raise PluginError("invalid_credentials", "Grant is unavailable")
            grant = rows[0]
            user = await self.user(grant["user_id"])
            actor = self.principal(user)
            if grant["revoked_at"] is not None or grant["expires_at"] <= time.time():
                raise PluginError("invalid_credentials", "Grant is unavailable")
            scopes = self.scopes(json.loads(grant["scopes"]), business=True)
            # Permission reductions affect existing grants without issuing new tokens.
            scopes = [s for s in scopes if s in actor.scopes]
            return {
                "grant": {
                    **public(grant),
                    "scopes": scopes,
                    "expires_at": min(
                        grant["expires_at"], user["expires_at"] or float("inf")
                    ),
                }
            }
        if method == "grants":
            actor = self.actor()
            if actor.kind != "user" or not actor.user_id:
                raise PluginError("forbidden", "Sign in with a user identity")
            self.active(await self.user(actor.user_id))
            rows = await self.store.query(
                "SELECT * FROM agent_grants WHERE user_id=? ORDER BY created_at DESC",
                [actor.user_id],
            )
            return {"grants": [public(r) for r in rows]}
        if method == "revoke_grant":
            if not text(params.get("id"), 128):
                raise PluginError("invalid_request", "Unknown grant")
            rows = await self.store.query(
                "SELECT * FROM agent_grants WHERE id=?", [params.get("id")]
            )
            if not rows:
                raise PluginError("invalid_request", "Unknown grant")
            if self.context.call_info.get("owner") != self.context.config.get(
                "identity_provider", "oidc-auth"
            ):
                actor = self.actor()
                if not actor.unrestricted and not (
                    actor.kind == "user" and actor.user_id == rows[0]["user_id"]
                ):
                    raise PluginError(
                        "forbidden", "You can only revoke your own grants"
                    )
            await self.store.execute(
                "UPDATE agent_grants SET revoked_at=COALESCE(revoked_at,?) WHERE id=?",
                [time.time(), rows[0]["id"]],
            )
            return {"revoked": True}
        raise PluginError("invalid_request", "Unknown identity operation")
