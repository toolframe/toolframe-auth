"""Credential authority. All persistence goes through the managed SQL service."""

from __future__ import annotations

import asyncio
import hmac
import json
import re
import secrets
import time
import uuid
from importlib.resources import files

from toolframe_sdk import (
    AuthorizationSpec,
    MethodSpec,
    Migration,
    Plugin,
    PluginDefinition,
    PluginError,
    Principal,
    Requirement,
    ServiceSpec,
    StoreSchema,
)

from .crypto import lookup, new_verifier, session_digest, verifier
from .identities import METHODS as IDENTITY_METHODS
from .identities import SCHEMA as IDENTITY_SCHEMA
from .identities import IdentityAuthority

SERVICE = "toolframe.auth"
SCHEMA = """
CREATE TABLE credentials (
 id TEXT PRIMARY KEY, label TEXT NOT NULL, lookup TEXT NOT NULL,
 salt TEXT NOT NULL, verifier TEXT NOT NULL, created_at REAL NOT NULL,
 expires_at REAL, revoked_at REAL, scopes TEXT NOT NULL,
 all_business INTEGER NOT NULL, last_login REAL, last_used REAL
);
CREATE INDEX credentials_lookup ON credentials(lookup);
CREATE TABLE sessions (
 digest TEXT PRIMARY KEY, credential_id TEXT NOT NULL REFERENCES credentials(id),
 created_at REAL NOT NULL, absolute_expires REAL NOT NULL,
 last_activity REAL NOT NULL, invalidated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX sessions_credential ON sessions(credential_id);
"""
EXPECTED_ERRORS = {
    "invalid_credentials",
    "session_invalid",
    "password_conflict",
    "credential_missing",
    "credential_revoked",
    "invalid_request",
    "forbidden",
    "rate_limited",
}


def valid(record, now):
    return record["revoked_at"] is None and (
        record["expires_at"] is None or record["expires_at"] > now
    )


def valid_text(value):
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
        return True
    except UnicodeError:
        return False


def principal(record):
    return Principal(
        kind="password",
        credential_id=record["id"],
        scopes=tuple(json.loads(record["scopes"])),
        all_business=bool(record["all_business"]),
        expires_at=record["expires_at"],
    )


def public_record(record):
    return {
        key: value
        for key, value in record.items()
        if key not in {"lookup", "salt", "verifier"}
    } | {
        "scopes": json.loads(record["scopes"]),
        "all_business": bool(record["all_business"]),
    }


class AuthProvider(Plugin):
    def __init__(self, context):
        super().__init__(context)
        self.lock = asyncio.Lock()
        self.key = None
        self.store = context.storage()
        self.idle = context.config.get("session_idle_seconds", 86400)
        self.lifetime = context.config.get("session_max_seconds", 604800)
        self.pending_hashes = 0
        self.identities = IdentityAuthority(self)

    async def activate(self):
        self.key = bytes.fromhex(self.context.private_secrets["password-lookup"])
        # Probe read is allowed during activation; host already ensured the schema.
        await self.store.query("SELECT id FROM credentials LIMIT 1")

    async def rows(self, sql, params=(), store=None):
        return await (store or self.store).query(sql, params)

    async def get(self, identifier, store=None):
        rows = await self.rows(
            "SELECT * FROM credentials WHERE id=?", [identifier], store
        )
        if not rows:
            raise PluginError("credential_missing", "Access password record not found")
        return rows[0]

    def actor(self):
        value = self.context.call_info.get("principal")
        if not value:
            raise PluginError("forbidden", "A host-admitted administrator is required")
        actor = Principal.model_validate(value)
        if not actor.unrestricted and "system.auth.passwords" not in actor.scopes:
            raise PluginError("forbidden", "Password management scope required")
        return actor

    def bounds(self, actor, scopes, all_business, expires_at):
        if actor.unrestricted:
            return
        catalog = self.context.call_info.get("scope_catalog", {})
        if (all_business and not actor.all_business) or not actor.allows(
            scopes, catalog
        ):
            raise PluginError(
                "forbidden", "Cannot delegate scopes beyond your own grant"
            )
        if actor.expires_at is not None and (
            expires_at is None or expires_at > actor.expires_at
        ):
            raise PluginError(
                "forbidden", "Cannot delegate beyond your password expiry"
            )

    def fields(self, params):
        label, scopes = params.get("label", ""), params.get("scopes", [])
        expiry, all_business = (
            params.get("expires_at"),
            params.get("all_business", False),
        )
        catalog = self.context.call_info.get("scope_catalog", {})
        if (
            not valid_text(label)
            or not label.strip()
            or len(label) > 120
            or not isinstance(scopes, list)
            or not all(isinstance(x, str) and x in catalog for x in scopes)
            or not isinstance(all_business, bool)
            or (
                expiry is not None
                and (
                    isinstance(expiry, bool)
                    or not isinstance(expiry, (int, float))
                    or not time.time() < expiry < 253402300800
                )
            )
        ):
            raise PluginError(
                "invalid_request",
                "Supply a label, known scopes and a future expiry (or null)",
            )
        return label.strip(), sorted(set(scopes)), all_business, expiry

    async def hash_work(self, function, *args):
        # Reject excess work before submitting to the thread pool; no unbounded queue.
        if self.pending_hashes >= 2:
            raise PluginError("rate_limited", "Password verifier is busy; retry later")
        self.pending_hashes += 1
        task = asyncio.create_task(asyncio.to_thread(function, *args))
        try:
            return await asyncio.shield(task)
        finally:
            # Cancellation cannot release the memory budget before scrypt finishes.
            if not task.done():
                await asyncio.shield(task)
            self.pending_hashes -= 1

    async def invoke(self, service, method, params):
        if method == "login":
            return await self.login(params)
        if method == "create":
            return await self.create(params)
        async with self.lock:
            if method in IDENTITY_METHODS:
                return await self.identities.invoke(method, params)
            if method == "resolve":
                if isinstance(params.get("token"), str) and params["token"].startswith(
                    "tf_user_"
                ):
                    return await self.identities.resolve(params)
                return await self.resolve(params)
            if method == "logout":
                await self.store.execute(
                    "UPDATE sessions SET invalidated=1 WHERE digest=?",
                    [session_digest(params["token"])],
                )
                await self.store.execute(
                    "UPDATE user_sessions SET invalidated=1 WHERE digest=?",
                    [session_digest(params["token"])],
                )
                return {}
            actor = self.actor()
            if method == "list":
                records = await self.rows(
                    "SELECT * FROM credentials ORDER BY created_at DESC"
                )
                result = []
                for record in records:
                    try:
                        self.bounds(
                            actor,
                            json.loads(record["scopes"]),
                            record["all_business"],
                            record["expires_at"],
                        )
                    except PluginError:
                        continue
                    result.append(public_record(record))
                return {"credentials": result}
            if method in {"update", "revoke"}:
                if not isinstance(params.get("id"), str) or not re.fullmatch(
                    r"[0-9a-f]{32}", params["id"]
                ):
                    raise PluginError(
                        "invalid_request", "Supply a credential record ID"
                    )
                async with self.store.transaction() as store:
                    record = await self.get(params.get("id"), store)
                    self.bounds(
                        actor,
                        json.loads(record["scopes"]),
                        record["all_business"],
                        record["expires_at"],
                    )
                    if method == "revoke":
                        await store.execute(
                            "UPDATE credentials SET revoked_at=COALESCE(revoked_at,?) WHERE id=?",
                            [time.time(), record["id"]],
                        )
                    else:
                        if record["revoked_at"] is not None:
                            raise PluginError(
                                "credential_revoked",
                                "Create a new password record instead",
                            )
                        label, scopes, all_business, expiry = self.fields(params)
                        self.bounds(actor, scopes, all_business, expiry)
                        await self.unique(
                            record["lookup"], exclude=record["id"], store=store
                        )
                        await store.execute(
                            "UPDATE credentials SET label=?,scopes=?,all_business=?,expires_at=? WHERE id=?",
                            [
                                label,
                                json.dumps(scopes),
                                int(all_business),
                                expiry,
                                record["id"],
                            ],
                        )
                    # Grant/expiry changes require a fresh login. Revocation is immediate.
                    await store.execute(
                        "UPDATE sessions SET invalidated=1 WHERE credential_id=?",
                        [record["id"]],
                    )
                    return public_record(await self.get(record["id"], store))
            raise PluginError("invalid_request", "Unknown auth operation")

    async def unique(self, index, *, exclude="", store=None):
        rows = await self.rows(
            "SELECT id FROM credentials WHERE lookup=? AND id<>? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)",
            [index, exclude, time.time()],
            store,
        )
        if rows:
            raise PluginError(
                "password_conflict", "This password already has an active authorization"
            )

    async def create(self, params):
        actor = self.actor()
        label, scopes, all_business, expiry = self.fields(params)
        self.bounds(actor, scopes, all_business, expiry)
        secret = params.get("password")
        generated = secret is None
        if generated:
            secret = secrets.token_urlsafe(24)
        if not valid_text(secret) or not 8 <= len(secret) <= 32:
            raise PluginError(
                "invalid_request", "Passwords must contain 8–32 characters"
            )
        index = lookup(self.key, secret)
        salt, encoded = await self.hash_work(new_verifier, secret)
        async with self.lock, self.store.transaction() as store:
            await self.unique(index, store=store)
            first = not await self.rows(
                "SELECT id FROM credentials LIMIT 1", store=store
            )
            identifier = uuid.uuid4().hex
            await store.execute(
                "INSERT INTO credentials(id,label,lookup,salt,verifier,created_at,expires_at,scopes,all_business) VALUES(?,?,?,?,?,?,?,?,?)",
                [
                    identifier,
                    label,
                    index,
                    salt,
                    encoded,
                    time.time(),
                    expiry,
                    json.dumps(scopes),
                    int(all_business),
                ],
            )
            result = public_record(await self.get(identifier, store))
        return {
            "credential": result,
            "first_password": first,
            "password": secret if generated else None,
        }

    async def login(self, params):
        secret = params.get("password")
        if not valid_text(secret) or not 1 <= len(secret) <= 1024:
            raise PluginError("invalid_credentials", "Invalid password")
        # Unique active lookup is serialized with create/extend/revoke.
        async with self.lock:
            records = await self.rows(
                "SELECT * FROM credentials WHERE lookup=? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)",
                [lookup(self.key, secret), time.time()],
            )
            record = records[0] if len(records) == 1 else None
        # Dummy verification makes unknown/expired passwords take the same hash work.
        salt = record["salt"] if record else "00" * 16
        result = await self.hash_work(verifier, secret, salt)
        if record is None or not hmac.compare_digest(result, record["verifier"]):
            raise PluginError("invalid_credentials", "Invalid password")
        async with self.lock, self.store.transaction() as store:
            record = await self.get(record["id"], store)
            now = time.time()
            if not valid(record, now):
                raise PluginError("invalid_credentials", "Invalid password")
            token = secrets.token_urlsafe(32)
            expires = min(now + self.lifetime, record["expires_at"] or float("inf"))
            await store.execute(
                "INSERT INTO sessions(digest,credential_id,created_at,absolute_expires,last_activity) VALUES(?,?,?,?,?)",
                [session_digest(token), record["id"], now, expires, now],
            )
            await store.execute(
                "UPDATE credentials SET last_login=?,last_used=? WHERE id=?",
                [now, now, record["id"]],
            )
        return {
            "token": token,
            "expires_at": expires,
            "principal": principal(record).model_dump(),
        }

    async def resolve(self, params):
        token = params.get("token", "")
        if not valid_text(token) or len(token) > 256:
            raise PluginError("session_invalid", "Sign in again")
        sessions = await self.rows(
            "SELECT * FROM sessions WHERE digest=?", [session_digest(token)]
        )
        if not sessions:
            raise PluginError("session_invalid", "Sign in again")
        session = sessions[0]
        record = await self.get(session["credential_id"])
        now = time.time()
        if (
            session["invalidated"]
            or now >= session["absolute_expires"]
            or now >= session["last_activity"] + self.idle
            or not valid(record, now)
        ):
            if not session["invalidated"]:
                await self.store.execute(
                    "UPDATE sessions SET invalidated=1 WHERE digest=?",
                    [session["digest"]],
                )
            raise PluginError("session_invalid", "Sign in again")
        if params.get("activity", False):
            async with self.store.transaction() as store:
                await store.execute(
                    "UPDATE sessions SET last_activity=? WHERE digest=?",
                    [now, session["digest"]],
                )
                await store.execute(
                    "UPDATE credentials SET last_used=? WHERE id=?", [now, record["id"]]
                )
        return {"principal": principal(record).model_dump()}


plugin = PluginDefinition(
    id="auth",
    kind="provider",
    provider_kind="auth",
    factory="toolframe_auth.plugin:AuthProvider",
    authorization=AuthorizationSpec(),
    private_secrets=("password-lookup",),
    requires={"storage": Requirement(service="toolframe.storage.sql")},
    services={
        SERVICE: ServiceSpec(
            methods={
                name: MethodSpec(audience="internal")
                for name in (
                    "login",
                    "resolve",
                    "logout",
                    "create",
                    "list",
                    "update",
                    "revoke",
                    *IDENTITY_METHODS,
                )
            }
        )
    },
    config_schema={
        "type": "object",
        "properties": {
            "identity_provider": {
                "type": "string",
                "pattern": "^[a-z][a-z0-9-]{0,63}$",
            },
            "federated_identities": {
                "type": "array",
                "maxItems": 10000,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["issuer", "subject", "label", "scopes"],
                    "properties": {
                        "issuer": {"type": "string", "minLength": 1, "maxLength": 2048},
                        "subject": {"type": "string", "minLength": 1, "maxLength": 255},
                        "label": {"type": "string", "minLength": 1, "maxLength": 120},
                        "scopes": {
                            "type": "array",
                            "items": {"type": "string"},
                            "uniqueItems": True,
                        },
                    },
                },
            },
            "session_idle_seconds": {
                "type": "integer",
                "minimum": 1,
                "maximum": 31536000,
            },
            "session_max_seconds": {
                "type": "integer",
                "minimum": 1,
                "maximum": 31536000,
            },
        },
        "additionalProperties": False,
    },
    store=StoreSchema(
        revision="v2",
        migrations=(
            Migration(
                revision="v1",
                sql=SCHEMA,
                dialects={
                    "postgresql": files(__package__)
                    .joinpath("migrations", "v1.postgresql.sql")
                    .read_text()
                },
            ),
            Migration(
                revision="v2",
                parent="v1",
                sql=IDENTITY_SCHEMA,
                dialects={
                    "postgresql": files(__package__)
                    .joinpath("migrations", "v2.postgresql.sql")
                    .read_text()
                },
            ),
        ),
    ),
)
