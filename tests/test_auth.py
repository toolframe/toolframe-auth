"""Credential invariants exercised against the real managed SQLite provider."""

import asyncio
import json
import time
from contextlib import contextmanager

import pytest
from toolframe_sdk import PluginError, Principal, RuntimeContext, call_context
from toolframe_storage_sqlite.plugin import ADMIN_SERVICE, SQL_SERVICE, SqliteProvider

from toolframe_auth.crypto import lookup
from toolframe_auth.plugin import SERVICE, AuthProvider, plugin

CATALOG = {
    "notes.read": {"category": "business"},
    "notes.write": {"category": "business"},
    "system.auth.passwords": {"category": "system"},
    "system.plugins.manage": {"category": "system"},
}


@contextmanager
def caller(actor=None, **extra):
    token = call_context.set(
        {
            "principal": (actor or Principal(kind="local")).model_dump(),
            "scope_catalog": CATALOG,
            "deadline": time.time() + 30,
            "root_id": "test-root",
            "chain": ["auth"],
            **extra,
        }
    )
    try:
        yield
    finally:
        call_context.reset(token)


class StoragePeer:
    def __init__(self, provider):
        self.provider = provider

    async def request(self, method, params, timeout=None):
        assert method == "service.call" and params["alias"] == "storage"
        token = call_context.set(
            {
                "application_id": "test",
                "owner": "auth",
                "owner_generation": "one",
                "root_id": "test-root",
                "deadline": time.time() + 30,
            }
        )
        try:
            return await self.provider.invoke(
                SQL_SERVICE, params["method"], params["params"]
            )
        finally:
            call_context.reset(token)


@pytest.fixture
async def auth(tmp_path):
    storage = SqliteProvider(
        RuntimeContext(
            None, plugin_id="storage-sqlite", generation="one", state_directory=tmp_path
        )
    )
    await storage.activate()
    with caller(management=True, application_id="test"):
        await storage.invoke(
            ADMIN_SERVICE,
            "ensure_store",
            {"owner": "auth", "schema": plugin.store.model_dump()},
        )
    instance = AuthProvider(
        RuntimeContext(
            StoragePeer(storage),
            plugin_id="auth",
            generation="one",
            private_secrets={"password-lookup": "ab" * 32},
        )
    )
    with caller():
        await instance.activate()
    try:
        yield instance
    finally:
        await storage.dispose()


async def create(auth, password="correct-secret-one", **fields):
    with caller():
        return await auth.invoke(
            SERVICE,
            "create",
            {
                "label": "Example",
                "password": password,
                "all_business": False,
                "scopes": ["notes.read"],
                **fields,
            },
        )


async def login(auth, password="correct-secret-one"):
    with caller():
        return await auth.invoke(SERVICE, "login", {"password": password})


async def resolve(auth, token, **extra):
    with caller():
        return await auth.invoke(SERVICE, "resolve", {"token": token, **extra})


async def test_uniqueness_race_revoke_reuse_and_old_session_isolation(auth):
    results = await asyncio.gather(create(auth), create(auth), return_exceptions=True)
    good = [r for r in results if isinstance(r, dict)]
    bad = [r for r in results if isinstance(r, PluginError)]
    assert len(good) == len(bad) == 1 and bad[0].code == "password_conflict"
    first = good[0]["credential"]
    old = await login(auth)
    with caller():
        await auth.invoke(SERVICE, "revoke", {"id": first["id"]})
    with pytest.raises(PluginError, match="Sign in"):
        await resolve(auth, old["token"])
    replacement = await create(auth, scopes=["notes.write"])
    assert replacement["credential"]["id"] != first["id"]
    assert (await login(auth))["principal"]["scopes"] == ("notes.write",)
    with pytest.raises(PluginError, match="Sign in"):
        await resolve(auth, old["token"])


async def test_expired_secret_reuse_blocks_old_record_extension(auth):
    old = (await create(auth))["credential"]
    session = await login(auth)
    with caller():
        await auth.store.execute(
            "UPDATE credentials SET expires_at=? WHERE id=?",
            [time.time() - 1, old["id"]],
        )
    await create(auth, scopes=["notes.write"])
    with caller(), pytest.raises(PluginError) as problem:
        await auth.invoke(SERVICE, "update", {**old, "expires_at": time.time() + 100})
    assert problem.value.code == "password_conflict"
    with pytest.raises(PluginError):
        await resolve(auth, session["token"])


async def test_usage_polling_expiry_caps_and_restart(auth):
    auth.idle = 20
    record = (await create(auth, expires_at=time.time() + 100))["credential"]
    session = await login(auth)
    assert session["expires_at"] <= record["expires_at"]
    with caller():
        before = await auth.get(record["id"])
    await resolve(auth, session["token"])
    with caller():
        after = await auth.get(record["id"])
    assert before["last_used"] == after["last_used"] == before["last_login"]
    await resolve(auth, session["token"], activity=True)
    with caller():
        assert (await auth.get(record["id"]))["last_used"] > before["last_used"]
        restarted = AuthProvider(auth.context)
        await restarted.activate()
    assert (await resolve(restarted, session["token"]))["principal"][
        "credential_id"
    ] == record["id"]
    with caller():
        await auth.store.execute(
            "UPDATE sessions SET last_activity=?", [time.time() - 21]
        )
    with pytest.raises(PluginError):
        await resolve(auth, session["token"])
    with caller():
        await auth.store.execute("UPDATE sessions SET last_activity=?", [time.time()])
    with pytest.raises(PluginError):
        await resolve(auth, session["token"])


async def test_delegation_scope_target_and_expiry_bounds(auth):
    unlimited = await create(auth, scopes=["system.plugins.manage"])
    expiry = time.time() + 120
    actor = Principal(
        kind="password",
        credential_id="admin",
        scopes=("notes.read", "system.auth.passwords"),
        expires_at=expiry,
    )
    base = {
        "label": "Delegated",
        "password": "delegated-secret",
        "scopes": ["notes.read"],
        "expires_at": expiry - 1,
    }
    for fields in (
        {"scopes": ["notes.write"]},
        {"all_business": True},
        {"expires_at": None},
        {"expires_at": expiry + 1},
    ):
        with caller(actor), pytest.raises(PluginError) as problem:
            await auth.invoke(SERVICE, "create", {**base, **fields})
        assert problem.value.code == "forbidden"
    with caller(actor):
        created = await auth.invoke(SERVICE, "create", base)
        listed = await auth.invoke(SERVICE, "list", {})
        assert [r["id"] for r in listed["credentials"]] == [created["credential"]["id"]]
        with pytest.raises(PluginError):
            await auth.invoke(SERVICE, "revoke", {"id": unlimited["credential"]["id"]})
    assert (await login(auth, "delegated-secret"))["principal"][
        "expires_at"
    ] == expiry - 1


async def test_no_plaintext_or_fast_unkeyed_lookup_and_generated_once(auth):
    created = await create(auth, password=None)
    secret = created["password"]
    assert len(secret) >= 32
    with caller():
        listing = await auth.invoke(SERVICE, "list", {})
        record = await auth.get(created["credential"]["id"])
    assert secret not in json.dumps(listing) and "verifier" not in json.dumps(listing)
    assert secret not in json.dumps(record)
    assert record["lookup"] == lookup(auth.key, secret)
    assert record["lookup"] != lookup(bytes(32), secret)
    with pytest.raises(PluginError) as problem:
        await login(auth, "wrong-password")
    assert problem.value.code == "invalid_credentials"


async def test_malformed_inputs_are_typed_denials(auth):
    with caller():
        for method, params in (
            ("create", {"label": []}),
            ("revoke", {"id": []}),
            ("update", {}),
        ):
            with pytest.raises(PluginError) as problem:
                await auth.invoke(SERVICE, method, params)
            assert problem.value.code == "invalid_request"
