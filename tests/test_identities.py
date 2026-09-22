"""Shared users and grants preserve password authority and delegation bounds."""

# ruff: noqa: F811 -- shared pytest fixture
import time

import pytest
from test_auth import CATALOG, auth, caller, create, login  # noqa: F401
from toolframe_sdk import PluginError, Principal

CATALOG.update(
    {
        "system.auth.users": {"category": "system"},
        "system.auth.self": {"category": "system"},
    }
)


async def user(auth, subject="one", scopes=None):
    auth.context.config["federated_identities"] = [
        {
            "issuer": "https://idp.test",
            "subject": subject,
            "label": subject,
            "scopes": scopes or ["notes.read"],
        }
    ]
    with caller(owner="oidc-auth"):
        return await auth.invoke(
            "toolframe.auth",
            "federated_login",
            {"issuer": "https://idp.test", "subject": subject},
        )


async def grant(auth, actor, **extra):
    with caller(Principal.model_validate(actor), owner="oidc-auth"):
        return await auth.invoke(
            "toolframe.auth",
            "grant_create",
            {
                "user_id": actor["user_id"],
                "issuer": "https://app.test/oauth",
                "client_id": "agent",
                "client_name": "Agent",
                "resource": "https://app.test/mcp",
                "scopes": ["notes.read"],
                "expires_at": time.time() + 300,
                **extra,
            },
        )


async def test_trusted_issuer_subject_admission_and_separate_password_sessions(auth):
    await create(auth)
    password = await login(auth)
    external = await user(auth)
    assert external["principal"]["kind"] == "user"
    assert external["principal"]["user_id"] != password["principal"]["credential_id"]
    with (
        caller(owner="business"),
        pytest.raises(PluginError, match="configured identity"),
    ):
        await auth.invoke(
            "toolframe.auth",
            "federated_login",
            {"issuer": "https://idp.test", "subject": "one"},
        )
    with (
        caller(owner="oidc-auth"),
        pytest.raises(PluginError, match="not been admitted"),
    ):
        await auth.invoke(
            "toolframe.auth",
            "federated_login",
            {"issuer": "https://other.test", "subject": "one"},
        )
    with caller():
        await auth.invoke("toolframe.auth", "logout", {"token": external["token"]})
        assert (
            await auth.invoke("toolframe.auth", "resolve", {"token": password["token"]})
        )["principal"]["kind"] == "password"
        with pytest.raises(PluginError, match="Sign in again"):
            await auth.invoke("toolframe.auth", "resolve", {"token": external["token"]})


async def test_grants_reduce_on_permission_change_and_revoke_without_logout(auth):
    session = await user(auth, scopes=["notes.read", "notes.write"])
    actor = session["principal"]
    issued = await grant(auth, actor, scopes=["notes.read", "notes.write"])
    with caller():
        await auth.invoke(
            "toolframe.auth",
            "user_update",
            {"id": actor["user_id"], "scopes": ["notes.read"], "disabled": False},
        )
    with caller(owner="oidc-auth"):
        assert (await auth.invoke("toolframe.auth", "grant_check", issued))["grant"][
            "scopes"
        ] == ["notes.read"]
    with caller(Principal.model_validate(actor)):
        await auth.invoke("toolframe.auth", "revoke_grant", issued)
        assert (
            await auth.invoke("toolframe.auth", "resolve", {"token": session["token"]})
        )["principal"]["user_id"] == actor["user_id"]
    with caller(owner="oidc-auth"), pytest.raises(PluginError):
        await auth.invoke("toolframe.auth", "grant_check", issued)


async def test_cross_user_revoke_and_system_scope_delegation_are_denied(auth):
    one = await user(auth, "one", ["notes.read", "system.auth.users"])
    two = await user(auth, "two")
    record = await grant(auth, one["principal"])
    with (
        caller(Principal.model_validate(two["principal"])),
        pytest.raises(PluginError, match="own grants"),
    ):
        await auth.invoke("toolframe.auth", "revoke_grant", record)
    with pytest.raises(PluginError):
        await grant(auth, one["principal"], scopes=["system.auth.users"])
    with caller():
        await auth.invoke(
            "toolframe.auth",
            "user_update",
            {
                "id": one["principal"]["user_id"],
                "scopes": ["notes.read"],
                "disabled": True,
            },
        )
        with pytest.raises(PluginError):
            await auth.invoke("toolframe.auth", "resolve", {"token": one["token"]})
    with caller(owner="oidc-auth"), pytest.raises(PluginError):
        await auth.invoke("toolframe.auth", "grant_check", record)


@pytest.mark.parametrize("identifier", [None, [], {}, "\ud800", "x" * 129])
async def test_malformed_grant_ids_are_denials(auth, identifier):
    with caller(owner="oidc-auth"):
        for method in ("grant_check", "revoke_grant"):
            with pytest.raises(PluginError) as error:
                await auth.invoke("toolframe.auth", method, {"id": identifier})
            assert error.value.code in {"invalid_credentials", "invalid_request"}
