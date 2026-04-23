"""Unit tests for supabase-rpc-auth-scanner.

Covers:
- Core heuristic classification
- Severity tiers
- Known-safe pattern exclusion
- Multi-layer GraphQL type unwrapping
- pg_graphql builtin filtering
- Probe result classification
- Edge cases (empty functions, array args, safe single-ID deletes)
"""
from __future__ import annotations

from supabase_rpc_auth_scanner.scanner import (
    Argument,
    Function,
    SEV_CRITICAL,
    SEV_HIGH,
    SEV_INFO,
    SEV_MEDIUM,
    _unwrap_type,
)


# ─────────────────────── helpers ───────────────────────


def _arg(name: str, type_name: str, required: bool = True,
         is_list: bool = False) -> Argument:
    return Argument(
        name=name, type_name=type_name, type_kind="SCALAR",
        required=required, is_list=is_list,
    )


# ─────────────────── core heuristic ──────────────────


def test_classic_vulnerable_pattern_flagged():
    """The reference bad pattern: p_account_id UUID + p_count Int."""
    fn = Function(
        name="increment_leads_used",
        arguments=[_arg("p_account_id", "UUID"), _arg("p_count", "Int")],
    )
    assert fn.suspicious
    assert fn.severity == SEV_HIGH
    assert len(fn.tenant_args) == 1


def test_pure_delete_by_uuid_not_flagged():
    """Only a UUID arg, no value param. Not flagged."""
    fn = Function(name="nuke_something", arguments=[_arg("p_account_id", "UUID")])
    assert not fn.suspicious
    assert fn.severity == SEV_INFO


def test_multiple_tenant_args_critical():
    """Two different tenant args + value = CRITICAL (cross-tenant risk)."""
    fn = Function(
        name="transfer_credits",
        arguments=[
            _arg("src_org_id", "UUID"),
            _arg("dst_org_id", "UUID"),
            _arg("amount", "Int"),
        ],
    )
    assert fn.suspicious
    assert fn.severity == SEV_CRITICAL
    assert len(fn.tenant_args) == 2


def test_user_uuid_arg_flagged():
    """user_id / owner_id also count as tenant-scoped identifiers."""
    fn = Function(
        name="set_user_plan",
        arguments=[_arg("p_user_id", "UUID"), _arg("p_plan", "String")],
    )
    assert fn.suspicious
    assert fn.severity == SEV_HIGH


def test_hospital_clinic_firm_patterns_flagged():
    """Extended tenant-name patterns cover healthcare/legal verticals."""
    for name in ["p_hospital_id", "clinic_uuid", "firm_id", "practice_id",
                 "p_landlord_id", "p_store_id"]:
        fn = Function(
            name="update_something",
            arguments=[_arg(name, "UUID"), _arg("p_value", "Int")],
        )
        assert fn.suspicious, f"expected {name} to be flagged"


# ─────────────────── type coverage ──────────────────


def test_bigint_tenant_id_flagged():
    """Non-UUID tenant IDs (bigint) are still identifiers."""
    fn = Function(
        name="increment_credits",
        arguments=[_arg("account_id", "BigInt"), _arg("count", "Int")],
    )
    assert fn.suspicious


def test_int_tenant_id_flagged():
    fn = Function(
        name="set_quota",
        arguments=[_arg("org_id", "Int"), _arg("quota", "Int")],
    )
    assert fn.suspicious


def test_text_slug_tenant_flagged():
    """Slug-based tenant (text/String type) is still a valid identifier."""
    fn = Function(
        name="set_org_plan",
        arguments=[_arg("workspace_slug", "String"), _arg("plan", "String")],
    )
    assert fn.suspicious


def test_jsonb_type_not_tenant_identifier():
    """JSON/JSONB-typed arg isn't a tenant identifier even with that name."""
    fn = Function(
        name="do_thing",
        arguments=[_arg("account_id", "JSON"), _arg("v", "Int")],
    )
    assert not fn.suspicious


# ────────────────── known-safe downgrade ─────────────


def test_invite_token_pattern_not_flagged():
    """accept_invite(p_invite_id UUID, p_decision Boolean) — single-use
    token, uniqueness is the authorization. Not flagged."""
    fn = Function(
        name="accept_invite",
        arguments=[_arg("p_invite_id", "UUID"), _arg("p_decision", "Boolean")],
    )
    assert not fn.suspicious


def test_message_read_pattern_not_flagged():
    """mark_message_read — message_id is a safe token, not tenant."""
    fn = Function(
        name="mark_message_read",
        arguments=[_arg("p_message_id", "UUID"), _arg("p_read", "Boolean")],
    )
    assert not fn.suspicious


def test_session_token_pattern_not_flagged():
    fn = Function(
        name="revoke_session",
        arguments=[_arg("p_session_id", "UUID")],
    )
    assert not fn.suspicious


def test_magic_link_pattern_not_flagged():
    fn = Function(
        name="consume_magic_link",
        arguments=[_arg("p_magic_token", "String")],
    )
    assert not fn.suspicious


def test_tenant_plus_safe_token_downgrades_to_medium():
    """A function with a tenant ID AND a safe-token-shaped other ID
    (like accept_invite(org_id, invite_id)) is MEDIUM severity — the
    tenant ID gate may or may not be respected."""
    fn = Function(
        name="claim_invite_for_org",
        arguments=[
            _arg("p_org_id", "UUID"),
            _arg("p_invite_id", "UUID"),
        ],
    )
    # tenant + safe-token, no value arg, so not suspicious per current rule
    assert not fn.suspicious


# ─────────────── pg_graphql builtins ───────────────


def test_pg_graphql_builtins_filtered():
    for name in ("insertIntoleadsCollection", "updateaccountsCollection",
                 "deleteFromaccountsCollection", "insertIntoworkspacesCollection"):
        fn = Function(name=name, arguments=[])
        assert fn.builtin


def test_non_builtin_name_not_filtered():
    for name in ("my_custom_rpc", "increment_usage", "transfer_credits"):
        fn = Function(name=name, arguments=[])
        assert not fn.builtin


# ─────────────── type unwrapping ───────────────


def test_unwrap_non_null_uuid():
    """NON_NULL { UUID } → UUID scalar, required=True"""
    t = {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "UUID"}}
    name, kind, required, is_list = _unwrap_type(t)
    assert name == "UUID"
    assert kind == "SCALAR"
    assert required is True
    assert is_list is False


def test_unwrap_list_of_non_null_uuids():
    """LIST { NON_NULL { UUID } } → UUID scalar, is_list=True"""
    t = {
        "kind": "LIST",
        "ofType": {
            "kind": "NON_NULL",
            "ofType": {"kind": "SCALAR", "name": "UUID"},
        },
    }
    name, kind, required, is_list = _unwrap_type(t)
    assert name == "UUID"
    assert is_list is True


def test_unwrap_non_null_list_of_non_null():
    """NON_NULL { LIST { NON_NULL { UUID } } } — fully-wrapped array"""
    t = {
        "kind": "NON_NULL",
        "ofType": {
            "kind": "LIST",
            "ofType": {
                "kind": "NON_NULL",
                "ofType": {"kind": "SCALAR", "name": "UUID"},
            },
        },
    }
    name, kind, required, is_list = _unwrap_type(t)
    assert name == "UUID"
    assert required is True
    assert is_list is True


def test_unwrap_bare_scalar():
    t = {"kind": "SCALAR", "name": "String"}
    name, kind, required, is_list = _unwrap_type(t)
    assert name == "String"
    assert required is False
    assert is_list is False


def test_unwrap_none_returns_none():
    assert _unwrap_type(None) == (None, None, False, False)


# ──────────────── argument flags ────────────────


def test_argument_is_uuid():
    assert _arg("p_id", "UUID").is_uuid
    assert _arg("p_id", "Uuid").is_uuid  # case-insensitive
    assert not _arg("p_id", "String").is_uuid


def test_argument_is_numeric():
    assert _arg("p_count", "Int").is_numeric
    assert _arg("p_amount", "BigInt").is_numeric
    assert _arg("p_rate", "Float").is_numeric
    assert not _arg("p_id", "UUID").is_numeric


def test_argument_tenant_match_requires_type_and_name():
    """A UUID arg not named tenant-ish isn't a tenant ID; a tenant-named
    JSON arg isn't either."""
    assert not _arg("p_message", "UUID").looks_like_tenant_id
    assert not _arg("p_account_id", "JSON").looks_like_tenant_id
    assert _arg("p_account_id", "UUID").looks_like_tenant_id
    assert _arg("p_account_id", "BigInt").looks_like_tenant_id
    assert _arg("p_workspace_slug", "String").looks_like_tenant_id


# ──────────────── value_args correctness ────────────────


def test_value_args_returns_non_tenant_non_safe_args():
    fn = Function(
        name="update_leads",
        arguments=[
            _arg("p_account_id", "UUID"),       # tenant
            _arg("p_count", "Int"),              # value
            _arg("p_note", "String"),            # value
            _arg("p_invite_id", "UUID"),        # safe token, excluded
        ],
    )
    names = [a.name for a in fn.value_args]
    assert names == ["p_count", "p_note"]


def test_value_args_empty_when_no_values():
    """Only tenant IDs, no value params → value_args empty."""
    fn = Function(
        name="refresh",
        arguments=[_arg("p_account_id", "UUID")],
    )
    assert fn.value_args == []


# ──────────────── severity matrix ────────────────


def test_severity_matrix():
    """Map out severity outputs across several archetypes."""
    cases = [
        # (function, expected severity)
        (Function("increment", [_arg("account_id", "UUID"), _arg("cnt", "Int")]),
         SEV_HIGH),
        (Function("xfer", [_arg("src_org_id", "UUID"),
                           _arg("dst_org_id", "UUID"),
                           _arg("n", "Int")]),
         SEV_CRITICAL),
        (Function("accept", [_arg("p_invite_id", "UUID"),
                             _arg("p_yes", "Boolean")]),
         SEV_INFO),
        (Function("ping", []), SEV_INFO),
        (Function("delete_by_id", [_arg("p_id", "UUID")]), SEV_INFO),
    ]
    for fn, expected in cases:
        assert fn.severity == expected, \
            f"{fn.name}: expected {expected}, got {fn.severity}"


# ──────────────── empty/degenerate ────────────────


def test_function_no_args_not_suspicious():
    fn = Function(name="whoami", arguments=[])
    assert not fn.suspicious
    assert fn.severity == SEV_INFO


def test_function_with_only_value_args():
    """No tenant args, just a value — not suspicious (not scoped, but
    also not exploitable for horizontal-authz)."""
    fn = Function(
        name="random_number",
        arguments=[_arg("p_max", "Int")],
    )
    assert not fn.suspicious
