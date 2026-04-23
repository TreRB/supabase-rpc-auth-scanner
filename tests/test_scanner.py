"""Unit tests for the RPC auth scanner heuristics."""
from supabase_rpc_auth_scanner.scanner import Argument, Function


def _arg(name: str, type_name: str, required: bool = True) -> Argument:
    return Argument(name=name, type_name=type_name, type_kind="SCALAR", required=required)


def test_classic_vulnerable_pattern_flagged():
    """increment_leads_used(p_account_id UUID, p_count Int) is the reference
    bad pattern — caller-supplied tenant UUID plus a value param."""
    fn = Function(
        name="increment_leads_used",
        arguments=[_arg("p_account_id", "UUID"), _arg("p_count", "Int")],
    )
    assert fn.suspicious
    assert len(fn.tenant_args) == 1


def test_pure_delete_by_uuid_not_flagged():
    """A function with only a UUID arg isn't flagged — pg_graphql's built-in
    deleteFromXCollection is the main example and RLS covers those."""
    fn = Function(name="nuke_something", arguments=[_arg("p_account_id", "UUID")])
    # Only a UUID arg, no value param
    assert not fn.suspicious


def test_pg_graphql_builtins_filtered():
    for name in ("insertIntoleadsCollection",
                 "updateaccountsCollection",
                 "deleteFromaccountsCollection"):
        fn = Function(name=name, arguments=[])
        assert fn.builtin


def test_non_tenant_uuid_arg_not_flagged():
    """A UUID argument whose name isn't tenant-shaped (e.g. p_message_id)
    is not automatically suspicious. Still worth the developer checking,
    but we don't want false positives on every UUID-accepting function."""
    fn = Function(
        name="mark_message_read",
        arguments=[_arg("p_message_id", "UUID"), _arg("p_read", "Boolean")],
    )
    assert not fn.suspicious


def test_multiple_tenant_args_flagged():
    """A function with org_id AND team_id AND a value is absolutely
    suspicious."""
    fn = Function(
        name="transfer_credits",
        arguments=[
            _arg("src_org_id", "UUID"),
            _arg("dst_org_id", "UUID"),
            _arg("amount", "Int"),
        ],
    )
    assert fn.suspicious
    assert len(fn.tenant_args) == 2


def test_user_uuid_arg_flagged():
    """user_id / owner_id etc. also count as tenant-scoped identifiers."""
    fn = Function(
        name="set_user_plan",
        arguments=[_arg("p_user_id", "UUID"), _arg("p_plan", "String")],
    )
    assert fn.suspicious
