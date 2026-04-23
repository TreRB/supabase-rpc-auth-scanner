"""Integration tests for the Scanner class with a mock HTTP layer.

These tests exercise the full scan flow (introspection → classification
→ probe) against realistic GraphQL/REST responses without hitting the
network.
"""
from __future__ import annotations

import io
import json
from unittest.mock import patch, MagicMock

from supabase_rpc_auth_scanner.scanner import Scanner


def _mock_urlopen_seq(responses: list[dict]):
    """Build a urlopen replacement that returns a sequence of canned
    responses. Each `responses` entry has keys: `body` (dict or str),
    optional `status` (default 200)."""
    idx = {"i": 0}

    class FakeResp:
        def __init__(self, body, status):
            if isinstance(body, dict):
                body = json.dumps(body)
            self._body = body.encode()
            self._read_cursor = 0
            self.status = status

        def read(self, n=None):
            if n is None:
                data = self._body[self._read_cursor:]
                self._read_cursor = len(self._body)
                return data
            data = self._body[self._read_cursor:self._read_cursor + n]
            self._read_cursor += n
            return data

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _urlopen(req, timeout=None):
        r = responses[idx["i"]]
        idx["i"] += 1
        return FakeResp(r.get("body", ""), r.get("status", 200))

    return _urlopen


# ───────────────── GraphQL introspection response fixtures ─────────────────


def _mutation_introspection_payload():
    """Simulated pg_graphql Mutation introspection response containing:
    - 1 vulnerable function (caller-controlled account_id)
    - 1 pg_graphql builtin (should be filtered)
    - 1 safe function (invite_id only)
    - 1 cross-tenant function (two tenant args)
    - 1 function with NON_NULL type wrapping
    """
    return {
        "data": {
            "__type": {
                "name": "Mutation",
                "fields": [
                    # vulnerable
                    {
                        "name": "increment_leads_used",
                        "args": [
                            {"name": "p_account_id",
                             "type": {"kind": "SCALAR", "name": "UUID"}},
                            {"name": "p_count",
                             "type": {"kind": "SCALAR", "name": "Int"}},
                        ],
                    },
                    # pg_graphql builtin (should be filtered)
                    {
                        "name": "insertIntoleadsCollection",
                        "args": [],
                    },
                    # safe: invite token
                    {
                        "name": "accept_invite",
                        "args": [
                            {"name": "p_invite_id",
                             "type": {"kind": "SCALAR", "name": "UUID"}},
                            {"name": "p_decision",
                             "type": {"kind": "SCALAR", "name": "Boolean"}},
                        ],
                    },
                    # cross-tenant
                    {
                        "name": "transfer_credits",
                        "args": [
                            {"name": "src_org_id",
                             "type": {"kind": "SCALAR", "name": "UUID"}},
                            {"name": "dst_org_id",
                             "type": {"kind": "SCALAR", "name": "UUID"}},
                            {"name": "amount",
                             "type": {"kind": "SCALAR", "name": "Int"}},
                        ],
                    },
                    # NON_NULL wrapping
                    {
                        "name": "set_org_plan",
                        "args": [
                            {"name": "p_workspace_slug",
                             "type": {
                                 "kind": "NON_NULL",
                                 "name": None,
                                 "ofType": {
                                     "kind": "SCALAR", "name": "String",
                                     "ofType": None,
                                 },
                             }},
                            {"name": "p_plan",
                             "type": {"kind": "SCALAR", "name": "String"}},
                        ],
                    },
                ],
            }
        }
    }


# ──────────────────── scan() test ────────────────────


def test_scan_classifies_mocked_responses():
    """Full scan over mocked GraphQL introspection; verify filtering and
    classification."""
    s = Scanner(url="https://x.supabase.co", key="key", jwt="jwt")
    with patch.object(s, "_gql", return_value=_mutation_introspection_payload()):
        findings = s.scan(probe=False)

    # Builtin filtered out
    names = [f.function.name for f in findings]
    assert "insertIntoleadsCollection" not in names
    assert len(findings) == 4

    by_name = {f.function.name: f for f in findings}
    assert by_name["increment_leads_used"].function.suspicious
    assert by_name["increment_leads_used"].function.severity == "high"
    assert not by_name["accept_invite"].function.suspicious
    assert by_name["transfer_credits"].function.suspicious
    assert by_name["transfer_credits"].function.severity == "critical"
    assert by_name["set_org_plan"].function.suspicious

    # NON_NULL unwrap preserved the required flag + scalar name
    set_org_plan = by_name["set_org_plan"].function
    slug_arg = next(a for a in set_org_plan.arguments
                    if a.name == "p_workspace_slug")
    assert slug_arg.type_name == "String"
    assert slug_arg.required is True


def test_scan_with_probe_hits_rpc_endpoint():
    """Verify that probe=True triggers two _rpc_call invocations per
    suspicious function (differential probing)."""
    s = Scanner(url="https://x.supabase.co", key="key", jwt="jwt")

    from supabase_rpc_auth_scanner.scanner import ProbeResult
    rpc_call_count = {"n": 0}

    def fake_rpc(fn, uuid_value):
        rpc_call_count["n"] += 1
        return ProbeResult(invoked=True, status=204, body_sample="")

    with patch.object(s, "_gql", return_value=_mutation_introspection_payload()), \
            patch.object(s, "_rpc_call", side_effect=fake_rpc):
        findings = s.scan(probe=True)

    # 3 suspicious functions × 2 differential probes = 6 calls
    suspicious = [f for f in findings if f.function.suspicious]
    assert len(suspicious) == 3
    assert rpc_call_count["n"] == 6


def test_scan_include_queries():
    """When include_queries=True, we hit Query type introspection too."""
    s = Scanner(url="https://x.supabase.co", key="key", jwt="jwt")

    mutation_payload = _mutation_introspection_payload()
    query_payload = {
        "data": {
            "__type": {
                "name": "Query",
                "fields": [
                    # Collection — should be filtered (pg_graphql table shape)
                    {"name": "leadsCollection", "args": []},
                    # Custom RPC in Query
                    {
                        "name": "get_tenant_stats",
                        "args": [
                            {"name": "p_tenant_id",
                             "type": {"kind": "SCALAR", "name": "UUID"}},
                        ],
                    },
                ],
            }
        }
    }

    call_count = {"i": 0}

    def fake_gql(query: str):
        call_count["i"] += 1
        return mutation_payload if "Mutation" in query else query_payload

    with patch.object(s, "_gql", side_effect=fake_gql):
        findings = s.scan(include_queries=True)

    names = [f.function.name for f in findings]
    assert "get_tenant_stats" in names
    assert "leadsCollection" not in names  # filtered


def test_probe_builds_correct_payload_shapes():
    """_rpc_call must emit zero-valued params for Int/Float/Bool/String/JSON."""
    from supabase_rpc_auth_scanner.scanner import Argument, Function, ProbeResult

    s = Scanner(url="https://x.supabase.co", key="key", jwt="jwt")

    fn = Function(
        name="test_fn",
        arguments=[
            Argument("p_id", "UUID", "SCALAR", True),
            Argument("p_n", "Int", "SCALAR", True),
            Argument("p_amt", "Float", "SCALAR", True),
            Argument("p_active", "Boolean", "SCALAR", True),
            Argument("p_note", "String", "SCALAR", True),
            Argument("p_meta", "JSON", "SCALAR", True),
        ],
    )
    captured = {}

    def fake_urlopen(req, timeout=None):
        # Stash the body JSON so we can assert on it
        captured["body"] = json.loads(req.data.decode())

        class R:
            status = 204

            def read(self, n=None):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        return R()

    with patch("supabase_rpc_auth_scanner.scanner.request.urlopen",
               side_effect=fake_urlopen):
        s._rpc_call(fn, "00000000-0000-0000-0000-000000000001")

    body = captured["body"]
    assert body["p_id"] == "00000000-0000-0000-0000-000000000001"
    assert body["p_n"] == 0
    assert body["p_amt"] == 0.0
    assert body["p_active"] is False
    assert body["p_note"] == ""
    assert body["p_meta"] == {}
