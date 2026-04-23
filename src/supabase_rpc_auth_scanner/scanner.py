"""
Core scanner. Given a Supabase project URL, publishable/anon key, and an
authenticated JWT, introspects the pg_graphql Mutation (and optionally
Query) surface and flags RPC functions that look like they trust a
caller-controlled tenant identifier.

The bug class this catches is horizontal-authz bypass via SECURITY
DEFINER. Example from a real engagement:

    CREATE OR REPLACE FUNCTION increment_leads_used(
        p_account_id UUID, p_count INT
    ) RETURNS VOID
    LANGUAGE plpgsql
    SECURITY DEFINER
    AS $$
    BEGIN
        UPDATE accounts SET leads_used = leads_used + p_count
         WHERE id = p_account_id;
    END;
    $$;

Because the function runs as the function owner (typically `postgres`),
RLS on the `accounts` table is bypassed inside the function body. A
malicious authenticated user can pass *any* account_id and inflate or
zero out any tenant's usage counter. The fix is to derive the scope from
`auth.uid()` instead of trusting the caller-supplied UUID.

Heuristic layers:

1.  A function is SUSPICIOUS when its arguments include at least one
    tenant-scope identifier (UUID, bigint, int, or slug-text named
    account_id, tenant_id, org_id, etc.) PLUS at least one non-identifier
    value parameter (what a SECURITY DEFINER function would use to
    modify the target row).

2.  A function is DOWNGRADED to INFO when it matches a known-safe
    pattern: inviteId, tokenId, messageId, sessionId, inviteCode, etc.
    These are usually single-use tokens whose uniqueness is the
    authorization.

3.  A function is EXCLUDED when it is a pg_graphql built-in
    (insertInto*, update*, deleteFrom*) because those always run as
    the authenticated role and RLS applies.

4.  Optional active probe: call the RPC with a random UUID (+ zero
    values for other params) and compare the response with a second
    call using a different random UUID. Differential response
    classification separates "accepted any UUID" (likely vulnerable)
    from "permission denied / function not found" (likely safe).
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib import error, request


# Severity levels emitted in findings.
SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_INFO = "info"


# Parameter names that suggest a tenant-scope identifier. This is the
# core heuristic; false-positive filtering happens later.
TENANT_PARAM_RE = re.compile(
    r"(?:^|_)(?:p_)?"
    r"(account|tenant|org|organization|workspace|team|user|owner|"
    r"company|project|client|customer|hospital|clinic|practice|"
    r"firm|store|dealer|franchise|partner|landlord|operator|"
    r"branch|region|district|location|facility|site)"
    r"(?:_id|_uuid|_key|_slug|id)?$",
    re.IGNORECASE,
)

# Parameter names that are NOT tenant identifiers even though they look
# like UUIDs. Single-use tokens + message-level identifiers. When a
# function's only identifier is one of these, it's usually safe because
# the uniqueness of the token IS the authorization.
SAFE_PARAM_RE = re.compile(
    r"(?:^|_)(?:p_)?"
    r"(invite|invitation|token|session|message|notification|"
    r"reset|verify|verification|confirmation|magic|otp|"
    r"event|audit|log|webhook|thread|comment|reply|"
    r"attachment|file|media|asset|upload|artifact)"
    r"(?:_id|_uuid|_key|_code|_token|id|code|token)?$",
    re.IGNORECASE,
)

# Scalar types we treat as potential tenant identifiers.
# pg_graphql surfaces UUID as "UUID", bigint as "BigInt", int as "Int",
# text/varchar as "String".
TENANT_TYPE_NAMES = {
    "UUID", "BIGINT", "BIGINTEGER", "INT", "INTEGER", "STRING", "TEXT",
}

# Scalar types we treat as value parameters (the payload the function
# operates with once it has the tenant ID).
VALUE_TYPE_NAMES = {
    "INT", "INTEGER", "BIGINT", "BIGINTEGER", "FLOAT", "NUMERIC",
    "DECIMAL", "BIGFLOAT", "BOOLEAN", "STRING", "TEXT", "JSON", "JSONB",
    "DATE", "DATETIME", "TIMESTAMP",
}


# ───────────────────────────── data types ─────────────────────────────


@dataclass
class Argument:
    name: str
    type_name: Optional[str]
    type_kind: Optional[str]
    required: bool
    is_list: bool = False

    @property
    def type_norm(self) -> str:
        return (self.type_name or "").upper()

    @property
    def is_uuid(self) -> bool:
        return self.type_norm == "UUID"

    @property
    def is_tenant_type(self) -> bool:
        return self.type_norm in TENANT_TYPE_NAMES

    @property
    def is_numeric(self) -> bool:
        return self.type_norm in {"INT", "INTEGER", "BIGINT", "BIGINTEGER",
                                  "FLOAT", "NUMERIC", "DECIMAL", "BIGFLOAT"}

    @property
    def looks_like_tenant_id(self) -> bool:
        """True if the name matches the tenant pattern AND the type
        supports being an identifier. A text-typed `account_id` counts
        (slug tenant). A JSON-typed `account_id` does not."""
        if not TENANT_PARAM_RE.search(self.name):
            return False
        return self.is_tenant_type

    @property
    def looks_like_safe_token(self) -> bool:
        return bool(SAFE_PARAM_RE.search(self.name))


@dataclass
class Function:
    name: str
    arguments: list[Argument] = field(default_factory=list)
    in_mutation: bool = True

    @property
    def tenant_args(self) -> list[Argument]:
        return [a for a in self.arguments if a.looks_like_tenant_id]

    @property
    def safe_token_args(self) -> list[Argument]:
        return [a for a in self.arguments if a.looks_like_safe_token]

    @property
    def value_args(self) -> list[Argument]:
        """Non-identifier arguments. These are what a SECURITY DEFINER
        function would apply to the row identified by a tenant UUID."""
        out = []
        for a in self.arguments:
            if a.looks_like_tenant_id:
                continue
            if a.looks_like_safe_token:
                continue
            if a.type_norm in VALUE_TYPE_NAMES:
                out.append(a)
        return out

    @property
    def suspicious(self) -> bool:
        return len(self.tenant_args) >= 1 and len(self.value_args) >= 1

    @property
    def severity(self) -> str:
        """Severity classification:
        - CRITICAL: two+ tenant args of different names + value args
          (e.g. transfer_credits(src_org, dst_org, amount)) — always
          vulnerable to cross-tenant manipulation.
        - HIGH: single tenant arg + value args — the classic pattern.
        - MEDIUM: tenant arg with only safe-token-shaped other args.
        - INFO: no tenant args or only safe tokens.
        """
        if not self.suspicious:
            return SEV_INFO
        distinct_tenant_names = {a.name.lower() for a in self.tenant_args}
        if len(distinct_tenant_names) >= 2:
            return SEV_CRITICAL
        # Downgrade if every non-tenant arg is a safe-token-looking ID
        only_safe_tokens = all(
            a.looks_like_safe_token for a in self.arguments
            if not a.looks_like_tenant_id
        )
        if only_safe_tokens and self.arguments:
            return SEV_MEDIUM
        return SEV_HIGH

    @property
    def builtin(self) -> bool:
        """pg_graphql exposes collection-level CRUD mutations. They always
        run as the authenticated role and RLS applies, so flagging them
        would be a false positive."""
        return self.name.startswith(("insertInto", "update", "deleteFrom"))


@dataclass
class ProbeResult:
    invoked: bool
    status: Optional[int]
    body_sample: Optional[str] = None
    error: Optional[str] = None
    classification: str = "unknown"
    differential_match: Optional[bool] = None


@dataclass
class Finding:
    function: Function
    probe: Optional[ProbeResult] = None

    @property
    def severity(self) -> str:
        return self.function.severity


# ────────────────────────────── scanner ──────────────────────────────


class Scanner:
    def __init__(
        self,
        url: str,
        key: str,
        jwt: str,
        timeout: int = 10,
        verbose: bool = False,
        user_agent: str = "supabase-rpc-auth-scanner/0.2",
    ) -> None:
        self.url = url.rstrip("/")
        self.key = key
        self.jwt = jwt
        self.timeout = timeout
        self.verbose = verbose
        self.user_agent = user_agent

    # ──────────────────────────── introspection ────────────────────────────

    _INTROSPECTION_Q = """
    {
      __type(name: "%s") {
        name
        fields {
          name
          args {
            name
            type {
              name
              kind
              ofType {
                name
                kind
                ofType {
                  name
                  kind
                }
              }
            }
          }
        }
      }
    }
    """

    def fetch_type_functions(self, type_name: str) -> list[Function]:
        """Introspect a GraphQL type ('Mutation' or 'Query') and return
        its fields as Function objects."""
        data = self._gql(self._INTROSPECTION_Q % type_name)
        t = (data or {}).get("data", {}).get("__type") or {}
        fields = t.get("fields") or []
        out: list[Function] = []
        for f in fields:
            args = []
            for a in f.get("args", []):
                tname, tkind, required, is_list = _unwrap_type(a.get("type"))
                args.append(Argument(
                    name=a.get("name", ""),
                    type_name=tname,
                    type_kind=tkind,
                    required=required,
                    is_list=is_list,
                ))
            out.append(Function(
                name=f.get("name", ""),
                arguments=args,
                in_mutation=(type_name == "Mutation"),
            ))
        return out

    def fetch_mutations(self) -> list[Function]:
        return self.fetch_type_functions("Mutation")

    def fetch_queries(self) -> list[Function]:
        """Fetch Query-type RPCs. Functions returning SETOF or TABLE
        show up here, not under Mutation. Less commonly SECURITY DEFINER
        but still worth checking."""
        return self.fetch_type_functions("Query")

    # ─────────────────────────── active probing ────────────────────────────

    def probe(self, fn: Function) -> ProbeResult:
        """Differential probe: call with two random UUIDs and compare
        responses. If both return 200/204 with similar bodies, the
        function is clearly accepting arbitrary tenant IDs (likely
        vulnerable). If one returns 404/403/500 and the other doesn't,
        something is interesting. If both return an auth/permission
        error, the function is likely safe."""
        uuid1 = "00000000-0000-0000-0000-000000000001"
        uuid2 = "00000000-0000-0000-0000-000000000002"
        r1 = self._rpc_call(fn, uuid1)
        r2 = self._rpc_call(fn, uuid2)

        diff_match = (
            r1.status == r2.status
            and (r1.body_sample or "")[:120] == (r2.body_sample or "")[:120]
        ) if r1.invoked and r2.invoked else None

        # Classification
        if not r1.invoked:
            cls = "network_error"
        elif r1.status in (200, 204):
            cls = "accepts_arbitrary_uuid"
        elif r1.status in (401, 403):
            cls = "permission_denied"
        elif r1.status == 404:
            cls = "function_or_row_not_found"
        elif r1.status in (400,) and r1.body_sample and "does not exist" in (r1.body_sample or "").lower():
            cls = "function_not_found"
        elif r1.status and 400 <= r1.status < 500:
            cls = "client_error"
        elif r1.status and 500 <= r1.status < 600:
            cls = "server_error"
        else:
            cls = "other"

        r1.classification = cls
        r1.differential_match = diff_match
        return r1

    def _rpc_call(self, fn: Function, uuid_value: str) -> ProbeResult:
        """Send one no-op call with a specific UUID and zero-valued
        other params."""
        params: dict[str, Any] = {}
        for a in fn.arguments:
            if a.is_uuid:
                params[a.name] = uuid_value
            elif a.type_norm in {"INT", "INTEGER", "BIGINT", "BIGINTEGER"}:
                params[a.name] = 0
            elif a.type_norm in {"FLOAT", "NUMERIC", "DECIMAL", "BIGFLOAT"}:
                params[a.name] = 0.0
            elif a.type_norm == "BOOLEAN":
                params[a.name] = False
            elif a.type_norm in {"STRING", "TEXT"}:
                params[a.name] = ""
            elif a.type_norm in {"JSON", "JSONB"}:
                params[a.name] = {}
            else:
                params[a.name] = None

        url = f"{self.url}/rest/v1/rpc/{fn.name}"
        body = json.dumps(params).encode()
        req = request.Request(
            url, data=body, method="POST",
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.jwt}",
                "Content-Type": "application/json",
                "User-Agent": self.user_agent,
            },
        )
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                body_sample = resp.read(400).decode("utf-8", errors="replace")
                return ProbeResult(
                    invoked=True, status=resp.status, body_sample=body_sample
                )
        except error.HTTPError as e:
            try:
                detail = e.read().decode("utf-8", errors="replace")[:400]
            except Exception:
                detail = str(e)
            return ProbeResult(invoked=True, status=e.code, body_sample=detail)
        except Exception as e:
            return ProbeResult(invoked=False, status=None, error=str(e))

    # ──────────────────────────── GraphQL plumbing ─────────────────────────

    def _gql(self, query: str) -> dict:
        url = f"{self.url}/graphql/v1"
        body = json.dumps({"query": query}).encode()
        req = request.Request(
            url, data=body, method="POST",
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.jwt}",
                "Content-Type": "application/json",
                "User-Agent": self.user_agent,
            },
        )
        with request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())

    # ──────────────────────────── high-level scan ──────────────────────────

    def scan(self, probe: bool = False,
             include_queries: bool = False) -> list[Finding]:
        functions: list[Function] = self.fetch_mutations()
        if include_queries:
            # Only include Query-type functions that aren't pg_graphql
            # table collections (everything in Query that isn't a Collection
            # suffix is a function).
            for q in self.fetch_queries():
                if q.name.endswith("Collection") or q.name == "node":
                    continue
                functions.append(q)

        findings: list[Finding] = []
        for fn in functions:
            if fn.builtin:
                continue
            p = self.probe(fn) if (probe and fn.suspicious) else None
            findings.append(Finding(function=fn, probe=p))
            if self.verbose:
                import sys
                sev = fn.severity.upper()
                print(f"  [{sev:8}] {fn.name}({len(fn.arguments)} args)",
                      file=sys.stderr)
        return findings


# ───────────────────────────── helpers ─────────────────────────────


def _unwrap_type(t: Optional[dict]) -> tuple[Optional[str], Optional[str],
                                              bool, bool]:
    """Unwrap a GraphQL type tree (NON_NULL { LIST { NON_NULL { UUID } } })
    into (scalar_name, kind, required, is_list)."""
    if not t:
        return None, None, False, False
    required = False
    is_list = False
    cur = t
    # Peel at most 3 layers of wrappers
    for _ in range(4):
        kind = cur.get("kind")
        name = cur.get("name")
        if kind == "NON_NULL":
            required = True
            cur = cur.get("ofType") or {}
            continue
        if kind == "LIST":
            is_list = True
            cur = cur.get("ofType") or {}
            continue
        return name, kind, required, is_list
    return cur.get("name"), cur.get("kind"), required, is_list
