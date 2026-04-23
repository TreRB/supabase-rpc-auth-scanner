"""
Core scanner. Given a Supabase project URL, publishable/anon key, and an
authenticated JWT, introspects the GraphQL Mutation type and flags functions
that look like they trust a caller-controlled tenant identifier.

The heuristic: a function is suspicious when its arguments include at least
one UUID-typed parameter whose name matches tenant/account/org/user/team/
workspace patterns AND at least one non-UUID parameter (i.e. it does work
with a value, not just delete-by-id which is a separately auditable
case).
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib import error, request

# Parameter names that suggest a tenant-scope identifier.
TENANT_PARAM_RE = re.compile(
    r"(?:^|_)(account|tenant|org|organization|workspace|team|user|owner|company|project|client|customer)(?:_id|_uuid|id)?$",
    re.IGNORECASE,
)


@dataclass
class Argument:
    name: str
    type_name: Optional[str]
    type_kind: Optional[str]
    required: bool

    @property
    def is_uuid(self) -> bool:
        return (self.type_name or "").upper() == "UUID"

    @property
    def looks_like_tenant_id(self) -> bool:
        return self.is_uuid and bool(TENANT_PARAM_RE.search(self.name))


@dataclass
class Function:
    name: str
    arguments: list[Argument] = field(default_factory=list)

    @property
    def tenant_args(self) -> list[Argument]:
        return [a for a in self.arguments if a.looks_like_tenant_id]

    @property
    def value_args(self) -> list[Argument]:
        """Non-UUID args — these are what a SECURITY DEFINER function would
        apply to the row identified by a tenant UUID."""
        return [a for a in self.arguments if not a.is_uuid and not a.name.startswith("p_") or (not a.is_uuid)]

    @property
    def suspicious(self) -> bool:
        # Must have a tenant-ID-looking UUID AND at least one non-UUID value
        # parameter. Pure delete-by-id (one UUID arg only) is a separately
        # auditable case — we don't flag it here because it's often
        # legitimate and the delete is scoped via WITH CHECK clause.
        has_tenant = any(a.looks_like_tenant_id for a in self.arguments)
        has_value = any(not a.is_uuid for a in self.arguments)
        return has_tenant and has_value

    @property
    def builtin(self) -> bool:
        """Filter out pg_graphql's CRUD mutations (insertInto*, updateX,
        deleteFromX) which are always safe because RLS still applies."""
        return self.name.startswith(("insertInto", "update", "deleteFrom"))


@dataclass
class ProbeResult:
    invoked: bool
    status: Optional[int]
    message: Optional[str]


@dataclass
class Finding:
    function: Function
    probe: Optional[ProbeResult]


class Scanner:
    def __init__(
        self,
        url: str,
        key: str,
        jwt: str,
        timeout: int = 10,
    ) -> None:
        self.url = url.rstrip("/")
        self.key = key
        self.jwt = jwt
        self.timeout = timeout

    # ──────────────────────────── introspection ────────────────────────────

    _MUTATION_Q = (
        "{ __type(name: \"Mutation\") { fields { name args { name type "
        "{ name kind ofType { name kind } } } } } }"
    )

    def fetch_mutations(self) -> list[Function]:
        data = self._gql(self._MUTATION_Q)
        t = (data or {}).get("data", {}).get("__type") or {}
        fields = t.get("fields") or []
        out: list[Function] = []
        for f in fields:
            args = []
            for a in f.get("args", []):
                type_info = a.get("type", {}) or {}
                tkind = type_info.get("kind")
                tname = type_info.get("name")
                of = type_info.get("ofType") or {}
                required = tkind == "NON_NULL"
                if required and not tname:
                    tname = of.get("name")
                    tkind = of.get("kind")
                args.append(Argument(
                    name=a.get("name", ""),
                    type_name=tname,
                    type_kind=tkind,
                    required=required,
                ))
            out.append(Function(name=f.get("name", ""), arguments=args))
        return out

    # ─────────────────────────── active probing ────────────────────────────

    def probe(self, fn: Function) -> ProbeResult:
        """Send a no-op call with a random UUID and zero-valued payload.
        HTTP 200 / 204 with no error means the function accepted an
        arbitrary UUID — strong signal it's not scoping to auth.uid().

        We pass zero-valued or empty-string values for non-UUID args so the
        side effects (if any) are no-ops on a row that doesn't exist.
        """
        params: dict[str, Any] = {}
        for a in fn.arguments:
            if a.is_uuid:
                params[a.name] = "00000000-0000-0000-0000-000000000001"
            else:
                tname = (a.type_name or "").lower()
                if tname in ("int", "bigint", "float", "numeric", "decimal", "bigfloat"):
                    params[a.name] = 0
                elif tname == "boolean":
                    params[a.name] = False
                elif tname in ("string", "text"):
                    params[a.name] = ""
                else:
                    params[a.name] = None
        return self._rpc_call(fn.name, params)

    def _rpc_call(self, name: str, params: dict) -> ProbeResult:
        url = f"{self.url}/rest/v1/rpc/{name}"
        body = json.dumps(params).encode()
        req = request.Request(
            url, data=body, method="POST",
            headers={
                "apikey": self.key,
                "Authorization": f"Bearer {self.jwt}",
                "Content-Type": "application/json",
            },
        )
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                return ProbeResult(invoked=True, status=resp.status, message=None)
        except error.HTTPError as e:
            try:
                detail = e.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                detail = str(e)
            return ProbeResult(invoked=True, status=e.code, message=detail)
        except Exception as e:
            return ProbeResult(invoked=False, status=None, message=str(e))

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
            },
        )
        with request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())

    # ──────────────────────────── high-level scan ──────────────────────────

    def scan(self, probe: bool = False) -> list[Finding]:
        mutations = self.fetch_mutations()
        findings: list[Finding] = []
        for fn in mutations:
            if fn.builtin:
                continue
            p = self.probe(fn) if (probe and fn.suspicious) else None
            findings.append(Finding(function=fn, probe=p))
        return findings
