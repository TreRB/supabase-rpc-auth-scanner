"""Output formatters for findings: text, JSON, SARIF 2.1.0, Markdown.

SARIF (Static Analysis Results Interchange Format) is the standard for
security-tool output consumed by GitHub Advanced Security, Azure DevOps,
DefectDojo, and most enterprise AppSec platforms.
"""
from __future__ import annotations

import datetime
import json
from typing import Iterable
from urllib.parse import urlparse

from .scanner import Finding, Function, SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_INFO


_SARIF_LEVEL = {
    SEV_CRITICAL: "error",
    SEV_HIGH: "error",
    SEV_MEDIUM: "warning",
    SEV_INFO: "note",
}

# Approximate CVSS-3.1 scores per severity tier (for Defectdojo / ticket
# enrichment downstream). Adjust to your org's risk model.
_APPROX_CVSS = {
    SEV_CRITICAL: 9.1,
    SEV_HIGH: 7.5,
    SEV_MEDIUM: 5.3,
    SEV_INFO: 0.0,
}


def _format_arg(a) -> str:
    t = a.type_name or "?"
    suffix = ""
    if a.is_list:
        suffix += "[]"
    if a.required:
        suffix += "!"
    return f"{a.name}: {t}{suffix}"


def format_signature(fn: Function) -> str:
    sig = ", ".join(_format_arg(a) for a in fn.arguments)
    return f"{fn.name}({sig})"


# ────────────────────────── text ──────────────────────────


def text_report(url: str, findings: list[Finding],
                only_suspicious: bool = False,
                version: str = "0.2.0") -> str:
    host = urlparse(url).hostname or url
    lines = [f"supabase-rpc-auth-scanner v{version}",
             f"project: {host}", ""]
    suspicious = [f for f in findings if f.function.suspicious]
    safe = [f for f in findings if not f.function.suspicious]

    # Group by severity
    by_sev: dict[str, list[Finding]] = {SEV_CRITICAL: [], SEV_HIGH: [], SEV_MEDIUM: []}
    for f in suspicious:
        by_sev.setdefault(f.severity, []).append(f)

    for sev in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM):
        for f in by_sev[sev]:
            lines.append(f"[{sev.upper():8}] {format_signature(f.function)}")
            fn = f.function
            if sev == SEV_CRITICAL:
                lines.append("  multiple tenant-ID parameters + value params.")
                lines.append("  textbook cross-tenant mutation flaw when SECURITY DEFINER.")
            else:
                lines.append("  caller-controlled tenant ID + value param.")
                lines.append("  horizontal-authz flaw when the function is SECURITY DEFINER.")
            lines.append("  verify the function scopes to auth.uid() / session_user, not")
            lines.append("  to the caller-supplied identifier.")
            if f.probe:
                lines.append("")
                lines.append(f"  probe: POST /rest/v1/rpc/{fn.name}")
                if f.probe.invoked:
                    lines.append(f"         -> HTTP {f.probe.status} ({f.probe.classification})")
                    if f.probe.differential_match is True:
                        lines.append("         -> differential probe matched across two UUIDs")
                        lines.append("            (strong signal of arbitrary-UUID acceptance)")
                    if f.probe.status and f.probe.status not in (200, 204) and f.probe.body_sample:
                        lines.append(f"         -> body: {(f.probe.body_sample or '')[:140].strip()}")
                else:
                    lines.append(f"         -> probe error: {f.probe.error}")
            lines.append("")

    if not only_suspicious:
        lines.append("")
        for f in safe:
            lines.append(f"[INFO    ] {format_signature(f.function)}")
        lines.append("")

    total = len(suspicious) + len(safe)
    summary_parts = []
    for sev in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM):
        c = len(by_sev.get(sev, []))
        if c:
            summary_parts.append(f"{c} {sev}")
    summary_parts.append(f"{len(safe)} info")
    lines.append(f"{total} functions scanned · " + " · ".join(summary_parts))
    return "\n".join(lines)


# ────────────────────────── JSON ──────────────────────────


def json_report(url: str, findings: list[Finding],
                version: str = "0.2.0") -> str:
    host = urlparse(url).hostname or url
    out = {
        "tool": "supabase-rpc-auth-scanner",
        "version": version,
        "project": host,
        "scanned_at": _now_iso(),
        "summary": _summary(findings),
        "functions": [],
    }
    for f in findings:
        fn = f.function
        entry = {
            "name": fn.name,
            "signature": format_signature(fn),
            "in_mutation": fn.in_mutation,
            "suspicious": fn.suspicious,
            "severity": fn.severity,
            "approx_cvss": _APPROX_CVSS[fn.severity],
            "arguments": [
                {
                    "name": a.name,
                    "type": a.type_name,
                    "kind": a.type_kind,
                    "required": a.required,
                    "is_list": a.is_list,
                    "is_tenant_id": a.looks_like_tenant_id,
                    "is_safe_token": a.looks_like_safe_token,
                }
                for a in fn.arguments
            ],
            "tenant_arg_names": [a.name for a in fn.tenant_args],
            "value_arg_names": [a.name for a in fn.value_args],
        }
        if f.probe:
            entry["probe"] = {
                "invoked": f.probe.invoked,
                "status": f.probe.status,
                "classification": f.probe.classification,
                "differential_match": f.probe.differential_match,
                "body_sample": (f.probe.body_sample or "")[:300] if f.probe.body_sample else None,
                "error": f.probe.error,
            }
        out["functions"].append(entry)
    return json.dumps(out, indent=2)


def _summary(findings: list[Finding]) -> dict:
    counts = {SEV_CRITICAL: 0, SEV_HIGH: 0, SEV_MEDIUM: 0, SEV_INFO: 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "total": len(findings),
        "by_severity": counts,
        "suspicious": sum(1 for f in findings if f.function.suspicious),
    }


# ────────────────────────── SARIF 2.1.0 ──────────────────────────


SARIF_SCHEMA_URL = ("https://json.schemastore.org/sarif-2.1.0.json")

_SARIF_RULES = [
    {
        "id": "SUPA-RPC-001",
        "name": "HorizontalAuthzTenantID",
        "shortDescription": {"text": "RPC accepts caller-controlled tenant identifier"},
        "fullDescription": {
            "text": (
                "The RPC function accepts a tenant-scope identifier (account_id, "
                "org_id, workspace_slug, etc.) as a parameter AND at least one "
                "value parameter. If the function is SECURITY DEFINER and the body "
                "trusts the caller-supplied identifier, any authenticated user can "
                "operate on any other tenant's row. Scope must derive from "
                "auth.uid() / session_user, not from the caller-supplied argument."
            )
        },
        "help": {
            "text": (
                "Change the function body to ignore the caller-supplied tenant ID "
                "and derive scope from auth.uid() or current_setting('role'). "
                "If the parameter is needed for a non-auth purpose, rename it and "
                "add an explicit check that the caller owns the target row."
            ),
            "markdown": (
                "**Remediation:** Change the function body to derive tenant scope "
                "from `auth.uid()` or `current_setting('role')`. Do not trust the "
                "caller-supplied ID.\n\n"
                "**Example fix:**\n"
                "```sql\n"
                "CREATE OR REPLACE FUNCTION increment_leads_used(p_count INT)\n"
                "RETURNS VOID\n"
                "LANGUAGE plpgsql\n"
                "SECURITY DEFINER\n"
                "SET search_path = public\n"
                "AS $$\n"
                "BEGIN\n"
                "  UPDATE accounts\n"
                "     SET leads_used = leads_used + p_count\n"
                "   WHERE owner_id = auth.uid();\n"
                "END;\n"
                "$$;\n"
                "```"
            ),
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "security-severity": "7.5",
            "tags": ["security", "authorization", "horizontal-privilege-escalation",
                     "supabase", "postgres", "rls"],
        },
    },
    {
        "id": "SUPA-RPC-002",
        "name": "CrossTenantMutation",
        "shortDescription": {"text": "RPC accepts multiple tenant IDs for cross-tenant mutation"},
        "fullDescription": {
            "text": (
                "The RPC accepts two or more distinct tenant-scope identifiers plus "
                "a value parameter. Functions of this shape (e.g. transfer_credits("
                "src_org, dst_org, amount)) are textbook cross-tenant mutation risks "
                "when SECURITY DEFINER."
            )
        },
        "help": {
            "text": (
                "Redesign the function so that at most one tenant ID is "
                "accepted and the other is derived from auth.uid() or a "
                "JOIN. If a cross-tenant transfer is legitimate, enforce an "
                "explicit permission check against both source and "
                "destination before the mutation."
            ),
            "markdown": (
                "**Remediation:** Redesign the function so only one tenant "
                "ID is accepted OR require an explicit pre-check that "
                "`auth.uid()` has permission on both tenants.\n\n"
                "**Example hardened form:**\n"
                "```sql\n"
                "CREATE OR REPLACE FUNCTION transfer_credits("
                "p_dst_org_id UUID, p_amount INT)\n"
                "RETURNS VOID\n"
                "LANGUAGE plpgsql\n"
                "SECURITY DEFINER\n"
                "AS $$\n"
                "DECLARE\n"
                "  v_src_org_id UUID;\n"
                "BEGIN\n"
                "  SELECT org_id INTO v_src_org_id\n"
                "    FROM org_members\n"
                "   WHERE user_id = auth.uid() AND role = 'admin';\n"
                "  IF v_src_org_id IS NULL THEN\n"
                "    RAISE EXCEPTION 'not an org admin';\n"
                "  END IF;\n"
                "  -- verify dst is partnered with src ...\n"
                "  UPDATE accounts SET credits = credits - p_amount\n"
                "   WHERE id = v_src_org_id;\n"
                "  UPDATE accounts SET credits = credits + p_amount\n"
                "   WHERE id = p_dst_org_id;\n"
                "END;\n"
                "$$;\n"
                "```"
            ),
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {
            "security-severity": "9.1",
            "tags": ["security", "authorization", "cross-tenant",
                     "supabase", "postgres"],
        },
    },
]


def sarif_report(url: str, findings: list[Finding],
                 version: str = "0.2.0") -> str:
    host = urlparse(url).hostname or url
    results = []
    for f in findings:
        if not f.function.suspicious:
            continue
        rule_id = "SUPA-RPC-002" if f.severity == SEV_CRITICAL else "SUPA-RPC-001"
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {
                "text": (
                    f"{format_signature(f.function)} accepts a caller-controlled "
                    f"tenant identifier and a value parameter. If SECURITY DEFINER, "
                    f"any authenticated user can operate on any tenant."
                )
            },
            "locations": [{
                "logicalLocations": [{
                    "name": f.function.name,
                    "kind": "function",
                    "fullyQualifiedName": f"supabase.rpc.{f.function.name}",
                }]
            }],
            "properties": {
                "severity": f.severity,
                "approx_cvss": _APPROX_CVSS[f.severity],
                "project": host,
                "tenant_args": [a.name for a in f.function.tenant_args],
                "value_args": [a.name for a in f.function.value_args],
                "probe_classification": (
                    f.probe.classification if f.probe else None
                ),
            },
        })
    out = {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "supabase-rpc-auth-scanner",
                    "version": version,
                    "informationUri":
                        "https://github.com/TreRB/supabase-rpc-auth-scanner",
                    "rules": _SARIF_RULES,
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": _now_iso(),
            }],
            "properties": {"project": host},
            "results": results,
        }],
    }
    return json.dumps(out, indent=2)


# ────────────────────────── Markdown ──────────────────────────


def markdown_report(url: str, findings: list[Finding],
                    version: str = "0.2.0") -> str:
    host = urlparse(url).hostname or url
    lines = [
        f"# supabase-rpc-auth-scanner v{version}",
        "",
        f"- **Project:** {host}",
        f"- **Scanned:** {_now_iso()}",
        "",
    ]
    summ = _summary(findings)
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total functions scanned: {summ['total']}")
    for sev in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM):
        c = summ["by_severity"].get(sev, 0)
        if c:
            lines.append(f"- {sev.capitalize()}: {c}")
    lines.append(f"- Info (no finding): {summ['by_severity'].get(SEV_INFO, 0)}")
    lines.append("")

    by_sev: dict[str, list[Finding]] = {SEV_CRITICAL: [], SEV_HIGH: [], SEV_MEDIUM: []}
    for f in findings:
        if f.function.suspicious:
            by_sev.setdefault(f.severity, []).append(f)

    for sev in (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM):
        if not by_sev.get(sev):
            continue
        lines.append(f"## {sev.capitalize()} findings")
        lines.append("")
        for f in by_sev[sev]:
            lines.append(f"### `{format_signature(f.function)}`")
            lines.append("")
            lines.append(f"- Severity: **{sev}**")
            lines.append(f"- Tenant args: `{'`, `'.join(a.name for a in f.function.tenant_args)}`")
            val_names = [a.name for a in f.function.value_args]
            if val_names:
                lines.append(f"- Value args: `{'`, `'.join(val_names)}`")
            if f.probe:
                lines.append(f"- Probe: HTTP {f.probe.status} ({f.probe.classification})")
                if f.probe.differential_match is True:
                    lines.append("- Differential probe: matched across two UUIDs (strong signal)")
            lines.append("")
    return "\n".join(lines)


# ────────────────────────── helpers ──────────────────────────


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
