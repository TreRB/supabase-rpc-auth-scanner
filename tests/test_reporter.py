"""Tests for output formatters."""
from __future__ import annotations

import json

from supabase_rpc_auth_scanner.reporter import (
    format_signature,
    json_report,
    markdown_report,
    sarif_report,
    text_report,
    SARIF_SCHEMA_URL,
)
from supabase_rpc_auth_scanner.scanner import (
    Argument,
    Finding,
    Function,
    ProbeResult,
    SEV_CRITICAL,
    SEV_HIGH,
    SEV_INFO,
)


def _arg(name: str, type_name: str, required: bool = True) -> Argument:
    return Argument(name=name, type_name=type_name, type_kind="SCALAR",
                    required=required)


def _vulnerable_finding() -> Finding:
    fn = Function(
        name="increment_leads_used",
        arguments=[_arg("p_account_id", "UUID"), _arg("p_count", "Int")],
    )
    return Finding(
        function=fn,
        probe=ProbeResult(
            invoked=True, status=204, body_sample="",
            classification="accepts_arbitrary_uuid",
            differential_match=True,
        ),
    )


def _safe_finding() -> Finding:
    fn = Function(name="whoami", arguments=[])
    return Finding(function=fn, probe=None)


def _critical_finding() -> Finding:
    fn = Function(
        name="transfer_credits",
        arguments=[
            _arg("src_org_id", "UUID"),
            _arg("dst_org_id", "UUID"),
            _arg("amount", "Int"),
        ],
    )
    return Finding(function=fn)


# ───────────── signature formatting ─────────────


def test_format_signature_required_marker():
    fn = Function(
        name="add_user",
        arguments=[_arg("u", "UUID", required=True),
                   _arg("n", "String", required=False)],
    )
    sig = format_signature(fn)
    assert sig == "add_user(u: UUID!, n: String)"


def test_format_signature_list_marker():
    fn = Function(
        name="set_tags",
        arguments=[Argument(name="tags", type_name="String", type_kind="SCALAR",
                            required=True, is_list=True)],
    )
    sig = format_signature(fn)
    assert "[]" in sig


# ────────────────── text report ──────────────────


def test_text_report_lists_suspicious_findings():
    r = text_report("https://abc.supabase.co",
                    [_vulnerable_finding(), _safe_finding()])
    assert "increment_leads_used" in r
    assert "HIGH" in r
    assert "supabase-rpc-auth-scanner v" in r
    assert "abc.supabase.co" in r


def test_text_report_only_suspicious_hides_safe():
    r = text_report("https://x.supabase.co",
                    [_vulnerable_finding(), _safe_finding()],
                    only_suspicious=True)
    assert "whoami" not in r
    assert "increment_leads_used" in r


def test_text_report_probe_output():
    r = text_report("https://x.supabase.co", [_vulnerable_finding()])
    assert "probe" in r.lower()
    assert "accepts_arbitrary_uuid" in r
    assert "differential probe matched" in r


def test_text_report_empty_findings():
    r = text_report("https://x.supabase.co", [])
    assert "0 functions scanned" in r


# ────────────────── JSON report ──────────────────


def test_json_report_valid_json():
    r = json_report("https://x.supabase.co",
                    [_vulnerable_finding(), _safe_finding()])
    data = json.loads(r)
    assert data["tool"] == "supabase-rpc-auth-scanner"
    assert "version" in data
    assert data["project"] == "x.supabase.co"
    assert "scanned_at" in data
    assert data["summary"]["total"] == 2
    assert data["summary"]["suspicious"] == 1


def test_json_report_includes_severity_and_cvss():
    r = json_report("https://x.supabase.co", [_vulnerable_finding()])
    data = json.loads(r)
    fn_entry = data["functions"][0]
    assert fn_entry["severity"] == SEV_HIGH
    assert fn_entry["approx_cvss"] == 7.5
    assert "tenant_arg_names" in fn_entry
    assert "value_arg_names" in fn_entry


def test_json_report_critical_severity():
    r = json_report("https://x.supabase.co", [_critical_finding()])
    data = json.loads(r)
    assert data["functions"][0]["severity"] == SEV_CRITICAL
    assert data["functions"][0]["approx_cvss"] == 9.1


def test_json_report_probe_fields():
    r = json_report("https://x.supabase.co", [_vulnerable_finding()])
    data = json.loads(r)
    probe = data["functions"][0]["probe"]
    assert probe["status"] == 204
    assert probe["classification"] == "accepts_arbitrary_uuid"
    assert probe["differential_match"] is True


# ────────────────── SARIF 2.1.0 ──────────────────


def test_sarif_valid_schema():
    r = sarif_report("https://x.supabase.co",
                     [_vulnerable_finding(), _safe_finding()])
    data = json.loads(r)
    assert data["$schema"] == SARIF_SCHEMA_URL
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "supabase-rpc-auth-scanner"
    assert "rules" in driver
    assert len(driver["rules"]) == 2


def test_sarif_results_only_suspicious():
    """SARIF should only include suspicious findings as results."""
    r = sarif_report("https://x.supabase.co",
                     [_vulnerable_finding(), _safe_finding(), _critical_finding()])
    data = json.loads(r)
    results = data["runs"][0]["results"]
    assert len(results) == 2  # vulnerable + critical, not safe


def test_sarif_rule_id_routing():
    """Critical findings use SUPA-RPC-002, High use SUPA-RPC-001."""
    r = sarif_report("https://x.supabase.co",
                     [_vulnerable_finding(), _critical_finding()])
    data = json.loads(r)
    rule_ids = [res["ruleId"] for res in data["runs"][0]["results"]]
    assert "SUPA-RPC-001" in rule_ids
    assert "SUPA-RPC-002" in rule_ids


def test_sarif_level_mapping():
    """severity=high → level=error, severity=critical → level=error."""
    r = sarif_report("https://x.supabase.co",
                     [_vulnerable_finding(), _critical_finding()])
    data = json.loads(r)
    for res in data["runs"][0]["results"]:
        assert res["level"] == "error"


def test_sarif_rule_metadata_complete():
    """The driver rules include remediation help + CWE-equivalent tags."""
    r = sarif_report("https://x.supabase.co", [])
    data = json.loads(r)
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    for rule in rules:
        assert "help" in rule
        assert "fullDescription" in rule
        assert "markdown" in rule["help"] or "text" in rule["help"]
        assert "security-severity" in rule["properties"]


# ────────────────── Markdown ──────────────────


def test_markdown_report_has_header_and_summary():
    r = markdown_report("https://x.supabase.co",
                        [_vulnerable_finding(), _critical_finding(), _safe_finding()])
    assert r.startswith("# supabase-rpc-auth-scanner v")
    assert "## Summary" in r
    assert "- Total functions scanned: 3" in r


def test_markdown_report_lists_findings_by_severity_section():
    r = markdown_report("https://x.supabase.co",
                        [_vulnerable_finding(), _critical_finding()])
    assert "## Critical findings" in r
    assert "## High findings" in r
    # Signature should appear in backticks
    assert "`transfer_credits" in r
    assert "`increment_leads_used" in r
