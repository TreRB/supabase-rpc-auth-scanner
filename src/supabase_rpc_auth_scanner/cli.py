"""Command-line entry point."""
from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlparse

from . import __version__
from .scanner import Finding, Scanner


def _format_arg(a) -> str:
    t = a.type_name or "?"
    return f"{a.name}: {t}{'!' if a.required else ''}"


def _text_report(url: str, findings: list[Finding], only_suspicious: bool) -> str:
    lines = []
    host = urlparse(url).hostname or url
    lines.append(f"supabase-rpc-auth-scanner v{__version__}")
    lines.append(f"project: {host}")
    lines.append("")

    suspicious = [f for f in findings if f.function.suspicious]
    safe = [f for f in findings if not f.function.suspicious]

    for f in suspicious:
        fn = f.function
        sig = ", ".join(_format_arg(a) for a in fn.arguments)
        lines.append(f"[!] {fn.name}({sig})")
        lines.append(f"    caller-controlled tenant ID + value parameter.")
        lines.append(f"    this pattern is the textbook horizontal-authz flaw when the")
        lines.append(f"    function is SECURITY DEFINER. verify the function body scopes")
        lines.append(f"    to auth.uid(), not to the caller-supplied UUID.")
        if f.probe is not None:
            lines.append("")
            lines.append(f"    probe: POST /rest/v1/rpc/{fn.name}")
            if f.probe.invoked:
                verdict = "flaw likely" if f.probe.status in (200, 204) else "not confirmed"
                lines.append(f"           -> HTTP {f.probe.status}  ({verdict})")
                if f.probe.status not in (200, 204) and f.probe.message:
                    lines.append(f"              detail: {f.probe.message[:160]}")
            else:
                lines.append(f"           -> probe error: {f.probe.message}")
        lines.append("")

    if not only_suspicious:
        for f in safe:
            fn = f.function
            sig = ", ".join(_format_arg(a) for a in fn.arguments) or "()"
            lines.append(f"[ok] {fn.name}({sig})")
            lines.append(f"    no caller-controlled tenant parameter; looks invoker-scoped.")
            lines.append("")

    total = len(suspicious) + len(safe)
    lines.append(
        f"{len(suspicious)} suspicious function(s), {len(safe)} apparently-safe function(s) "
        f"of {total} non-builtin mutations."
    )
    return "\n".join(lines)


def _json_report(url: str, findings: list[Finding]) -> str:
    out = {
        "tool": "supabase-rpc-auth-scanner",
        "version": __version__,
        "project": urlparse(url).hostname or url,
        "functions": [],
    }
    for f in findings:
        fn = f.function
        entry = {
            "name": fn.name,
            "suspicious": fn.suspicious,
            "arguments": [
                {"name": a.name, "type": a.type_name, "kind": a.type_kind, "required": a.required}
                for a in fn.arguments
            ],
        }
        if f.probe is not None:
            entry["probe"] = {
                "invoked": f.probe.invoked,
                "status": f.probe.status,
                "message": f.probe.message,
            }
        out["functions"].append(entry)
    return json.dumps(out, indent=2)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="supabase-rpc-auth-scanner",
        description="Audit a Supabase project's GraphQL Mutation surface for SECURITY DEFINER RPCs with caller-controlled tenant IDs.",
    )
    ap.add_argument("--url", required=True, help="Supabase project URL (https://xxx.supabase.co)")
    ap.add_argument("--key", required=True, help="Publishable/anon key (sb_publishable_... or legacy JWT)")
    ap.add_argument("--jwt", required=True, help="An authenticated user JWT")
    ap.add_argument("--probe", action="store_true",
                    help="Actively call suspicious RPCs with a random UUID + zero-valued payload to confirm the authz gap. Only use on projects you own or have permission to test.")
    ap.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON instead of text")
    ap.add_argument("--out", help="Write report to a file")
    ap.add_argument("--timeout", type=int, default=10, help="HTTP timeout, seconds (default 10)")
    ap.add_argument("--only-suspicious", action="store_true",
                    help="Skip functions that look safe in the text report")
    ap.add_argument("-V", "--version", action="version", version=f"supabase-rpc-auth-scanner {__version__}")
    args = ap.parse_args(argv)

    scanner = Scanner(url=args.url, key=args.key, jwt=args.jwt, timeout=args.timeout)
    try:
        findings = scanner.scan(probe=args.probe)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.as_json:
        report = _json_report(args.url, findings)
    else:
        report = _text_report(args.url, findings, args.only_suspicious)

    if args.out:
        with open(args.out, "w") as f:
            f.write(report)
            if not report.endswith("\n"):
                f.write("\n")
    else:
        print(report)

    # Exit 1 if anything suspicious was found (CI-friendly)
    return 1 if any(f.function.suspicious for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
