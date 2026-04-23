"""Command-line entry point."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .reporter import (
    json_report,
    markdown_report,
    sarif_report,
    text_report,
)
from .scanner import Scanner


FORMATS = ("text", "json", "sarif", "markdown")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="supabase-rpc-auth-scanner",
        description=(
            "Audit a Supabase project's pg_graphql Mutation (and optionally "
            "Query) surface for SECURITY DEFINER RPCs with caller-controlled "
            "tenant IDs. Finds the horizontal-authz flaw class."
        ),
        epilog=(
            "Example:\n"
            "  supabase-rpc-auth-scanner \\\n"
            "      --url https://abc.supabase.co \\\n"
            "      --key sb_publishable_... \\\n"
            "      --jwt <authenticated-user-jwt> \\\n"
            "      --probe --format sarif --out findings.sarif"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = ap.add_argument_group("target")
    target.add_argument("--url", required=True,
                        help="Supabase project URL (https://xxx.supabase.co)")
    target.add_argument("--key", required=True,
                        help="Publishable/anon key (sb_publishable_... or legacy JWT)")
    target.add_argument("--jwt", required=True,
                        help="An authenticated user JWT to use for introspection + probes")

    scan = ap.add_argument_group("scan")
    scan.add_argument("--probe", action="store_true",
                      help="Actively probe suspicious RPCs with differential UUID "
                           "requests. Only use on projects you own / have permission to test.")
    scan.add_argument("--include-queries", action="store_true",
                      help="Also introspect the Query type for RPC functions "
                           "(functions that RETURN TABLE / SETOF).")
    scan.add_argument("--timeout", type=int, default=10,
                      help="HTTP timeout seconds (default 10)")
    scan.add_argument("--verbose", action="store_true",
                      help="Print progress to stderr as functions are classified")

    output = ap.add_argument_group("output")
    output.add_argument("--format", choices=FORMATS, default="text",
                        help="Output format (default: text)")
    output.add_argument("--out", help="Write report to a file instead of stdout")
    output.add_argument("--only-suspicious", action="store_true",
                        help="Text report: skip functions that look safe")
    output.add_argument("--ci", action="store_true",
                        help="CI mode: exit non-zero if any suspicious finding, "
                             "regardless of output format")

    ap.add_argument("-V", "--version", action="version",
                    version=f"supabase-rpc-auth-scanner {__version__}")

    args = ap.parse_args(argv)

    scanner = Scanner(
        url=args.url, key=args.key, jwt=args.jwt,
        timeout=args.timeout, verbose=args.verbose,
    )
    try:
        findings = scanner.scan(probe=args.probe,
                                include_queries=args.include_queries)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.format == "json":
        report = json_report(args.url, findings, version=__version__)
    elif args.format == "sarif":
        report = sarif_report(args.url, findings, version=__version__)
    elif args.format == "markdown":
        report = markdown_report(args.url, findings, version=__version__)
    else:
        report = text_report(args.url, findings,
                             only_suspicious=args.only_suspicious,
                             version=__version__)

    if args.out:
        with open(args.out, "w") as f:
            f.write(report)
            if not report.endswith("\n"):
                f.write("\n")
    else:
        print(report)

    # Exit 1 if any suspicious finding (CI-friendly)
    if args.ci or args.format == "text":
        return 1 if any(f.function.suspicious for f in findings) else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
