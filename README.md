# supabase-rpc-auth-scanner

Audit a Supabase project's `pg_graphql` Mutation (and optionally Query)
surface for `SECURITY DEFINER` RPC functions that accept caller-controlled
tenant identifiers — the horizontal-authorization flaw class that defeats
RLS without the developer realizing it.

Built by [Valtik Studios](https://valtikstudios.com). MIT licensed.

- **Severity-classified output** (critical / high / medium / info)
- **Type-aware detection** (UUID, BigInt, Int, text-slug tenants)
- **Vertical-aware names** (healthcare, legal, retail, real-estate, logistics)
- **Known-safe exclusions** (invite tokens, magic links, session IDs, message IDs)
- **Differential probing** (two-UUID diff to separate "accepts anything" from "permission denied")
- **SARIF 2.1.0 + JSON + Markdown + text output** for CI integration
- **50 tests**, pure stdlib, zero external dependencies

## Why this exists

RLS on a Supabase project is normally watertight when every caller uses
the `authenticated` role and the policy is a simple `auth.uid() =
user_id`. But `SECURITY DEFINER` functions run as the function owner
(typically `postgres`), and RLS is bypassed inside the function body. If
the function trusts a parameter like `p_account_id` instead of deriving
scope from `auth.uid()`, any authenticated user can pass *someone else's*
account ID and make the function operate on that tenant.

We found exactly this pattern in a real Supabase-backed SaaS during a
pentest: a `SECURITY DEFINER` RPC named `increment_leads_used(p_account_id
uuid, p_count int)` let any authenticated user inflate any other tenant's
usage counter to `INT_MAX`, or zero it out to bypass trial limits. RLS on
the underlying table was correctly configured — the function simply
bypassed it.

The scanner surfaces this entire class of flaw automatically.

## What it does

1. Pulls the `Mutation` type (and `Query` with `--include-queries`) from
   the project's `/graphql/v1` endpoint via introspection.
2. Classifies each function argument as: tenant identifier, safe token,
   value parameter, or unknown.
3. Flags functions whose argument list combines a tenant identifier with
   at least one value parameter. Downgrades to `info` when the only
   identifiers are safe-token-shaped (invite_id, session_id, etc.).
4. Optionally probes flagged RPCs with **two different random UUIDs**
   and compares responses. Matching 200/204 is a strong signal of
   arbitrary-UUID acceptance.
5. Emits a report in text, JSON, SARIF 2.1.0, or Markdown.

## Install

```bash
pipx install valtik-supabase-rpc-auth-scanner
# or
pip install valtik-supabase-rpc-auth-scanner
# or from source
git clone https://github.com/TreRB/supabase-rpc-auth-scanner
cd supabase-rpc-auth-scanner
pip install -e .
```

## Use

Basic scan (no active probing, text output):

```bash
supabase-rpc-auth-scanner \
    --url https://xxxxxxxxxxxxxxxxxxxx.supabase.co \
    --key sb_publishable_<your-anon-or-publishable-key> \
    --jwt <any-authenticated-user-jwt>
```

With active differential probing (only against projects you own or have
permission to test):

```bash
supabase-rpc-auth-scanner \
    --url https://xxxx.supabase.co \
    --key sb_publishable_... \
    --jwt <jwt> \
    --probe --include-queries --verbose
```

Emit SARIF for GitHub code scanning:

```bash
supabase-rpc-auth-scanner \
    --url https://xxxx.supabase.co \
    --key sb_publishable_... \
    --jwt <jwt> \
    --format sarif --out findings.sarif --ci
```

### CLI flags

| Group | Flag | Effect |
|-------|------|--------|
| target | `--url` | Supabase project URL (required) |
| target | `--key` | Publishable / anon key (required) |
| target | `--jwt` | Authenticated user JWT (required) |
| scan | `--probe` | Send differential (two-UUID) RPC probes to confirm suspected findings |
| scan | `--include-queries` | Also introspect the Query type (functions returning TABLE / SETOF) |
| scan | `--timeout N` | HTTP timeout in seconds (default 10) |
| scan | `--verbose` | Print per-function classification to stderr |
| output | `--format FMT` | `text` \| `json` \| `sarif` \| `markdown` (default `text`) |
| output | `--out PATH` | Write report to a file instead of stdout |
| output | `--only-suspicious` | Text format: skip info-level findings |
| output | `--ci` | Exit non-zero on any suspicious finding, any format |

## What the report looks like

### Text

```
supabase-rpc-auth-scanner v0.2.0
project: xxxxxxxxxxxxxxxxxxxx.supabase.co

[CRITICAL] transfer_credits(src_org_id: UUID!, dst_org_id: UUID!, amount: Int!)
  multiple tenant-ID parameters + value params.
  textbook cross-tenant mutation flaw when SECURITY DEFINER.

  probe: POST /rest/v1/rpc/transfer_credits
         -> HTTP 204 (accepts_arbitrary_uuid)
         -> differential probe matched across two UUIDs
            (strong signal of arbitrary-UUID acceptance)

[HIGH    ] increment_leads_used(p_account_id: UUID!, p_count: Int!)
  caller-controlled tenant ID + value param.
  horizontal-authz flaw when the function is SECURITY DEFINER.

5 functions scanned · 1 critical · 1 high · 3 info
```

### SARIF 2.1.0

Every suspicious finding emits a SARIF `result` entry with:
- `ruleId`: `SUPA-RPC-001` (high) or `SUPA-RPC-002` (critical)
- `level`: `error` / `warning` / `note`
- `logicalLocations`: `supabase.rpc.<function_name>`
- `properties.security-severity`: approximate CVSS-3.1 score
- Embedded remediation SQL snippet in `help.markdown`

The SARIF file is ready to upload to GitHub code scanning via
`github/codeql-action/upload-sarif@v3` (see
[`.github/workflows/example-scan.yml`](.github/workflows/example-scan.yml)
for a drop-in workflow).

### JSON

```json
{
  "tool": "supabase-rpc-auth-scanner",
  "version": "0.2.0",
  "project": "xxxxxxxxxxxxxxxxxxxx.supabase.co",
  "scanned_at": "2026-04-23T21:30:00Z",
  "summary": {
    "total": 5,
    "suspicious": 2,
    "by_severity": {"critical": 1, "high": 1, "medium": 0, "info": 3}
  },
  "functions": [
    {
      "name": "transfer_credits",
      "signature": "transfer_credits(src_org_id: UUID!, dst_org_id: UUID!, amount: Int!)",
      "suspicious": true,
      "severity": "critical",
      "approx_cvss": 9.1,
      "tenant_arg_names": ["src_org_id", "dst_org_id"],
      "value_arg_names": ["amount"],
      "probe": {
        "status": 204,
        "classification": "accepts_arbitrary_uuid",
        "differential_match": true
      }
    }
  ]
}
```

## Severity rubric

| Level | Condition |
|-------|-----------|
| `critical` | Two+ distinct tenant-shape args plus a value arg (e.g. `transfer_credits(src_org_id, dst_org_id, amount)`) |
| `high` | Single tenant-shape arg plus value arg (e.g. `increment_leads_used(p_account_id, p_count)`) |
| `medium` | Tenant-shape arg alongside only safe-token-shape IDs (e.g. `claim_invite_for_org(p_org_id, p_invite_id)`) |
| `info` | No tenant arg, or only safe-token args |

## Safe-token patterns we exclude

These parameter names are treated as single-use tokens whose uniqueness
is the authorization — flagging them would be false-positive noise:

`invite` / `invitation` / `token` / `session` / `message` /
`notification` / `reset` / `verify` / `verification` / `confirmation` /
`magic` / `otp` / `event` / `audit` / `log` / `webhook` / `thread` /
`comment` / `reply` / `attachment` / `file` / `media` / `asset` /
`upload` / `artifact`

## Tenant-shape patterns we detect

Argument names matching these (with optional `p_` prefix and
`_id` / `_uuid` / `_key` / `_slug` suffix) are treated as tenant
identifiers:

`account` / `tenant` / `org` / `organization` / `workspace` / `team` /
`user` / `owner` / `company` / `project` / `client` / `customer` /
`hospital` / `clinic` / `practice` / `firm` / `store` / `dealer` /
`franchise` / `partner` / `landlord` / `operator` / `branch` /
`region` / `district` / `location` / `facility` / `site`

The `hospital` / `clinic` / `practice` additions come from healthcare
engagements where the tenant model uses vertical-specific naming, and
the `firm` / `landlord` / `operator` additions come from legal / real-
estate / logistics projects.

## Running in GitHub Actions

Drop [`.github/workflows/example-scan.yml`](.github/workflows/example-scan.yml)
into your repo, configure `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`,
and `SUPABASE_TEST_JWT` as repo secrets, and every push and scheduled
nightly run will:

1. Execute the scanner against your Supabase project
2. Upload findings to GitHub Code Scanning (via SARIF)
3. Exit non-zero on any finding (blocks the PR check)

## What it WILL NOT do

- Read the PostgreSQL function body. `pg_graphql` only exposes argument
  names and types, not the SQL body. To confirm whether a flagged
  function is actually `SECURITY DEFINER` versus `SECURITY INVOKER`, you
  need database credentials or a peek in the migration repo. The scanner
  gives you a prioritized list of functions to audit manually.
- Exploit the flaw. Active probing sends zero-valued payloads
  (`p_count: 0`, empty strings, empty JSON) against random UUIDs, so
  side effects are no-ops on non-existent rows.

## The fix (for developers)

Rewrite flagged functions so scope comes from `auth.uid()`, not from a
caller-supplied parameter:

```sql
-- VULNERABLE
CREATE OR REPLACE FUNCTION public.increment_leads_used(p_account_id uuid, p_count int)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  UPDATE public.accounts SET leads_used = leads_used + p_count WHERE id = p_account_id;
END $$;

-- FIXED
CREATE OR REPLACE FUNCTION public.increment_leads_used(p_count int)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF p_count < 0 THEN RAISE EXCEPTION 'p_count must be non-negative'; END IF;
  UPDATE public.accounts
     SET leads_used = LEAST(leads_limit, leads_used + p_count)
   WHERE user_id = auth.uid();
END $$;
REVOKE EXECUTE ON FUNCTION public.increment_leads_used FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.increment_leads_used(int) TO authenticated;
```

## Development

```bash
git clone https://github.com/TreRB/supabase-rpc-auth-scanner
cd supabase-rpc-auth-scanner
pip install -e ".[dev]"
pytest tests/ -v
```

50 tests pass. Test coverage includes:
- Core heuristic classification across the severity matrix
- Type unwrapping for all GraphQL wrapper combos
- SARIF schema compliance
- Integration tests with mocked HTTP for full scan flow
- Differential probe behaviour
- JSON/Markdown formatter output shape

## Scope and ethics

Only run this against Supabase projects you own or have explicit
written permission to test. Active probing does not exploit anything,
but unsolicited probes against third-party production systems are
still not okay.

## Author

Built by Phillip (Tre) Bucchi at [Valtik Studios](https://valtikstudios.com).
We do cybersecurity consulting for SaaS and platform teams — penetration
testing, SOC 2 / PCI DSS 4.0 / HIPAA / CMMC 2.0 / NYDFS 500 readiness,
Supabase + Next.js security reviews. Based in Connecticut, serving
Dallas-Fort Worth + nationwide.

Reach us at tre@valtikstudios.com.

## License

MIT. See [LICENSE](LICENSE).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
