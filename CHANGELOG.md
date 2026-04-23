# Changelog

All notable changes to `supabase-rpc-auth-scanner` are documented here.

## [0.2.0] - 2026-04-23

Significant refactor around the scanner core, reporter layer, and test
coverage. This release is backward-incompatible for anyone relying on
the internal `Function.value_args` behaviour; the CLI flags are a
compatible superset.

### Added

- **Severity classification.** Findings are now classified as
  `critical` (cross-tenant, two+ tenant args), `high` (classic
  caller-controlled tenant + value arg), `medium` (tenant + only safe
  tokens), or `info` (no finding).
- **Known-safe exclusions.** Tokens matching `invite`, `token`,
  `session`, `message`, `magic`, `verify`, etc. no longer cause false
  positives on `accept_invite(p_invite_id, p_decision)`-shaped RPCs.
- **Expanded tenant-type detection.** Non-UUID tenant identifiers
  (`BigInt`, `Int`, slug-typed `String` like `workspace_slug`) now
  classify correctly.
- **Vertical-aware name patterns.** Healthcare (`hospital_id`,
  `clinic_id`, `practice_id`), legal (`firm_id`), retail (`store_id`),
  real-estate (`landlord_id`, `operator_id`), and logistics
  (`branch_id`, `region_id`, `facility_id`) tenant fields now detected.
- **Differential probing.** `--probe` now sends two requests with
  different UUIDs and compares responses. A matching 200/204 across
  both is a strong signal of arbitrary-UUID acceptance.
- **`--include-queries` flag.** Introspects the `Query` type for
  functions that `RETURN TABLE` / `RETURNS SETOF`, which also appear
  in the pg_graphql surface and can be SECURITY DEFINER.
- **SARIF 2.1.0 output.** GitHub Advanced Security + Azure DevOps
  compatible, with embedded remediation text + code fixes.
- **Markdown output.** For PR-comment and issue-body usage.
- **JSON output** includes severity, approximate CVSS, per-argument
  classification, and probe details.
- **`--verbose` mode** for per-function classification log to stderr.
- **`--ci` flag** ensures non-zero exit on any suspicious finding
  regardless of output format.
- **GitHub Actions workflow templates** (`.github/workflows/test.yml`
  for CI on this repo, `example-scan.yml` for users to copy).

### Fixed

- **`value_args` logic bug.** The previous implementation had a
  short-circuit expression that always returned all non-UUID args
  regardless of the `p_` prefix check. Value detection is now
  deterministic and correctly excludes safe-token-shaped IDs.
- **Multi-layer GraphQL type unwrapping.** Previously only unwrapped
  one `NON_NULL` layer. Now correctly unwraps
  `NON_NULL { LIST { NON_NULL { UUID } } }` and tracks the `is_list`
  flag.
- **User-Agent header** is now set on all outbound requests for better
  server-side observability and rate-limit behaviour.

### Changed

- **Test suite expanded from 6 → 50 tests**, including integration
  tests with mocked HTTP, SARIF schema validation, probe
  classification, and type-unwrap edge cases.
- **CLI flags reorganized** into `target`, `scan`, and `output`
  argument groups for discoverability.

### Previously in 0.1.0

- Core Mutation introspection and tenant-UUID heuristic.
- Text and JSON output formats.
- Basic `--probe` mode.
