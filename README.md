# Supabase Security Audit

[![audit](https://github.com/blackdiamondcyber-png/supabase-security-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/blackdiamondcyber-png/supabase-security-audit/actions/workflows/ci.yml)

Read-only SQL that tells you what is actually exposed in a Postgres or Supabase
project. It needs no agent or dashboard and never writes anything. Paste it into the SQL
editor and read the output, or run it from a terminal:

```bash
psql "$DATABASE_URL" -f sql/audit.sql
```

I wrote this auditing my own production database before anyone asked me to. It
found something. That is generally how this goes.

## What it checks

| Check | Why it matters |
|-------|----------------|
| Tables without RLS enabled | Anything readable with the public API key |
| RLS enabled but no policy | Deny-by-default, which is safe but usually accidental |
| `SECURITY DEFINER` functions callable by `anon` | These bypass RLS entirely |
| Same, callable by `authenticated` | Your real API surface; know what is in it |
| Functions with unpinned `search_path` | A caller can shadow `public` and change what runs |
| Trigger functions with direct execute rights | Triggers fire regardless; direct calls are unintended |
| Extensions installed in `public` | Namespace collisions, harder to reason about |

## The finding that matters most

Batch import and export helpers get written as `SECURITY DEFINER` so they can
move data without fighting policies. That is correct. The mistake is leaving
`EXECUTE` granted to `anon` and `authenticated`, which is the default. The
default comes from `PUBLIC`: Postgres grants `EXECUTE` on every new function to
`PUBLIC`, and every role inherits it, so revoking from `anon` and
`authenticated` alone leaves the function callable. The first CI run of this
repo's own fixture caught `remediate.sql` making exactly that mistake.

When that happens, your entire RLS policy set is decorative. Every table can be
enabled, every policy can be correct, and one unguarded function still hands out
the whole database. Gating it behind a hardcoded secret inside the function body
is not a fix: a static shared secret has no per-caller identity, no expiry, and
no audit trail, so you cannot tell whether it has ever been used.

```sql
-- The fix. Server-side callers use the service role key and are unaffected.
revoke execute on function public.bulk_export(text) from public, anon, authenticated;
```

## Trigger functions are a different case

A function returning `trigger` does not need direct execute rights. Triggers
fire as part of the statement regardless of who can call the function by name.
Revoking `EXECUTE` from `PUBLIC`, `anon` and `authenticated` on trigger functions removes
an unintended call path and breaks nothing.

## Reading the output

`audit.sql` returns one row per finding with a severity. Expect noise on a
healthy project:

- Deny-by-default tables are usually staging tables rather than problems.
- The list of `authenticated`-callable functions is your API. It should be
  large. What matters is whether anything in it surprises you.
- One anon-callable function is often a legitimate signup or lookup path. Read
  its body and confirm it returns one row and leaks nothing.

## Sample output

This is `audit.sql` run by CI against `tests/fixture.sql`, a schema with one
deliberate mistake per check. CI prints this report on every push and fails if
it stops matching the block below. Every name is fictional; nothing here comes from a
real project.

```text
 severity |                  finding                   |        object         |                             detail
----------+--------------------------------------------+-----------------------+-----------------------------------------------------------------
 CRITICAL | SECURITY DEFINER callable by anon          | fixture_anon_secdef   | Bypasses RLS. Anyone with the public key can call it.
 CRITICAL | table without RLS                          | orders_no_rls         | Readable/writable with the public API key
 MEDIUM   | function without pinned search_path        | fixture_unpinned_path | A caller can shadow public and change what this function reads.
 REVIEW   | SECURITY DEFINER callable by authenticated | fixture_authed_secdef | Part of your API surface. Confirm it should be.
 LOW      | extension in public schema                 | pgcrypto              | Consider a dedicated schema to avoid namespace collisions.
 LOW      | trigger function directly callable         | fixture_trigger_fn    | Triggers fire regardless. Direct execute is an unintended path.
 INFO     | RLS on, no policy                          | notes_rls_no_policy   | Deny-by-default. Intentional, or a table someone forgot?
(7 rows)
```

`remediate.sql` then generates these four statements, CI runs them, and
`verify.sql` has to report zero on every counter that should be zero:

```sql
revoke execute on function public.fixture_anon_secdef() from public, anon, authenticated;
revoke execute on function public.fixture_trigger_fn() from public, anon, authenticated;
alter function public.fixture_unpinned_path() set search_path = public;
alter table public.orders_no_rls enable row level security;
```

Getting this loop green found two bugs in the scripts themselves. `audit.sql`
sorted a `UNION` by an expression, which Postgres rejects, so it did not run as
published. And `remediate.sql` revoked from `anon` and `authenticated` but
not `PUBLIC`, which left the fixture's anon-callable function callable after
"remediation". Both are fixed, and the test now fails if either comes back.

## Files

| Path | Contents |
|------|----------|
| `sql/audit.sql` | All checks, one result set, severity-ordered |
| `sql/remediate.sql` | Generates the REVOKE and ALTER statements for you |
| `sql/verify.sql` | Re-run after remediation to confirm |
| `sql/00-local-shim.sql` | Anon and authenticated roles for a plain Postgres |
| `tests/fixture.sql` | Deliberately misconfigured schema for the tests below |
| `tests/audit-tests.sql` | Asserts audit.sql catches every planted problem |
| `tests/verify-tests.sql` | Asserts verify.sql is clean after remediation |

## Order of operations

Audit, then remediate, then verify. Do not trust that a fix applied because you
ran it: a web console can silently drop a change on a page reload, so re-query
the privilege tables and read the answer.

If you find a credential in a repository or a function body, rotate it before
you scrub it. Removing a secret from source does not un-leak it.

## License

MIT.

More of my work: [erik-pearson-portfolio.vercel.app](https://erik-pearson-portfolio.vercel.app). Contact: [LinkedIn](https://www.linkedin.com/in/erikpearson2).
