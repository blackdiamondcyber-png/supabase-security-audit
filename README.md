# Supabase Security Audit

Read-only SQL that tells you what is actually exposed in a Postgres or Supabase
project. It needs no agent or dashboard and never writes anything. Paste it into the SQL
editor and read the output.

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
`EXECUTE` granted to `anon` and `authenticated`, which is the default.

When that happens, your entire RLS policy set is decorative. Every table can be
enabled, every policy can be correct, and one unguarded function still hands out
the whole database. Gating it behind a hardcoded secret inside the function body
is not a fix: a static shared secret has no per-caller identity, no expiry, and
no audit trail, so you cannot tell whether it has ever been used.

```sql
-- The fix. Server-side callers use the service role key and are unaffected.
revoke execute on function public.bulk_export(text) from anon, authenticated;
```

## Trigger functions are a different case

A function returning `trigger` does not need direct execute rights. Triggers
fire as part of the statement regardless of who can call the function by name.
Revoking `EXECUTE` from `anon` and `authenticated` on trigger functions removes
an unintended call path and breaks nothing.

## Reading the output

`audit.sql` returns one row per finding with a severity. Expect noise on a
healthy project:

- Deny-by-default tables are usually staging tables, not problems.
- The list of `authenticated`-callable functions is your API. It should be
  large. What matters is whether anything in it surprises you.
- One anon-callable function is often a legitimate signup or lookup path. Read
  its body and confirm it returns one row and leaks nothing.

## Files

| Path | Contents |
|------|----------|
| `sql/audit.sql` | All checks, one result set, severity-ordered |
| `sql/remediate.sql` | Generates the REVOKE and ALTER statements for you |
| `sql/verify.sql` | Re-run after remediation to confirm |

## Order of operations

Audit, then remediate, then verify. Do not trust that a fix applied because you
ran it: a web console can silently drop a change on a page reload, so re-query
the privilege tables and read the answer.

If you find a credential in a repository or a function body, rotate it before
you scrub it. Removing a secret from source does not un-leak it.

## License

MIT.
