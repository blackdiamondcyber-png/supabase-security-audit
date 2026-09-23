-- A deliberately misconfigured schema, fictional names throughout, one
-- object per check that audit.sql performs. Run after 00-local-shim.sql.
-- Nothing here is a real project; it exists so audit.sql, remediate.sql and
-- verify.sql have something real to find, fix, and confirm fixed.

-- 1. tables_no_rls: a table where row level security was never turned on.
create table orders_no_rls (
  id    serial primary key,
  note  text
);

-- 2. rls_no_policy: RLS switched on, deliberately no policy attached.
-- Deny-by-default, and the exact shape the audit calls out as "intentional,
-- or a table someone forgot?"
create table notes_rls_no_policy (
  id    serial primary key,
  body  text
);
alter table notes_rls_no_policy enable row level security;

-- 3. anon_secdef: SECURITY DEFINER with a pinned search_path, left at its
-- default grant. Postgres grants EXECUTE to PUBLIC on a new function unless
-- something revokes it, and anon inherits PUBLIC, so anon can call this.
create function fixture_anon_secdef()
returns text
language sql
security definer
set search_path = public
as $$ select 'reachable by anon'::text $$;

-- 4. authed_secdef: SECURITY DEFINER, search_path pinned, cut back to
-- authenticated only. This is the shape of a real, intended API function.
create function fixture_authed_secdef()
returns text
language sql
security definer
set search_path = public
as $$ select 'reachable by authenticated only'::text $$;
revoke execute on function fixture_authed_secdef() from public;
grant execute on function fixture_authed_secdef() to authenticated;

-- 5. trigger_fn_exec: a trigger function left directly callable. Attached
-- to notes_rls_no_policy so it is a real trigger function, not just a
-- function that happens to return trigger.
create function fixture_trigger_fn()
returns trigger
language plpgsql
as $$ begin return new; end $$;

create trigger notes_rls_no_policy_biu
  before insert or update on notes_rls_no_policy
  for each row execute function fixture_trigger_fn();

-- 6. mutable_path: SECURITY DEFINER with no search_path pinned at all, and
-- no execute grants to anyone, so it shows up only here and not in the
-- anon/authenticated findings above.
create function fixture_unpinned_path()
returns text
language sql
security definer
as $$ select 'no pinned search_path'::text $$;
revoke execute on function fixture_unpinned_path() from public;

-- 7. ext_in_public: an extension installed in public instead of a
-- dedicated schema. pgcrypto is small and already proven available on the
-- postgres:16 image this suite runs against (n8n-approval-patterns uses it
-- the same way).
create extension if not exists pgcrypto with schema public;
