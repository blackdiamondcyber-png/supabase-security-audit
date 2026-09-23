-- Assertions that audit.sql reports every problem planted by fixture.sql.
-- Run after 00-local-shim.sql and fixture.sql. Raises on first failure.
--
-- This runs the real audit.sql, read in whole rather than re-typed, so
-- the test tracks the shipped file instead of a copy of it.

begin;

-- psql cannot finish an open statement from inside \i, so the shipped
-- file is read into a variable and interpolated whole.
\set audit_query `cat sql/audit.sql`
create temporary table audit_results as :audit_query

do $$
declare
  v_count int;
begin
  select count(*) into v_count from audit_results
   where finding = 'table without RLS' and object = 'orders_no_rls';
  if v_count <> 1 then
    raise exception 'expected orders_no_rls flagged as table without RLS, found %', v_count;
  end if;

  select count(*) into v_count from audit_results
   where finding = 'RLS on, no policy' and object = 'notes_rls_no_policy';
  if v_count <> 1 then
    raise exception 'expected notes_rls_no_policy flagged as RLS on, no policy, found %', v_count;
  end if;

  select count(*) into v_count from audit_results
   where finding = 'SECURITY DEFINER callable by anon' and object = 'fixture_anon_secdef';
  if v_count <> 1 then
    raise exception 'expected fixture_anon_secdef flagged as anon-callable SECURITY DEFINER, found %', v_count;
  end if;

  select count(*) into v_count from audit_results
   where finding = 'SECURITY DEFINER callable by authenticated' and object = 'fixture_authed_secdef';
  if v_count <> 1 then
    raise exception 'expected fixture_authed_secdef flagged as authenticated-callable SECURITY DEFINER, found %', v_count;
  end if;

  select count(*) into v_count from audit_results
   where finding = 'trigger function directly callable' and object = 'fixture_trigger_fn';
  if v_count <> 1 then
    raise exception 'expected fixture_trigger_fn flagged as a directly callable trigger function, found %', v_count;
  end if;

  select count(*) into v_count from audit_results
   where finding = 'function without pinned search_path' and object = 'fixture_unpinned_path';
  if v_count <> 1 then
    raise exception 'expected fixture_unpinned_path flagged for an unpinned search_path, found %', v_count;
  end if;

  select count(*) into v_count from audit_results
   where finding = 'extension in public schema' and object = 'pgcrypto';
  if v_count <> 1 then
    raise exception 'expected pgcrypto flagged as an extension in public schema, found %', v_count;
  end if;

  -- fixture_anon_secdef must not also count as an authenticated-only
  -- finding: the two checks are supposed to be mutually exclusive.
  select count(*) into v_count from audit_results
   where finding = 'SECURITY DEFINER callable by authenticated' and object = 'fixture_anon_secdef';
  if v_count <> 0 then
    raise exception 'fixture_anon_secdef should not also appear under the authenticated-only finding';
  end if;

  raise notice 'audit.sql reported all 7 planted findings';
end $$;

rollback;
