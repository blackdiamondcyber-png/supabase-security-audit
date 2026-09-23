-- audit.sql, remediate.sql and verify.sql all call has_function_privilege()
-- against the literal role names 'anon' and 'authenticated', which Supabase
-- provides on every project. This file creates just those two roles on a
-- plain Postgres, locally or in CI, so the checks have something real to
-- query has_function_privilege() against.
--
-- Do not run this on Supabase. It already has both roles.
--
-- Unlike rls-multitenant-patterns, nothing here needs the auth schema or
-- auth.uid(): these scripts read privilege catalogs, not row data.

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin;
  end if;
end $$;
