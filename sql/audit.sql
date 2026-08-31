-- Read-only security audit. Returns one row per finding.
-- Safe to run on production; performs no writes.

with
tables_no_rls as (
  select 'CRITICAL' as severity,
         'table without RLS' as finding,
         c.relname as object,
         'Readable/writable with the public API key' as detail
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity
),
rls_no_policy as (
  select 'INFO', 'RLS on, no policy', c.relname,
         'Deny-by-default. Intentional, or a table someone forgot?'
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and c.relkind = 'r' and c.relrowsecurity
    and not exists (select 1 from pg_policies p
                     where p.schemaname='public' and p.tablename=c.relname)
),
anon_secdef as (
  select 'CRITICAL', 'SECURITY DEFINER callable by anon', p.proname,
         'Bypasses RLS. Anyone with the public key can call it.'
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname='public' and p.prosecdef
    and has_function_privilege('anon', p.oid, 'EXECUTE')
),
authed_secdef as (
  select 'REVIEW', 'SECURITY DEFINER callable by authenticated', p.proname,
         'Part of your API surface. Confirm it should be.'
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname='public' and p.prosecdef
    and p.prorettype::regtype::text <> 'trigger'
    and has_function_privilege('authenticated', p.oid, 'EXECUTE')
    and not has_function_privilege('anon', p.oid, 'EXECUTE')
),
trigger_fn_exec as (
  select 'LOW', 'trigger function directly callable', p.proname,
         'Triggers fire regardless. Direct execute is an unintended path.'
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname='public'
    and p.prorettype::regtype::text = 'trigger'
    and (has_function_privilege('anon', p.oid, 'EXECUTE')
      or has_function_privilege('authenticated', p.oid, 'EXECUTE'))
),
mutable_path as (
  select 'MEDIUM', 'function without pinned search_path', p.proname,
         'A caller can shadow public and change what this function reads.'
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname='public' and p.prosecdef
    and not exists (
      select 1 from unnest(coalesce(p.proconfig,'{}')) cfg
       where cfg like 'search_path=%'
    )
),
ext_in_public as (
  select 'LOW', 'extension in public schema', e.extname,
         'Consider a dedicated schema to avoid namespace collisions.'
  from pg_extension e
  join pg_namespace n on n.oid = e.extnamespace
  where n.nspname = 'public' and e.extname not in ('plpgsql')
)
select * from tables_no_rls
union all select * from anon_secdef
union all select * from mutable_path
union all select * from authed_secdef
union all select * from trigger_fn_exec
union all select * from ext_in_public
union all select * from rls_no_policy
order by case severity
  when 'CRITICAL' then 1 when 'MEDIUM' then 2
  when 'REVIEW'  then 3 when 'LOW'    then 4 else 5 end,
  finding, object;
