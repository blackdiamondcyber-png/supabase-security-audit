-- Generates remediation statements. Review the output, then run what you agree with.
-- This script itself changes nothing.

-- 1. Revoke public execute on SECURITY DEFINER functions reachable by anon.
select 'revoke execute on function public.' || p.oid::regprocedure::text
       || ' from anon, authenticated;' as statement
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname='public' and p.prosecdef
  and has_function_privilege('anon', p.oid, 'EXECUTE')
  -- exclude anything you have deliberately exposed
  and p.proname not in ('signup_lookup')

union all

-- 2. Trigger functions never need direct execute.
select 'revoke execute on function public.' || p.oid::regprocedure::text
       || ' from anon, authenticated;'
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname='public'
  and p.prorettype::regtype::text = 'trigger'
  and (has_function_privilege('anon', p.oid, 'EXECUTE')
    or has_function_privilege('authenticated', p.oid, 'EXECUTE'))

union all

-- 3. Pin search_path on SECURITY DEFINER functions that lack it.
select 'alter function public.' || p.oid::regprocedure::text
       || ' set search_path = public;'
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname='public' and p.prosecdef
  and not exists (
    select 1 from unnest(coalesce(p.proconfig,'{}')) cfg
     where cfg like 'search_path=%'
  )

union all

-- 4. Enable RLS on any table missing it.
select 'alter table public.' || quote_ident(c.relname) || ' enable row level security;'
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname='public' and c.relkind='r' and not c.relrowsecurity;
