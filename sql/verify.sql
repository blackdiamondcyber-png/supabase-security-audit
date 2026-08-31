-- Run after remediation. Every number here should be zero except the last two.
select
  (select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace
    where n.nspname='public' and c.relkind='r' and not c.relrowsecurity)      as tables_without_rls,
  (select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.prosecdef
      and has_function_privilege('anon', p.oid,'EXECUTE'))                    as anon_callable_secdef,
  (select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.prosecdef
      and not exists (select 1 from unnest(coalesce(p.proconfig,'{}')) cfg
                       where cfg like 'search_path=%'))                       as unpinned_search_path,
  (select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.prorettype::regtype::text='trigger'
      and (has_function_privilege('anon', p.oid,'EXECUTE')
        or has_function_privilege('authenticated', p.oid,'EXECUTE')))         as trigger_fns_callable,
  -- expected to be non-zero: this is your intended API surface
  (select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.prosecdef
      and p.prorettype::regtype::text <> 'trigger'
      and has_function_privilege('authenticated', p.oid,'EXECUTE'))           as authenticated_api_fns,
  (select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace
    where n.nspname='public' and c.relkind='r' and c.relrowsecurity)          as tables_with_rls;
