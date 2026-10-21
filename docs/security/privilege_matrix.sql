-- Effective privilege matrix, computed from the live catalog (not from the
-- migration text). Run as a superuser in a migrated SERK database:
--   psql -At -f docs/security/privilege_matrix.sql
\pset footer off
\echo '## Tables: effective privileges per role (has_table_privilege / has_column_privilege)'
\echo
\echo '| table | serk_app (tenant logins) | serk_publisher (relay) | serk_scheduler (timers) | PUBLIC | RLS forced |'
\echo '|---|---|---|---|---|---|'
SELECT format('| %s | %s | %s | %s | %s | %s |', c.relname,
  (SELECT COALESCE(string_agg(p, ' '), '—') FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE']) p WHERE has_table_privilege('serk_app', c.oid, p))
    || COALESCE(' · UPDATE(' || (SELECT string_agg(a.attname, ',' ORDER BY a.attnum) FROM pg_attribute a
         WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped AND NOT has_table_privilege('serk_app', c.oid, 'UPDATE')
           AND has_column_privilege('serk_app', c.oid, a.attnum, 'UPDATE')) || ')', ''),
  (SELECT COALESCE(string_agg(p, ' '), '—') FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) p WHERE has_table_privilege('serk_publisher', c.oid, p))
    || COALESCE(' · UPDATE(' || (SELECT string_agg(a.attname, ',' ORDER BY a.attnum) FROM pg_attribute a
         WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped AND NOT has_table_privilege('serk_publisher', c.oid, 'UPDATE')
           AND has_column_privilege('serk_publisher', c.oid, a.attnum, 'UPDATE')) || ')', ''),
  (SELECT COALESCE(string_agg(p, ' '), '—') FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) p WHERE has_table_privilege('serk_scheduler', c.oid, p)),
  CASE WHEN EXISTS (SELECT 1 FROM aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) x WHERE x.grantee = 0) THEN 'yes' ELSE '—' END,
  CASE WHEN c.relforcerowsecurity THEN 'yes' WHEN c.relrowsecurity THEN 'enabled' ELSE 'no' END)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r'
ORDER BY c.relname;
\echo
\echo '## Functions callable by application roles (excluding trigger functions, which cannot be called directly)'
\echo
\echo '| function | security | serk_app | serk_publisher | serk_scheduler | PUBLIC |'
\echo '|---|---|---|---|---|---|'
SELECT format('| %s | %s | %s | %s | %s | %s |', p.oid::regprocedure,
  CASE WHEN p.prosecdef THEN '**DEFINER**' ELSE 'invoker' END,
  CASE WHEN has_function_privilege('serk_app', p.oid, 'EXECUTE') THEN 'EXECUTE' ELSE '—' END,
  CASE WHEN has_function_privilege('serk_publisher', p.oid, 'EXECUTE') THEN 'EXECUTE' ELSE '—' END,
  CASE WHEN has_function_privilege('serk_scheduler', p.oid, 'EXECUTE') THEN 'EXECUTE' ELSE '—' END,
  CASE WHEN EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) x WHERE x.grantee = 0 AND x.privilege_type = 'EXECUTE') THEN 'EXECUTE' ELSE '—' END)
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public' AND p.prorettype <> 'trigger'::regtype
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e') -- skip extension (pgcrypto) functions
ORDER BY p.prosecdef DESC, p.proname;
\echo
\echo '## SECURITY DEFINER functions: owner and pinned search_path'
\echo
\echo '| function | owner | search_path |'
\echo '|---|---|---|'
SELECT format('| %s | %s | %s |', p.oid::regprocedure, pg_get_userbyid(p.proowner), COALESCE(array_to_string(p.proconfig, ' '), '**NOT PINNED**'))
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public' AND p.prosecdef ORDER BY p.proname;
\echo
\echo '## Database-level privileges of PUBLIC'
\echo
SELECT format('- TEMPORARY for PUBLIC: %s; CREATE on schema public for PUBLIC: %s; advisory-lock functions EXECUTE for PUBLIC: %s',
  CASE WHEN EXISTS (SELECT 1 FROM pg_database d, aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) x WHERE d.datname = current_database() AND x.grantee = 0 AND x.privilege_type = 'TEMPORARY') THEN 'yes' ELSE 'no' END,
  CASE WHEN EXISTS (SELECT 1 FROM pg_namespace s, aclexplode(COALESCE(s.nspacl, acldefault('n', s.nspowner))) x WHERE s.nspname = 'public' AND x.grantee = 0 AND x.privilege_type = 'CREATE') THEN 'yes' ELSE 'no' END,
  CASE WHEN EXISTS (SELECT 1 FROM pg_proc p, aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) x WHERE p.proname = 'pg_advisory_lock' AND x.grantee = 0) THEN 'yes' ELSE 'no' END);
