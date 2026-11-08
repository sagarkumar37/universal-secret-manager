-- least-privilege login role for the backend: audit log is insert/select only
SELECT format('CREATE ROLE usm_app LOGIN PASSWORD %L', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'usm_app') \gexec
ALTER ROLE usm_app PASSWORD :'app_password';

GRANT CONNECT ON DATABASE :"dbname" TO usm_app;
GRANT USAGE ON SCHEMA public TO usm_app;
GRANT SELECT, INSERT, UPDATE ON users TO usm_app;
GRANT SELECT, INSERT ON audit_log TO usm_app;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO usm_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM usm_app;
