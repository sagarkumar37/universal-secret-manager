-- users and roles
CREATE TABLE users (
    email       text PRIMARY KEY CHECK (email = lower(email)),
    role        text NOT NULL CHECK (role IN ('viewer', 'editor', 'admin')),
    active      boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text,
    last_login  timestamptz
);

-- append-only audit log (never contains secret values)
CREATE TABLE audit_log (
    id            bigserial PRIMARY KEY,
    ts            timestamptz NOT NULL DEFAULT now(),
    actor         text NOT NULL,
    action        text NOT NULL,
    ok            boolean NOT NULL,
    vault         text,
    bundle        text,
    key           text,
    from_version  text,
    to_version    text,
    client_ip     text,
    detail        jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_ts_idx     ON audit_log (ts DESC);
CREATE INDEX audit_log_bundle_idx ON audit_log (bundle, ts DESC);
CREATE INDEX audit_log_actor_idx  ON audit_log (actor, ts DESC);
