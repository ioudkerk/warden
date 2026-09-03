--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA public;

--
-- Name: warden_set_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.warden_set_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

--
-- Name: FUNCTION warden_set_updated_at(); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.warden_set_updated_at() IS 'BEFORE UPDATE trigger: stamps updated_at with the transaction timestamp.';

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: action; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.action (
    id text NOT NULL,
    resource_type_id text NOT NULL,
    key public.citext NOT NULL,
    name text NOT NULL,
    implies text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT action_does_not_imply_itself CHECK ((NOT ((key)::text = ANY (implies)))),
    CONSTRAINT action_id_check CHECK ((id ~~ 'act\_%'::text)),
    CONSTRAINT action_key_has_no_separators CHECK (((key OPERATOR(public.!~) '[.:*[:space:]]'::public.citext) AND (length((key)::text) > 0)))
);

--
-- Name: app_enrollment; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.app_enrollment (
    tenant_id text NOT NULL,
    application_id text NOT NULL,
    enrolled_at timestamp with time zone DEFAULT now() NOT NULL,
    settings jsonb DEFAULT '{}'::jsonb NOT NULL
);

ALTER TABLE ONLY public.app_enrollment FORCE ROW LEVEL SECURITY;

--
-- Name: TABLE app_enrollment; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.app_enrollment IS 'A tenant using an application. Enrolling inherits the application''s role templates as a starting point (SPEC §6.1).';

--
-- Name: app_user; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.app_user (
    id text NOT NULL,
    tenant_id text NOT NULL,
    email public.citext NOT NULL,
    email_verified boolean DEFAULT false NOT NULL,
    display_name text,
    status text DEFAULT 'invited'::text NOT NULL,
    attributes jsonb DEFAULT '{}'::jsonb NOT NULL,
    mfa_enforced boolean DEFAULT false NOT NULL,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT app_user_id_check CHECK ((id ~~ 'usr\_%'::text)),
    CONSTRAINT app_user_status_valid CHECK ((status = ANY (ARRAY['invited'::text, 'active'::text, 'suspended'::text, 'deprovisioned'::text])))
);

ALTER TABLE ONLY public.app_user FORCE ROW LEVEL SECURITY;

--
-- Name: COLUMN app_user.status; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.app_user.status IS 'invited → active → suspended → deprovisioned (SPEC §7.6). Anything but active denies every decision.';

--
-- Name: application; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.application (
    id text NOT NULL,
    key public.citext NOT NULL,
    name text NOT NULL,
    manifest_version integer DEFAULT 0 NOT NULL,
    fail_mode text DEFAULT 'closed'::text NOT NULL,
    cache_mode text DEFAULT 'cached'::text NOT NULL,
    decision_log text DEFAULT 'denies'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT application_cache_mode_valid CHECK ((cache_mode = ANY (ARRAY['remote'::text, 'cached'::text, 'embedded'::text]))),
    CONSTRAINT application_decision_log_valid CHECK ((decision_log = ANY (ARRAY['off'::text, 'denies'::text, 'sampled'::text, 'all'::text]))),
    CONSTRAINT application_fail_mode_valid CHECK ((fail_mode = ANY (ARRAY['closed'::text, 'open_read'::text, 'stale'::text]))),
    CONSTRAINT application_id_check CHECK ((id ~~ 'app\_%'::text)),
    CONSTRAINT application_key_has_no_separators CHECK (((key OPERATOR(public.!~) '[.:*[:space:]]'::public.citext) AND (length((key)::text) > 0)))
);

--
-- Name: COLUMN application.fail_mode; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.application.fail_mode IS 'PDP unreachable behaviour: closed denies, open_read allows previously-allowed reads, stale serves expired cache entries (SPEC §10.6).';

--
-- Name: credential; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.credential (
    id text NOT NULL,
    user_id text NOT NULL,
    tenant_id text NOT NULL,
    type text NOT NULL,
    secret_hash text NOT NULL,
    params jsonb DEFAULT '{}'::jsonb NOT NULL,
    label text,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    CONSTRAINT credential_id_check CHECK ((id ~~ 'crd\_%'::text)),
    CONSTRAINT credential_type_valid CHECK ((type = ANY (ARRAY['password'::text, 'totp'::text, 'webauthn'::text, 'recovery_code'::text])))
);

ALTER TABLE ONLY public.credential FORCE ROW LEVEL SECURITY;

--
-- Name: denial; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.denial (
    id text NOT NULL,
    tenant_id text NOT NULL,
    subject_user_id text,
    subject_group_id text,
    permission_key public.citext NOT NULL,
    scope_kind text NOT NULL,
    scope_ref text NOT NULL,
    reason text NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT denial_exactly_one_subject CHECK ((num_nonnulls(subject_user_id, subject_group_id) = 1)),
    CONSTRAINT denial_id_check CHECK ((id ~~ 'den\_%'::text)),
    CONSTRAINT denial_permission_well_formed CHECK ((permission_key OPERATOR(public.~) '^[^.:[:space:]]+\.(\*|[^.:*[:space:]]+):(\*|[^.:*[:space:]]+)$'::public.citext)),
    CONSTRAINT denial_reason_check CHECK ((length(btrim(reason)) > 0)),
    CONSTRAINT denial_scope_kind_valid CHECK ((scope_kind = ANY (ARRAY['tenant'::text, 'application'::text, 'environment'::text, 'resource'::text, 'subtree'::text])))
);

ALTER TABLE ONLY public.denial FORCE ROW LEVEL SECURITY;

--
-- Name: environment; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.environment (
    id text NOT NULL,
    application_id text NOT NULL,
    name text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT environment_id_check CHECK ((id ~~ 'env\_%'::text)),
    CONSTRAINT environment_name_valid CHECK ((name = ANY (ARRAY['dev'::text, 'staging'::text, 'prod'::text])))
);

--
-- Name: TABLE environment; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.environment IS 'A slice of an application''s configuration. UI bindings are environment-scoped so a change is testable in staging and promoted (SPEC §11.3).';

--
-- Name: grant_; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.grant_ (
    id text NOT NULL,
    tenant_id text NOT NULL,
    subject_user_id text,
    subject_group_id text,
    role_id text NOT NULL,
    scope_kind text NOT NULL,
    scope_ref text NOT NULL,
    condition text,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_until timestamp with time zone,
    granted_by text,
    reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    seq bigint NOT NULL,
    CONSTRAINT grant__id_check CHECK ((id ~~ 'grn\_%'::text)),
    CONSTRAINT grant_exactly_one_subject CHECK ((num_nonnulls(subject_user_id, subject_group_id) = 1)),
    CONSTRAINT grant_scope_kind_valid CHECK ((scope_kind = ANY (ARRAY['tenant'::text, 'application'::text, 'environment'::text, 'resource'::text, 'subtree'::text]))),
    CONSTRAINT grant_window_ordered CHECK (((valid_until IS NULL) OR (valid_until > valid_from)))
);

ALTER TABLE ONLY public.grant_ FORCE ROW LEVEL SECURITY;

--
-- Name: grant__seq_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.grant_ ALTER COLUMN seq ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.grant__seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

--
-- Name: group_; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.group_ (
    id text NOT NULL,
    tenant_id text NOT NULL,
    key public.citext NOT NULL,
    name text NOT NULL,
    source text DEFAULT 'local'::text NOT NULL,
    connection_id text,
    attributes jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT group__id_check CHECK ((id ~~ 'grp\_%'::text)),
    CONSTRAINT group_connection_matches_source CHECK ((((source = 'local'::text) AND (connection_id IS NULL)) OR ((source = ANY (ARRAY['idp'::text, 'scim'::text])) AND (connection_id IS NOT NULL)))),
    CONSTRAINT group_source_valid CHECK ((source = ANY (ARRAY['local'::text, 'idp'::text, 'scim'::text])))
);

ALTER TABLE ONLY public.group_ FORCE ROW LEVEL SECURITY;

--
-- Name: group_member; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.group_member (
    group_id text NOT NULL,
    member_user_id text,
    member_group_id text,
    tenant_id text NOT NULL,
    source text DEFAULT 'local'::text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT group_member_exactly_one_member CHECK ((num_nonnulls(member_user_id, member_group_id) = 1)),
    CONSTRAINT group_member_no_self_nesting CHECK ((member_group_id IS DISTINCT FROM group_id)),
    CONSTRAINT group_member_source_valid CHECK ((source = ANY (ARRAY['local'::text, 'idp'::text, 'scim'::text])))
);

ALTER TABLE ONLY public.group_member FORCE ROW LEVEL SECURITY;

--
-- Name: identity; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity (
    id text NOT NULL,
    tenant_id text NOT NULL,
    user_id text NOT NULL,
    connection_id text NOT NULL,
    external_subject text NOT NULL,
    raw_claims jsonb DEFAULT '{}'::jsonb NOT NULL,
    linked_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT identity_id_check CHECK ((id ~~ 'idn\_%'::text))
);

ALTER TABLE ONLY public.identity FORCE ROW LEVEL SECURITY;

--
-- Name: idp_connection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.idp_connection (
    id text NOT NULL,
    tenant_id text NOT NULL,
    kind text NOT NULL,
    name text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    email_trusted boolean DEFAULT false NOT NULL,
    jit_policy text DEFAULT 'create'::text NOT NULL,
    domain_hints text[] DEFAULT '{}'::text[] NOT NULL,
    config jsonb NOT NULL,
    mapping jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT idp_connection_id_check CHECK ((id ~~ 'idp\_%'::text)),
    CONSTRAINT idp_connection_jit_policy_valid CHECK ((jit_policy = ANY (ARRAY['create'::text, 'link_only'::text, 'deny_unknown'::text]))),
    CONSTRAINT idp_connection_kind_valid CHECK ((kind = ANY (ARRAY['oidc'::text, 'saml'::text, 'local'::text])))
);

ALTER TABLE ONLY public.idp_connection FORCE ROW LEVEL SECURITY;

--
-- Name: COLUMN idp_connection.email_trusted; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.idp_connection.email_trusted IS 'Allows linking a federated login to a local account by email. A known account-takeover vector when the upstream IdP does not verify addresses (SPEC §7.4.1). Defaults to false.';

--
-- Name: permission; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.permission (
    id text NOT NULL,
    application_id text NOT NULL,
    key public.citext NOT NULL,
    resource_type_id text NOT NULL,
    action_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT permission_id_check CHECK ((id ~~ 'prm\_%'::text)),
    CONSTRAINT permission_key_well_formed CHECK ((key OPERATOR(public.~) '^[^.:*[:space:]]+\.[^.:*[:space:]]+:[^.:*[:space:]]+$'::public.citext))
);

--
-- Name: TABLE permission; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.permission IS 'The atom of authorization: app.resource:action. Materialized from resource_type × action at sync time (SPEC §9.2).';

--
-- Name: refresh_token; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_token (
    id text NOT NULL,
    session_id text NOT NULL,
    tenant_id text NOT NULL,
    family_id text NOT NULL,
    token_hash bytea NOT NULL,
    client_id text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    revoked_at timestamp with time zone,
    CONSTRAINT refresh_token_hash_is_sha256 CHECK ((octet_length(token_hash) = 32)),
    CONSTRAINT refresh_token_id_check CHECK ((id ~~ 'rft\_%'::text))
);

ALTER TABLE ONLY public.refresh_token FORCE ROW LEVEL SECURITY;

--
-- Name: resource_node; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resource_node (
    tenant_id text NOT NULL,
    ref text NOT NULL,
    resource_type_id text,
    parent_ref text,
    attributes jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT resource_node_not_its_own_parent CHECK ((parent_ref IS DISTINCT FROM ref))
);

ALTER TABLE ONLY public.resource_node FORCE ROW LEVEL SECURITY;

--
-- Name: resource_type; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resource_type (
    id text NOT NULL,
    application_id text NOT NULL,
    key public.citext NOT NULL,
    name text NOT NULL,
    parent_type_id text,
    attribute_schema jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT resource_type_id_check CHECK ((id ~~ 'rst\_%'::text)),
    CONSTRAINT resource_type_key_has_no_separators CHECK (((key OPERATOR(public.!~) '[.:*[:space:]]'::public.citext) AND (length((key)::text) > 0))),
    CONSTRAINT resource_type_not_own_parent CHECK ((parent_type_id IS DISTINCT FROM id))
);

--
-- Name: role; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role (
    id text NOT NULL,
    tenant_id text,
    application_id text,
    key public.citext NOT NULL,
    name text NOT NULL,
    description text,
    type text NOT NULL,
    forked_from text,
    template_version integer,
    constraints jsonb DEFAULT '{}'::jsonb NOT NULL,
    assignable_by text[] DEFAULT '{}'::text[] NOT NULL,
    immutable boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT role_id_check CHECK ((id ~~ 'rol\_%'::text)),
    CONSTRAINT role_not_its_own_fork CHECK ((forked_from IS DISTINCT FROM id)),
    CONSTRAINT role_scope_matches_type CHECK ((((type = 'tenant_custom'::text) AND (tenant_id IS NOT NULL)) OR ((type = ANY (ARRAY['system'::text, 'application_template'::text])) AND (tenant_id IS NULL)))),
    CONSTRAINT role_type_valid CHECK ((type = ANY (ARRAY['system'::text, 'application_template'::text, 'tenant_custom'::text])))
);

ALTER TABLE ONLY public.role FORCE ROW LEVEL SECURITY;

--
-- Name: COLUMN role.tenant_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.role.tenant_id IS 'NULL for an application template or system role, which every tenant can read but none can modify.';

--
-- Name: role_inheritance; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_inheritance (
    role_id text NOT NULL,
    parent_role_id text NOT NULL,
    tenant_id text,
    CONSTRAINT role_inheritance_no_self_reference CHECK ((role_id <> parent_role_id))
);

ALTER TABLE ONLY public.role_inheritance FORCE ROW LEVEL SECURITY;

--
-- Name: role_permission; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_permission (
    role_id text NOT NULL,
    tenant_id text,
    permission_key public.citext NOT NULL,
    condition text,
    CONSTRAINT role_permission_well_formed CHECK ((permission_key OPERATOR(public.~) '^[^.:[:space:]]+\.(\*|[^.:*[:space:]]+):(\*|[^.:*[:space:]]+)$'::public.citext))
);

ALTER TABLE ONLY public.role_permission FORCE ROW LEVEL SECURITY;

--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version bigint NOT NULL,
    dirty boolean NOT NULL
);

--
-- Name: service_account; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.service_account (
    id text NOT NULL,
    tenant_id text NOT NULL,
    name text NOT NULL,
    token_hash bytea NOT NULL,
    application_id text,
    disabled_at timestamp with time zone,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT service_account_hash_is_sha256 CHECK ((octet_length(token_hash) = 32)),
    CONSTRAINT service_account_id_check CHECK ((id ~~ 'svc\_%'::text))
);

--
-- Name: session; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.session (
    id text NOT NULL,
    tenant_id text NOT NULL,
    user_id text NOT NULL,
    amr text[] DEFAULT '{}'::text[] NOT NULL,
    auth_time timestamp with time zone NOT NULL,
    ip inet,
    user_agent text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT session_id_check CHECK ((id ~~ 'ses\_%'::text))
);

ALTER TABLE ONLY public.session FORCE ROW LEVEL SECURITY;

--
-- Name: TABLE session; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.session IS 'The browser-level SSO artifact (sid). Survives token refresh; the target of "log out everywhere". Mirrored from Redis for the active-sessions UI (SPEC §8.3).';

--
-- Name: tenant; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant (
    id text NOT NULL,
    slug public.citext NOT NULL,
    name text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    settings jsonb DEFAULT '{}'::jsonb NOT NULL,
    permission_rev bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT tenant_id_check CHECK ((id ~~ 'ten\_%'::text)),
    CONSTRAINT tenant_status_valid CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text, 'deleted'::text])))
);

ALTER TABLE ONLY public.tenant FORCE ROW LEVEL SECURITY;

--
-- Name: TABLE tenant; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.tenant IS 'An isolated customer space. The isolation boundary for users, roles and assignments (SPEC §6).';

--
-- Name: COLUMN tenant.permission_rev; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.tenant.permission_rev IS 'Incremented on every authorization-affecting write; the consistency token (SPEC §10.5).';

--
-- Name: tenant_isolation_registry; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_isolation_registry (
    table_name text NOT NULL,
    tenant_scoped boolean NOT NULL,
    rationale text,
    CONSTRAINT tenant_isolation_registry_global_needs_rationale CHECK ((tenant_scoped OR (rationale IS NOT NULL)))
);

--
-- Name: TABLE tenant_isolation_registry; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.tenant_isolation_registry IS 'Declares, per table, whether it holds tenant-scoped data. The isolation test in internal/store cross-checks this against pg_class, so a new table cannot silently escape row-level security.';

--
-- Name: action action_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action
    ADD CONSTRAINT action_pkey PRIMARY KEY (id);

--
-- Name: app_enrollment app_enrollment_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_enrollment
    ADD CONSTRAINT app_enrollment_pkey PRIMARY KEY (tenant_id, application_id);

--
-- Name: app_user app_user_id_tenant_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_user
    ADD CONSTRAINT app_user_id_tenant_key UNIQUE (id, tenant_id);

--
-- Name: app_user app_user_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_user
    ADD CONSTRAINT app_user_pkey PRIMARY KEY (id);

--
-- Name: application application_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.application
    ADD CONSTRAINT application_pkey PRIMARY KEY (id);

--
-- Name: credential credential_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT credential_pkey PRIMARY KEY (id);

--
-- Name: denial denial_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.denial
    ADD CONSTRAINT denial_pkey PRIMARY KEY (id);

--
-- Name: environment environment_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment
    ADD CONSTRAINT environment_pkey PRIMARY KEY (id);

--
-- Name: grant_ grant__pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.grant_
    ADD CONSTRAINT grant__pkey PRIMARY KEY (id);

--
-- Name: group_ group__pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_
    ADD CONSTRAINT group__pkey PRIMARY KEY (id);

--
-- Name: group_ group_id_tenant_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_
    ADD CONSTRAINT group_id_tenant_key UNIQUE (id, tenant_id);

--
-- Name: identity identity_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity
    ADD CONSTRAINT identity_pkey PRIMARY KEY (id);

--
-- Name: idp_connection idp_connection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idp_connection
    ADD CONSTRAINT idp_connection_pkey PRIMARY KEY (id);

--
-- Name: permission permission_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permission
    ADD CONSTRAINT permission_pkey PRIMARY KEY (id);

--
-- Name: refresh_token refresh_token_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_token
    ADD CONSTRAINT refresh_token_pkey PRIMARY KEY (id);

--
-- Name: resource_node resource_node_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_node
    ADD CONSTRAINT resource_node_pkey PRIMARY KEY (tenant_id, ref);

--
-- Name: resource_type resource_type_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_type
    ADD CONSTRAINT resource_type_pkey PRIMARY KEY (id);

--
-- Name: role role_id_tenant_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_id_tenant_key UNIQUE (id, tenant_id);

--
-- Name: role_inheritance role_inheritance_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_inheritance
    ADD CONSTRAINT role_inheritance_pkey PRIMARY KEY (role_id, parent_role_id);

--
-- Name: role_permission role_permission_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permission
    ADD CONSTRAINT role_permission_pkey PRIMARY KEY (role_id, permission_key);

--
-- Name: role role_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_pkey PRIMARY KEY (id);

--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);

--
-- Name: service_account service_account_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_account
    ADD CONSTRAINT service_account_pkey PRIMARY KEY (id);

--
-- Name: session session_id_tenant_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session
    ADD CONSTRAINT session_id_tenant_key UNIQUE (id, tenant_id);

--
-- Name: session session_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session
    ADD CONSTRAINT session_pkey PRIMARY KEY (id);

--
-- Name: tenant_isolation_registry tenant_isolation_registry_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_isolation_registry
    ADD CONSTRAINT tenant_isolation_registry_pkey PRIMARY KEY (table_name);

--
-- Name: tenant tenant_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant
    ADD CONSTRAINT tenant_pkey PRIMARY KEY (id);

--
-- Name: action_resource_type_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX action_resource_type_key_key ON public.action USING btree (resource_type_id, key);

--
-- Name: app_enrollment_application_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX app_enrollment_application_idx ON public.app_enrollment USING btree (application_id);

--
-- Name: app_user_attributes_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX app_user_attributes_idx ON public.app_user USING gin (attributes jsonb_path_ops);

--
-- Name: app_user_tenant_email_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX app_user_tenant_email_key ON public.app_user USING btree (tenant_id, email);

--
-- Name: app_user_tenant_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX app_user_tenant_id_idx ON public.app_user USING btree (tenant_id);

--
-- Name: application_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX application_key_key ON public.application USING btree (key);

--
-- Name: credential_one_password_per_user; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX credential_one_password_per_user ON public.credential USING btree (user_id) WHERE (type = 'password'::text);

--
-- Name: credential_tenant_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX credential_tenant_id_idx ON public.credential USING btree (tenant_id);

--
-- Name: credential_user_id_type_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX credential_user_id_type_idx ON public.credential USING btree (user_id, type);

--
-- Name: denial_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX denial_tenant_idx ON public.denial USING btree (tenant_id);

--
-- Name: environment_application_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX environment_application_name_key ON public.environment USING btree (application_id, name);

--
-- Name: grant_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX grant_expiry_idx ON public.grant_ USING btree (valid_until) WHERE (valid_until IS NOT NULL);

--
-- Name: grant_tenant_group_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX grant_tenant_group_idx ON public.grant_ USING btree (tenant_id, subject_group_id) WHERE (subject_group_id IS NOT NULL);

--
-- Name: grant_tenant_scope_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX grant_tenant_scope_idx ON public.grant_ USING btree (tenant_id, scope_ref);

--
-- Name: grant_tenant_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX grant_tenant_user_idx ON public.grant_ USING btree (tenant_id, subject_user_id) WHERE (subject_user_id IS NOT NULL);

--
-- Name: group_connection_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX group_connection_idx ON public.group_ USING btree (connection_id) WHERE (connection_id IS NOT NULL);

--
-- Name: group_member_by_group_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX group_member_by_group_idx ON public.group_member USING btree (member_group_id) WHERE (member_group_id IS NOT NULL);

--
-- Name: group_member_by_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX group_member_by_user_idx ON public.group_member USING btree (member_user_id) WHERE (member_user_id IS NOT NULL);

--
-- Name: group_member_group_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX group_member_group_key ON public.group_member USING btree (group_id, member_group_id) WHERE (member_group_id IS NOT NULL);

--
-- Name: group_member_tenant_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX group_member_tenant_id_idx ON public.group_member USING btree (tenant_id);

--
-- Name: group_member_user_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX group_member_user_key ON public.group_member USING btree (group_id, member_user_id) WHERE (member_user_id IS NOT NULL);

--
-- Name: group_tenant_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX group_tenant_id_idx ON public.group_ USING btree (tenant_id);

--
-- Name: group_tenant_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX group_tenant_key_key ON public.group_ USING btree (tenant_id, key);

--
-- Name: identity_connection_subject_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX identity_connection_subject_key ON public.identity USING btree (connection_id, external_subject);

--
-- Name: identity_tenant_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_tenant_id_idx ON public.identity USING btree (tenant_id);

--
-- Name: identity_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_user_id_idx ON public.identity USING btree (user_id);

--
-- Name: idp_connection_tenant_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idp_connection_tenant_id_idx ON public.idp_connection USING btree (tenant_id);

--
-- Name: idp_connection_tenant_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idp_connection_tenant_name_key ON public.idp_connection USING btree (tenant_id, name);

--
-- Name: permission_application_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX permission_application_key_key ON public.permission USING btree (application_id, key);

--
-- Name: permission_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX permission_key_key ON public.permission USING btree (key);

--
-- Name: permission_resource_action_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX permission_resource_action_key ON public.permission USING btree (resource_type_id, action_id);

--
-- Name: refresh_token_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX refresh_token_expires_at_idx ON public.refresh_token USING btree (expires_at) WHERE ((revoked_at IS NULL) AND (consumed_at IS NULL));

--
-- Name: refresh_token_family_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX refresh_token_family_idx ON public.refresh_token USING btree (family_id);

--
-- Name: refresh_token_hash_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX refresh_token_hash_key ON public.refresh_token USING btree (token_hash);

--
-- Name: refresh_token_session_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX refresh_token_session_idx ON public.refresh_token USING btree (session_id);

--
-- Name: refresh_token_tenant_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX refresh_token_tenant_id_idx ON public.refresh_token USING btree (tenant_id);

--
-- Name: resource_node_attributes_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX resource_node_attributes_idx ON public.resource_node USING gin (attributes jsonb_path_ops);

--
-- Name: resource_node_parent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX resource_node_parent_idx ON public.resource_node USING btree (tenant_id, parent_ref) WHERE (parent_ref IS NOT NULL);

--
-- Name: resource_type_application_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX resource_type_application_key_key ON public.resource_type USING btree (application_id, key);

--
-- Name: resource_type_parent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX resource_type_parent_idx ON public.resource_type USING btree (parent_type_id) WHERE (parent_type_id IS NOT NULL);

--
-- Name: role_application_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX role_application_id_idx ON public.role USING btree (application_id);

--
-- Name: role_inheritance_parent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX role_inheritance_parent_idx ON public.role_inheritance USING btree (parent_role_id);

--
-- Name: role_inheritance_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX role_inheritance_tenant_idx ON public.role_inheritance USING btree (tenant_id);

--
-- Name: role_owner_key_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX role_owner_key_key ON public.role USING btree (tenant_id, application_id, key) NULLS NOT DISTINCT;

--
-- Name: role_permission_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX role_permission_tenant_idx ON public.role_permission USING btree (tenant_id);

--
-- Name: role_tenant_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX role_tenant_id_idx ON public.role USING btree (tenant_id);

--
-- Name: service_account_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX service_account_tenant_idx ON public.service_account USING btree (tenant_id);

--
-- Name: service_account_tenant_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX service_account_tenant_name_key ON public.service_account USING btree (tenant_id, name);

--
-- Name: service_account_token_hash_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX service_account_token_hash_key ON public.service_account USING btree (token_hash);

--
-- Name: session_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX session_expires_at_idx ON public.session USING btree (expires_at) WHERE (revoked_at IS NULL);

--
-- Name: session_tenant_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX session_tenant_id_idx ON public.session USING btree (tenant_id);

--
-- Name: session_user_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX session_user_active_idx ON public.session USING btree (user_id) WHERE (revoked_at IS NULL);

--
-- Name: tenant_slug_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX tenant_slug_key ON public.tenant USING btree (slug);

--
-- Name: app_user app_user_set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER app_user_set_updated_at BEFORE UPDATE ON public.app_user FOR EACH ROW EXECUTE FUNCTION public.warden_set_updated_at();

--
-- Name: application application_set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER application_set_updated_at BEFORE UPDATE ON public.application FOR EACH ROW EXECUTE FUNCTION public.warden_set_updated_at();

--
-- Name: group_ group_set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER group_set_updated_at BEFORE UPDATE ON public.group_ FOR EACH ROW EXECUTE FUNCTION public.warden_set_updated_at();

--
-- Name: resource_node resource_node_set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER resource_node_set_updated_at BEFORE UPDATE ON public.resource_node FOR EACH ROW EXECUTE FUNCTION public.warden_set_updated_at();

--
-- Name: resource_type resource_type_set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER resource_type_set_updated_at BEFORE UPDATE ON public.resource_type FOR EACH ROW EXECUTE FUNCTION public.warden_set_updated_at();

--
-- Name: role role_set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER role_set_updated_at BEFORE UPDATE ON public.role FOR EACH ROW EXECUTE FUNCTION public.warden_set_updated_at();

--
-- Name: tenant tenant_set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER tenant_set_updated_at BEFORE UPDATE ON public.tenant FOR EACH ROW EXECUTE FUNCTION public.warden_set_updated_at();

--
-- Name: action action_resource_type_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action
    ADD CONSTRAINT action_resource_type_id_fkey FOREIGN KEY (resource_type_id) REFERENCES public.resource_type(id) ON DELETE CASCADE;

--
-- Name: app_enrollment app_enrollment_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_enrollment
    ADD CONSTRAINT app_enrollment_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.application(id);

--
-- Name: app_enrollment app_enrollment_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_enrollment
    ADD CONSTRAINT app_enrollment_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: app_user app_user_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_user
    ADD CONSTRAINT app_user_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: credential credential_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT credential_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: credential credential_user_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT credential_user_fkey FOREIGN KEY (user_id, tenant_id) REFERENCES public.app_user(id, tenant_id) ON DELETE CASCADE;

--
-- Name: denial denial_group_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.denial
    ADD CONSTRAINT denial_group_fkey FOREIGN KEY (subject_group_id, tenant_id) REFERENCES public.group_(id, tenant_id) ON DELETE CASCADE;

--
-- Name: denial denial_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.denial
    ADD CONSTRAINT denial_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: denial denial_user_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.denial
    ADD CONSTRAINT denial_user_fkey FOREIGN KEY (subject_user_id, tenant_id) REFERENCES public.app_user(id, tenant_id) ON DELETE CASCADE;

--
-- Name: environment environment_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.environment
    ADD CONSTRAINT environment_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.application(id) ON DELETE CASCADE;

--
-- Name: grant_ grant__tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.grant_
    ADD CONSTRAINT grant__tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: grant_ grant_group_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.grant_
    ADD CONSTRAINT grant_group_fkey FOREIGN KEY (subject_group_id, tenant_id) REFERENCES public.group_(id, tenant_id) ON DELETE CASCADE;

--
-- Name: grant_ grant_role_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.grant_
    ADD CONSTRAINT grant_role_fkey FOREIGN KEY (role_id) REFERENCES public.role(id) ON DELETE CASCADE;

--
-- Name: grant_ grant_user_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.grant_
    ADD CONSTRAINT grant_user_fkey FOREIGN KEY (subject_user_id, tenant_id) REFERENCES public.app_user(id, tenant_id) ON DELETE CASCADE;

--
-- Name: group_ group__connection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_
    ADD CONSTRAINT group__connection_id_fkey FOREIGN KEY (connection_id) REFERENCES public.idp_connection(id);

--
-- Name: group_ group__tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_
    ADD CONSTRAINT group__tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: group_member group_member_group_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_member
    ADD CONSTRAINT group_member_group_fkey FOREIGN KEY (group_id, tenant_id) REFERENCES public.group_(id, tenant_id) ON DELETE CASCADE;

--
-- Name: group_member group_member_nested_group_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_member
    ADD CONSTRAINT group_member_nested_group_fkey FOREIGN KEY (member_group_id, tenant_id) REFERENCES public.group_(id, tenant_id) ON DELETE CASCADE;

--
-- Name: group_member group_member_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_member
    ADD CONSTRAINT group_member_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: group_member group_member_user_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_member
    ADD CONSTRAINT group_member_user_fkey FOREIGN KEY (member_user_id, tenant_id) REFERENCES public.app_user(id, tenant_id) ON DELETE CASCADE;

--
-- Name: identity identity_connection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity
    ADD CONSTRAINT identity_connection_id_fkey FOREIGN KEY (connection_id) REFERENCES public.idp_connection(id);

--
-- Name: identity identity_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity
    ADD CONSTRAINT identity_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: identity identity_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity
    ADD CONSTRAINT identity_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.app_user(id) ON DELETE CASCADE;

--
-- Name: idp_connection idp_connection_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idp_connection
    ADD CONSTRAINT idp_connection_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: permission permission_action_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permission
    ADD CONSTRAINT permission_action_id_fkey FOREIGN KEY (action_id) REFERENCES public.action(id) ON DELETE CASCADE;

--
-- Name: permission permission_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permission
    ADD CONSTRAINT permission_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.application(id) ON DELETE CASCADE;

--
-- Name: permission permission_resource_type_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.permission
    ADD CONSTRAINT permission_resource_type_id_fkey FOREIGN KEY (resource_type_id) REFERENCES public.resource_type(id) ON DELETE CASCADE;

--
-- Name: refresh_token refresh_token_session_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_token
    ADD CONSTRAINT refresh_token_session_fkey FOREIGN KEY (session_id, tenant_id) REFERENCES public.session(id, tenant_id) ON DELETE CASCADE;

--
-- Name: refresh_token refresh_token_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_token
    ADD CONSTRAINT refresh_token_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: resource_node resource_node_parent_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_node
    ADD CONSTRAINT resource_node_parent_fkey FOREIGN KEY (tenant_id, parent_ref) REFERENCES public.resource_node(tenant_id, ref) ON DELETE SET NULL (parent_ref);

--
-- Name: resource_node resource_node_resource_type_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_node
    ADD CONSTRAINT resource_node_resource_type_id_fkey FOREIGN KEY (resource_type_id) REFERENCES public.resource_type(id);

--
-- Name: resource_node resource_node_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_node
    ADD CONSTRAINT resource_node_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: resource_type resource_type_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_type
    ADD CONSTRAINT resource_type_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.application(id) ON DELETE CASCADE;

--
-- Name: resource_type resource_type_parent_type_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_type
    ADD CONSTRAINT resource_type_parent_type_id_fkey FOREIGN KEY (parent_type_id) REFERENCES public.resource_type(id);

--
-- Name: role role_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.application(id) ON DELETE CASCADE;

--
-- Name: role role_forked_from_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_forked_from_fkey FOREIGN KEY (forked_from) REFERENCES public.role(id);

--
-- Name: role_inheritance role_inheritance_role_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_inheritance
    ADD CONSTRAINT role_inheritance_role_fkey FOREIGN KEY (role_id, tenant_id) REFERENCES public.role(id, tenant_id) ON DELETE CASCADE;

--
-- Name: role_inheritance role_inheritance_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_inheritance
    ADD CONSTRAINT role_inheritance_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: role_permission role_permission_role_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permission
    ADD CONSTRAINT role_permission_role_fkey FOREIGN KEY (role_id, tenant_id) REFERENCES public.role(id, tenant_id) ON DELETE CASCADE;

--
-- Name: role_permission role_permission_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_permission
    ADD CONSTRAINT role_permission_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: role role_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: service_account service_account_application_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_account
    ADD CONSTRAINT service_account_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.application(id) ON DELETE CASCADE;

--
-- Name: service_account service_account_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_account
    ADD CONSTRAINT service_account_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: session session_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session
    ADD CONSTRAINT session_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenant(id);

--
-- Name: session session_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session
    ADD CONSTRAINT session_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.app_user(id) ON DELETE CASCADE;

--
-- Name: app_enrollment; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.app_enrollment ENABLE ROW LEVEL SECURITY;

--
-- Name: app_user; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.app_user ENABLE ROW LEVEL SECURITY;

--
-- Name: credential; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.credential ENABLE ROW LEVEL SECURITY;

--
-- Name: denial; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.denial ENABLE ROW LEVEL SECURITY;

--
-- Name: grant_; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.grant_ ENABLE ROW LEVEL SECURITY;

--
-- Name: group_; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.group_ ENABLE ROW LEVEL SECURITY;

--
-- Name: group_member; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.group_member ENABLE ROW LEVEL SECURITY;

--
-- Name: identity; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.identity ENABLE ROW LEVEL SECURITY;

--
-- Name: idp_connection; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.idp_connection ENABLE ROW LEVEL SECURITY;

--
-- Name: refresh_token; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.refresh_token ENABLE ROW LEVEL SECURITY;

--
-- Name: resource_node; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.resource_node ENABLE ROW LEVEL SECURITY;

--
-- Name: role; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.role ENABLE ROW LEVEL SECURITY;

--
-- Name: role_inheritance; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.role_inheritance ENABLE ROW LEVEL SECURITY;

--
-- Name: role_permission; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.role_permission ENABLE ROW LEVEL SECURITY;

--
-- Name: session; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.session ENABLE ROW LEVEL SECURITY;

--
-- Name: tenant; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenant ENABLE ROW LEVEL SECURITY;

--
-- Name: app_enrollment tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.app_enrollment USING ((tenant_id = current_setting('warden.tenant_id'::text, true))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: app_user tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.app_user USING ((tenant_id = current_setting('warden.tenant_id'::text, true))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: credential tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.credential USING ((tenant_id = current_setting('warden.tenant_id'::text, true))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: denial tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.denial USING ((tenant_id = current_setting('warden.tenant_id'::text, true))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: grant_ tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.grant_ USING ((tenant_id = current_setting('warden.tenant_id'::text, true))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: group_ tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.group_ USING ((tenant_id = current_setting('warden.tenant_id'::text, true))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: group_member tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.group_member USING ((tenant_id = current_setting('warden.tenant_id'::text, true))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: identity tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.identity USING ((tenant_id = current_setting('warden.tenant_id'::text, true))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: idp_connection tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.idp_connection USING ((tenant_id = current_setting('warden.tenant_id'::text, true))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: refresh_token tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.refresh_token USING ((tenant_id = current_setting('warden.tenant_id'::text, true))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: resource_node tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.resource_node USING ((tenant_id = current_setting('warden.tenant_id'::text, true))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: role tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.role USING (((tenant_id IS NULL) OR (tenant_id = current_setting('warden.tenant_id'::text, true)))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: role_inheritance tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.role_inheritance USING (((tenant_id IS NULL) OR (tenant_id = current_setting('warden.tenant_id'::text, true)))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: role_permission tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.role_permission USING (((tenant_id IS NULL) OR (tenant_id = current_setting('warden.tenant_id'::text, true)))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: session tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.session USING ((tenant_id = current_setting('warden.tenant_id'::text, true))) WITH CHECK ((tenant_id = current_setting('warden.tenant_id'::text, true)));

--
-- Name: tenant tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.tenant USING ((id = current_setting('warden.tenant_id'::text, true))) WITH CHECK ((id = current_setting('warden.tenant_id'::text, true)));

--
-- PostgreSQL database dump complete
--

