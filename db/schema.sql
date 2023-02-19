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

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: collected_pages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collected_pages (
    id uuid NOT NULL,
    uri text NOT NULL,
    html text,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);


--
-- Name: injection_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.injection_requests (
    id uuid NOT NULL,
    request text NOT NULL,
    injection_key text NOT NULL,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);


--
-- Name: payload_fire_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payload_fire_results (
    id uuid NOT NULL,
    url text,
    user_id text NOT NULL,
    ip_address text,
    referer text,
    user_agent text,
    cookies text,
    title text,
    origin text,
    screenshot_id text,
    was_iframe boolean,
    browser_timestamp bigint,
    "gitExposed" text,
    "CORS" text,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL,
    encrypted boolean DEFAULT false NOT NULL,
    encrypted_data text,
    public_key text
);


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version character varying(255) NOT NULL
);


--
-- Name: secrets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secrets (
    id uuid NOT NULL,
    payload_id text NOT NULL,
    secret_type text NOT NULL,
    secret_value text,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid NOT NULL,
    email text NOT NULL,
    path text,
    "injectionCorrelationAPIKey" text,
    "additionalJS" text,
    "sendEmailAlerts" boolean DEFAULT true,
    "createdAt" timestamp with time zone NOT NULL,
    "updatedAt" timestamp with time zone NOT NULL,
    pgp_key text
);


--
-- Name: collected_pages collected_pages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collected_pages
    ADD CONSTRAINT collected_pages_pkey PRIMARY KEY (id);


--
-- Name: injection_requests injection_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.injection_requests
    ADD CONSTRAINT injection_requests_pkey PRIMARY KEY (id);


--
-- Name: payload_fire_results payload_fire_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payload_fire_results
    ADD CONSTRAINT payload_fire_results_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: secrets secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_pkey PRIMARY KEY (id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_injectionCorrelationAPIKey_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT "users_injectionCorrelationAPIKey_key" UNIQUE ("injectionCorrelationAPIKey");


--
-- Name: users users_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_path_key UNIQUE (path);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: injection_requests_injection_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX injection_requests_injection_key ON public.injection_requests USING btree (injection_key);


--
-- Name: payload_fire_results_browser_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_fire_results_browser_timestamp ON public.payload_fire_results USING btree (browser_timestamp);


--
-- Name: payload_fire_results_ip_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_fire_results_ip_address ON public.payload_fire_results USING btree (ip_address);


--
-- Name: payload_fire_results_origin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_fire_results_origin ON public.payload_fire_results USING btree (origin);


--
-- Name: payload_fire_results_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_fire_results_user_id ON public.payload_fire_results USING btree (user_id);


--
-- Name: payload_fire_results_was_iframe; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX payload_fire_results_was_iframe ON public.payload_fire_results USING btree (was_iframe);


--
-- Name: secrets_secret_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX secrets_secret_type ON public.secrets USING btree (secret_type);


--
-- Name: users_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_email ON public.users USING btree (email);


--
-- Name: users_path; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_path ON public.users USING btree (path);


--
-- PostgreSQL database dump complete
--


--
-- Dbmate schema migrations
--

INSERT INTO public.schema_migrations (version) VALUES
    ('20230219182023');
