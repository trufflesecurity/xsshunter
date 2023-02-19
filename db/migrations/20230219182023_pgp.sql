-- migrate:up

-- payload_fire_results table

ALTER TABLE IF EXISTS public.payload_fire_results
    ALTER COLUMN url DROP NOT NULL;

ALTER TABLE IF EXISTS public.payload_fire_results
    ALTER COLUMN ip_address DROP NOT NULL;

ALTER TABLE IF EXISTS public.payload_fire_results
    ALTER COLUMN referer DROP NOT NULL;

ALTER TABLE IF EXISTS public.payload_fire_results
    ALTER COLUMN user_agent DROP NOT NULL;

ALTER TABLE IF EXISTS public.payload_fire_results
    ALTER COLUMN cookies DROP NOT NULL;

ALTER TABLE IF EXISTS public.payload_fire_results
    ALTER COLUMN title DROP NOT NULL;

ALTER TABLE IF EXISTS public.payload_fire_results
    ALTER COLUMN origin DROP NOT NULL;

ALTER TABLE IF EXISTS public.payload_fire_results
    ALTER COLUMN was_iframe DROP NOT NULL;

ALTER TABLE IF EXISTS public.payload_fire_results
    ALTER COLUMN browser_timestamp DROP NOT NULL;

ALTER TABLE IF EXISTS public.payload_fire_results
    ADD COLUMN encrypted boolean NOT NULL DEFAULT false;

ALTER TABLE IF EXISTS public.payload_fire_results
    ADD COLUMN encrypted_data text;

ALTER TABLE IF EXISTS public.payload_fire_results
    ADD COLUMN public_key text;

-- users table

ALTER TABLE IF EXISTS public.users
    ADD COLUMN pgp_key text;


-- migrate:down

