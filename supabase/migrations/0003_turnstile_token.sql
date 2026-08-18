-- Bind each order to the CAPTCHA token that authorised it.
--
-- Run this once in the Supabase dashboard: SQL Editor -> New query -> Run.
-- It is idempotent, so re-running it is safe.
--
-- Cloudflare already enforces that a Turnstile token can only be redeemed once,
-- returning `timeout-or-duplicate` on a second attempt. This column is the
-- second layer: it makes replay impossible in our own data even if that
-- enforcement ever changes or a token is redeemed against a different endpoint.
--
-- Only the SHA-256 of the token is stored, never the token itself — it is a
-- bearer credential and there is no reason to keep it in readable form.

alter table public.orders
  add column if not exists turnstile_token_hash text;

-- One token, one order. Partial so the many rows written before CAPTCHA existed
-- (and any future row where verification was skipped because Cloudflare itself
-- was unreachable) do not all collide on NULL.
create unique index if not exists orders_turnstile_token_hash_key
  on public.orders (turnstile_token_hash)
  where turnstile_token_hash is not null;
