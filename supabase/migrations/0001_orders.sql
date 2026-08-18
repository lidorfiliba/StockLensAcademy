-- orders — durable record of every submitted purchase
--
-- Run this once in the Supabase dashboard: SQL Editor -> New query -> Run.
-- It is idempotent, so re-running it is safe.
--
-- Until now an order existed only as an EmailJS message. This table is the
-- backup: if the mail fails or lands in spam, the order is still here.
--
-- Written to exclusively by the `log-order` Edge Function using the
-- service_role key. Nothing else should ever write to it.

create table if not exists public.orders (
  id             uuid primary key default gen_random_uuid(),

  -- The join key. Same value as the EmailJS message, the ?order_id= on the
  -- thank-you page, and the Meta CAPI Purchase event_id. UNIQUE so a retry or
  -- a double-tapped submit button cannot produce two rows for one order.
  order_id       text        not null unique,

  name           text        not null,
  email          text        not null,
  phone          text,

  amount         numeric(10,2) not null,
  currency       text        not null default 'ILS',

  -- 'landing' (the marketing site modal) or 'course' (the in-app purchase tab).
  source_surface text        not null,

  -- 'pending' until a payment is confirmed by hand on the admin page.
  status         text        not null default 'pending',

  created_at     timestamptz not null default now(),
  paid_at        timestamptz
);

-- The admin page's default view is "pending, newest first".
create index if not exists orders_status_created_idx
  on public.orders (status, created_at desc);

-- Looking an order up by the id printed on the customer's thank-you page.
create index if not exists orders_order_id_idx
  on public.orders (order_id);

-- ── ROW LEVEL SECURITY ──────────────────────────────────────────────────────
-- This table holds customer names, emails and phone numbers.
--
-- RLS is enabled and NO policies are created, on purpose. That combination
-- denies every request that arrives with the anon key — which is published in
-- the page source of both front ends and is therefore effectively public — while
-- the service_role key used by the log-order Edge Function bypasses RLS and
-- keeps working.
--
-- Do not add a policy here to "make it work". If a read stops working, the fix
-- is to route it through the Edge Function, not to open the table up.
alter table public.orders enable row level security;

-- Belt and braces: revoke the API roles' table grants as well, so the table is
-- unreachable over PostgREST even if a policy is ever added by accident.
revoke all on public.orders from anon, authenticated;
