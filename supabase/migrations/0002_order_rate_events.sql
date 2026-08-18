-- order_rate_events — rate-limit counters for the public order endpoint
--
-- Run this once in the Supabase dashboard: SQL Editor -> New query -> Run.
-- It is idempotent, so re-running it is safe.
--
-- The `create` action on log-order is reachable by anyone holding the anon key,
-- which is published in both front ends. Without a limit, one script can fill
-- the pending list indefinitely. This table holds one row per accepted order per
-- identifier, and log-order counts rows inside a rolling window before allowing
-- the next insert.
--
-- Deliberately separate from `orders`: counters churn and get swept, orders are
-- a permanent business record. Mixing them would mean a retention policy on the
-- counters could delete real orders, and every rate query would scan the orders
-- table.

create table if not exists public.order_rate_events (
  id         bigserial   primary key,

  -- Which identifier this row counts against.
  kind       text        not null check (kind in ('ip', 'email', 'phone')),

  -- The normalised identifier: an IP string, a lowercased email, or a
  -- digits-only phone. Normalisation happens in the function so that casing or
  -- punctuation cannot be used to get a fresh allowance.
  value      text        not null,

  -- Which order produced this row. Not used for limiting; it is here so an
  -- unexpected block can be traced back to real orders when investigating.
  order_id   text,

  created_at timestamptz not null default now()
);

-- The only query shape the limiter runs: newest-first within one identifier.
create index if not exists order_rate_events_lookup_idx
  on public.order_rate_events (kind, value, created_at desc);

-- Supports the periodic sweep of rows older than the widest window.
create index if not exists order_rate_events_created_idx
  on public.order_rate_events (created_at);

-- ── ROW LEVEL SECURITY ──────────────────────────────────────────────────────
-- Same posture as `orders`: RLS on, no policies, API grants revoked. The rows
-- contain customer emails, phone numbers and IP addresses, and the anon key is
-- effectively public. service_role bypasses RLS, so log-order keeps working
-- while nothing reachable from a browser can read or write this table.
--
-- If a read stops working, route it through the Edge Function. Do not add a
-- policy here — a writable counter table is a bypassable rate limit.
alter table public.order_rate_events enable row level security;
revoke all on public.order_rate_events from anon, authenticated;
revoke all on sequence public.order_rate_events_id_seq from anon, authenticated;
