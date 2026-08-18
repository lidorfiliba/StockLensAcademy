// log-order — Supabase Edge Function
// Handles: create (public), admin_list_orders, admin_mark_paid
//
// Deploy: supabase functions deploy log-order
//
// ─────────────────────────────────────────────────────────────────────────────
// WHY THIS EXISTS
// Until now a submitted order existed in exactly one place: an EmailJS message.
// If EmailJS is down, rate-limits, or the mail lands in spam, a paying
// customer's order is gone and nothing anywhere records that they ordered. This
// function writes every submission to the `orders` table so there is a durable
// record independent of email.
//
// It is an ADDITION. The EmailJS path is untouched, and a failure here must
// never block the email or the redirect — the callers treat it as best effort.
//
// ─────────────────────────────────────────────────────────────────────────────
// AUTH — two different postures in one function, matching smart-function
//
//   create              PUBLIC. The caller is a customer filling in the
//                       purchase form; they have no account and no session yet,
//                       so there is nothing to authenticate. This mirrors the
//                       `login` action in smart-function, which is likewise
//                       reachable with only the anon key. Everything the public
//                       path accepts is validated and length-capped below, and
//                       it returns nothing but ok/order_id — never stored rows,
//                       so it cannot be used to read anyone else's order.
//
//   admin_*             Admin only, verified the same way smart-function does:
//                       admin status is re-derived from the users table on every
//                       call and the client-supplied username is never trusted
//                       on its own.
//
// The service_role key is read from the environment and never leaves the
// server, which is the whole point of routing the insert through a function
// instead of letting the browser write to the table directly.
//
// RLS: the `orders` table holds customer PII and must have RLS enabled with NO
// policies. service_role bypasses RLS, so this function keeps working while the
// anon key — which is public in the page source — can read nothing. See the
// migration SQL alongside this file.
// ─────────────────────────────────────────────────────────────────────────────

import { serve } from 'https://deno.land/std@0.177.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

const ADMIN_USERNAME = 'lidor_admin';

/* Which purchase surface the order came from. An allowlist rather than free
   text so this column stays groupable in a query. */
const SURFACES = new Set(['landing', 'course']);

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers':
    'authorization, x-client-info, apikey, content-type, x-course-token',
};

function json(body: object, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' },
  });
}

/* Trim and hard-cap every string that reaches the database. The public path is
   reachable by anyone with the anon key, so nothing is stored at whatever
   length the caller felt like sending. */
function str(v: unknown, max: number): string {
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ ok: false, error: 'invalid_json' }, 400); }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
  const action = (body.action as string) || 'create';

  /* Same helper, same rules, same table as smart-function's verifyAdmin. */
  async function verifyAdmin(admin_id: string, admin_username: string): Promise<boolean> {
    if (!admin_id || admin_username !== ADMIN_USERNAME) return false;
    const { data } = await supabase
      .from('users')
      .select('id, is_active')
      .eq('id', admin_id)
      .eq('username', ADMIN_USERNAME)
      .limit(1);
    return !!(data && data.length > 0 && data[0].is_active);
  }

  // ── CREATE (public) ────────────────────────────────────────────────────────
  if (action === 'create') {
    const order_id = str(body.order_id, 64);
    const name = str(body.name, 120);
    const email = str(body.email, 200).toLowerCase();
    const phone = str(body.phone, 40);
    const source_surface = str(body.source_surface, 20);
    const currency = str(body.currency, 3).toUpperCase() || 'ILS';
    const amountRaw = typeof body.amount === 'string' ? parseFloat(body.amount) : body.amount;

    /* The order id is the join key to the EmailJS message, the thank-you page
       and the CAPI Purchase event. A row without a valid one is worthless, so
       this is the one field that rejects rather than defaults. */
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(order_id)) {
      return json({ ok: false, error: 'invalid_order_id' }, 400);
    }
    if (!name) return json({ ok: false, error: 'missing_name' }, 400);
    if (!email || !email.includes('@')) return json({ ok: false, error: 'invalid_email' }, 400);
    if (!SURFACES.has(source_surface)) return json({ ok: false, error: 'invalid_source' }, 400);
    if (!/^[A-Z]{3}$/.test(currency)) return json({ ok: false, error: 'invalid_currency' }, 400);

    const amount = typeof amountRaw === 'number' ? amountRaw : NaN;
    if (!isFinite(amount) || amount <= 0 || amount > 1000000) {
      return json({ ok: false, error: 'invalid_amount' }, 400);
    }

    /* Idempotent on order_id. The caller may retry after a network blip, and a
       customer who double-taps submit must not produce two rows for one order.
       ignoreDuplicates means a repeat is a no-op rather than an error, so the
       client never sees a failure for something that already succeeded. */
    const { error } = await supabase
      .from('orders')
      .upsert({
        order_id,
        name,
        email,
        phone: phone || null,
        amount,
        currency,
        source_surface,
        /* status is left to the column default ('pending') so the default lives
           in one place — the schema — rather than being restated here. */
      }, { onConflict: 'order_id', ignoreDuplicates: true });

    if (error) {
      /* Full detail goes to the function's own log, which is readable in
         Dashboard -> Edge Functions -> log-order -> Logs. This is the record
         that survives the customer closing their tab. */
      console.error(JSON.stringify({
        event: 'orders_insert_failed',
        order_id, source_surface,
        pg_code: error.code ?? null,
        pg_message: error.message ?? null,
        pg_details: error.details ?? null,
        hint: error.hint ?? null,
        at: new Date().toISOString(),
      }));
      /* The caller gets the Postgres SQLSTATE but not the full message: enough
         to tell a missing table (42P01) from a bad column (42703) or an RLS
         denial (42501) in a browser console, without echoing schema internals
         to anyone who can reach this endpoint. */
      return json({ ok: false, error: 'insert_failed', code: error.code ?? null }, 500);
    }

    /* Read the row back so the caller gets proof it is actually stored, rather
       than proof the request was merely accepted. `stored` is what the client
       reports to the admin, so a silent no-op cannot masquerade as a success:
       upsert+ignoreDuplicates returns no rows on conflict, which is a genuine
       "already stored" rather than a failure, so that case is reported too. */
    const { data: saved } = await supabase
      .from('orders')
      .select('order_id, status, created_at')
      .eq('order_id', order_id)
      .limit(1);

    const row = saved && saved.length ? saved[0] : null;
    if (!row) {
      console.error(JSON.stringify({
        event: 'orders_insert_vanished',
        order_id, source_surface, at: new Date().toISOString(),
      }));
      return json({ ok: false, error: 'insert_not_visible' }, 500);
    }

    /* Still returns only this caller's own order. The public path must not
       become a way to read anyone else's row back out. */
    return json({ ok: true, order_id, stored: true, created_at: row.created_at });
  }

  // ── ADMIN: LIST ORDERS ─────────────────────────────────────────────────────
  if (action === 'admin_list_orders') {
    const { admin_id, admin_username, status } = body as {
      admin_id: string; admin_username: string; status?: string;
    };
    if (!await verifyAdmin(admin_id, admin_username)) return json({ ok: false, error: 'unauthorized' }, 403);

    /* Defaults to pending — that is the working queue the admin page shows.
       'all' is accepted so the same endpoint can show history later. */
    const want = str(status, 20) || 'pending';

    let q = supabase
      .from('orders')
      .select('order_id, name, email, phone, amount, currency, source_surface, status, created_at, paid_at')
      .order('created_at', { ascending: false })
      .limit(200);

    if (want !== 'all') q = q.eq('status', want);

    const { data: orders, error } = await q;
    if (error) return json({ ok: false, error: 'server_error' }, 500);
    return json({ ok: true, orders: orders ?? [] });
  }

  // ── ADMIN: MARK PAID ───────────────────────────────────────────────────────
  if (action === 'admin_mark_paid') {
    const { admin_id, admin_username, order_id } = body as {
      admin_id: string; admin_username: string; order_id: string;
    };
    if (!await verifyAdmin(admin_id, admin_username)) return json({ ok: false, error: 'unauthorized' }, 403);
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(order_id || '')) return json({ ok: false, error: 'invalid_order_id' }, 400);

    /* Scoped to rows that are still pending. Re-marking an already-paid order
       is then a no-op that reports not_found, rather than silently moving
       paid_at forward and losing when the payment was actually confirmed. */
    const { data, error } = await supabase
      .from('orders')
      .update({ status: 'paid', paid_at: new Date().toISOString() })
      .eq('order_id', order_id)
      .eq('status', 'pending')
      .select('order_id, status, paid_at');

    if (error) return json({ ok: false, error: 'server_error' }, 500);
    if (!data || data.length === 0) return json({ ok: false, error: 'not_found_or_already_paid' }, 404);
    return json({ ok: true, order: data[0] });
  }

  return json({ ok: false, error: 'unknown_action' }, 400);
});
