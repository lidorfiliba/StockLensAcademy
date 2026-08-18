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

/* ── RATE LIMITS ─────────────────────────────────────────────────────────────
   Enforced server-side because the endpoint is reachable with the anon key,
   which is published in both front ends — a client-side check would only
   inconvenience honest customers while an attacker calls the function directly.

   All four limits apply together; whichever trips first wins. */
const LIMITS = {
  /* Raised from 5/20. Israeli mobile carriers put many subscribers behind one
     public IP, so a low per-IP ceiling blocks real buyers as soon as traffic
     picks up. The CAPTCHA below is what actually stops a determined attacker;
     these limits are now a backstop against volume, not the primary defence. */
  IP_PER_HOUR: 15,
  IP_PER_DAY: 60,
  EMAIL_PER_DAY: 3,
  PHONE_PER_DAY: 3,
};

/* ── CLOUDFLARE TURNSTILE ────────────────────────────────────────────────────
   Rate limits alone cannot stop an attacker who rotates email, phone and IP.
   Turnstile does: every new order must carry a token that Cloudflare issued to
   a real browser, and that token is verified here, server-side, before
   anything is written.

   Set the secret with:
     supabase secrets set TURNSTILE_SECRET=<secret key> --project-ref flcakringwxebpeifhke

   Read at request time rather than module load, so setting it takes effect on
   the next invocation without a redeploy. */
const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const TURNSTILE_TIMEOUT_MS = 8000;

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/* Setting TURNSTILE_SECRET to this exact value turns the gate OFF deliberately:
   orders are accepted on the rate limits alone. It exists because "unset" must
   keep meaning "misconfigured, refuse everything" — an operator who has not
   finished setting this up should not silently get a CAPTCHA that checks
   nothing. Turning it off has to be a decision someone typed on purpose.

   To enable real verification, replace it with the secret key from Cloudflare. */
const TURNSTILE_DISABLED = 'disabled';

type CaptchaResult =
  | { state: 'ok' }
  | { state: 'skipped'; why: string }          // Cloudflare unreachable — fail open
  | { state: 'disabled' }                      // deliberately switched off
  | { state: 'unconfigured' }                  // secret missing — fail closed
  | { state: 'rejected'; codes: string[] };

/* Three distinct outcomes, deliberately not collapsed into a boolean:

   · unconfigured — TURNSTILE_SECRET is not set. Fails CLOSED. A CAPTCHA that
     is not actually checking anything is worse than no CAPTCHA, because it
     looks like protection. The caller is told exactly what is wrong.

   · skipped — the request to Cloudflare timed out or threw. Fails OPEN. This
     is an outage on their side or ours, and refusing every order because a
     third party is down would turn their bad day into lost sales. Logged
     loudly so it cannot pass unnoticed.

   · rejected — Cloudflare answered and said no. Fails CLOSED. This is the
     case the feature exists for. */
async function verifyTurnstile(token: string, ip: string): Promise<CaptchaResult> {
  const secret = Deno.env.get('TURNSTILE_SECRET') || '';
  if (!secret) return { state: 'unconfigured' };
  if (secret === TURNSTILE_DISABLED) return { state: 'disabled' };
  if (!token) return { state: 'rejected', codes: ['missing-input-response'] };

  const form = new URLSearchParams();
  form.set('secret', secret);
  form.set('response', token);
  /* Cloudflare cross-checks the IP the token was issued to. Omitted when we
     could not determine one, since sending a wrong value is worse than none. */
  if (ip && ip !== 'unknown') form.set('remoteip', ip);

  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TURNSTILE_TIMEOUT_MS);
    const r = await fetch(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
      signal: ctrl.signal,
    });
    clearTimeout(timer);

    if (!r.ok) return { state: 'skipped', why: 'siteverify HTTP ' + r.status };

    const d = await r.json();
    if (d.success === true) return { state: 'ok' };
    return { state: 'rejected', codes: d['error-codes'] ?? [] };
  } catch (e) {
    return { state: 'skipped', why: String(e && (e as Error).message ? (e as Error).message : e) };
  }
}
const HOUR_MS = 3600_000;
const DAY_MS = 86_400_000;

/* Rows older than the widest window can never affect a decision. Swept
   opportunistically rather than on a schedule so no cron job is needed. */
const SWEEP_OLDER_THAN_MS = DAY_MS + HOUR_MS;
const SWEEP_PROBABILITY = 0.1;

/* First entry of x-forwarded-for, matching smart-function's clientIp. Everything
   after the first hop is attacker-controllable, so only the first is used. */
function clientIp(req: Request): string {
  const fwd = req.headers.get('x-forwarded-for') || '';
  const first = fwd.split(',')[0].trim();
  return first || req.headers.get('cf-connecting-ip') || 'unknown';
}

/* Digits only, so 054-666-7812 / +972546667812 / 0546667812 all count as the
   same person rather than as three fresh allowances. */
function phoneKey(raw: string): string {
  let d = (raw || '').replace(/[^\d+]/g, '');
  if (d.startsWith('+972')) d = '0' + d.slice(4);
  else if (d.startsWith('972')) d = '0' + d.slice(3);
  return d.replace(/\D/g, '');
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

    /* ── IDEMPOTENCY, CHECKED BEFORE THE RATE LIMIT ────────────────────────
       A resubmission of an order_id that already exists is the retry queue or a
       double-tapped button, not a new order. It returns the stored row and
       stops here — so it costs nothing against the limits and can never be the
       request that locks a customer out of their own order. This ordering is
       load-bearing; moving the rate check above it would make the retry path
       able to rate-limit itself. */
    const { data: existing } = await supabase
      .from('orders')
      .select('order_id, created_at')
      .eq('order_id', order_id)
      .limit(1);

    if (existing && existing.length) {
      return json({
        ok: true, order_id, stored: true,
        created_at: existing[0].created_at, duplicate: true,
      });
    }

    const ip = clientIp(req);
    const phoneNorm = phoneKey(phone);

    /* ── CAPTCHA ────────────────────────────────────────────────────────────
       Checked AFTER the idempotency check above and BEFORE anything is
       written. Order matters in both directions:

       · after idempotency, so a resubmission of an order that is already
         stored — the retry queue, a double-tapped button — never needs a token
         and can never be refused for carrying a stale one.
       · before the insert, so a request that fails verification costs nothing
         and leaves no trace. */
    const captchaToken = str(body.turnstile_token, 2048);
    const captcha = await verifyTurnstile(captchaToken, ip);

    if (captcha.state === 'unconfigured') {
      console.error(JSON.stringify({
        event: 'captcha_unconfigured',
        message: 'TURNSTILE_SECRET is not set — refusing to accept orders. ' +
                 'Set it with: supabase secrets set TURNSTILE_SECRET=<secret key> ' +
                 '--project-ref flcakringwxebpeifhke',
        order_id, at: new Date().toISOString(),
      }));
      /* 503, not 403: the caller did nothing wrong, the server is misconfigured.
         The front ends treat this code as "our fault" and let the customer
         through to the email and the thank-you page rather than blaming them
         for an unset secret. */
      return json({
        ok: false,
        error: 'captcha_unconfigured',
        message: 'CAPTCHA verification is not configured on the server. ' +
                 'Set the TURNSTILE_SECRET secret. No order was stored.',
      }, 503);
    }

    if (captcha.state === 'disabled') {
      /* Recorded on every order so an "off" gate cannot be forgotten about.
         Orders are protected by the rate limits alone while this is the case. */
      console.warn(JSON.stringify({
        event: 'captcha_disabled',
        message: 'TURNSTILE_SECRET is set to "disabled" — accepting orders without ' +
                 'CAPTCHA verification, on rate limits alone. Set a real Cloudflare ' +
                 'secret key to enable it.',
        order_id, at: new Date().toISOString(),
      }));
    }

    if (captcha.state === 'skipped') {
      /* Loud on purpose. This is the one path where an order is written
         without a verified token, and it must be obvious in the logs that it
         happened and why. */
      console.error(JSON.stringify({
        event: 'captcha_verification_unavailable',
        message: 'Cloudflare siteverify could not be reached — ALLOWING the order ' +
                 'rather than losing a sale. Investigate if this repeats.',
        why: captcha.why, order_id, ip, at: new Date().toISOString(),
      }));
    }

    if (captcha.state === 'rejected') {
      const codes = captcha.codes;
      /* Cloudflare returns timeout-or-duplicate both for an expired token and
         for one already redeemed. Separated here because the front ends handle
         them differently: a stale token from the retry queue is re-minted,
         while a genuine replay is simply refused. */
      const stale = codes.includes('timeout-or-duplicate');
      console.warn(JSON.stringify({
        event: 'captcha_rejected', codes, stale, order_id, ip,
        at: new Date().toISOString(),
      }));
      return json({
        ok: false,
        error: stale ? 'captcha_stale' : 'captcha_failed',
        reason: codes.join(',') || 'verification_failed',
      }, 403);
    }

    /* ── REPLAY BINDING ─────────────────────────────────────────────────────
       Cloudflare already refuses a token twice, which is the primary defence.
       This is the second layer, in our own data: one token authorises exactly
       one order. It also means a token redeemed successfully but whose insert
       then failed cannot be reused to write a different order. */
    let tokenHash: string | null = null;
    if (captchaToken && captcha.state === 'ok') {
      tokenHash = await sha256Hex(captchaToken);
      const { data: reused } = await supabase
        .from('orders')
        .select('order_id')
        .eq('turnstile_token_hash', tokenHash)
        .limit(1);
      if (reused && reused.length) {
        console.warn(JSON.stringify({
          event: 'captcha_token_replayed',
          order_id, already_used_by: reused[0].order_id, ip,
          at: new Date().toISOString(),
        }));
        return json({ ok: false, error: 'captcha_replay',
          reason: 'token already used by another order' }, 403);
      }
    }

    // ── RATE LIMIT ──────────────────────────────────────────────────────────
    const now = Date.now();
    const dayAgo = new Date(now - DAY_MS).toISOString();
    const hourAgo = now - HOUR_MS;

    /* One query for the IP covers both of its windows: fetch the day's
       timestamps once and count the last hour in memory, rather than paying a
       second round trip for a subset of rows already in hand. */
    const { data: ipRows } = await supabase
      .from('order_rate_events')
      .select('created_at')
      .eq('kind', 'ip').eq('value', ip)
      .gte('created_at', dayAgo)
      .order('created_at', { ascending: false })
      .limit(200);

    const ipDay = ipRows?.length ?? 0;
    const ipHour = (ipRows ?? []).filter(r => new Date(r.created_at).getTime() >= hourAgo).length;

    const countSince = async (kind: string, value: string) => {
      const { count } = await supabase
        .from('order_rate_events')
        .select('id', { count: 'exact', head: true })
        .eq('kind', kind).eq('value', value)
        .gte('created_at', dayAgo);
      return count ?? 0;
    };

    const emailDay = await countSince('email', email);
    const phoneDay = phoneNorm ? await countSince('phone', phoneNorm) : 0;

    let blocked: string | null = null;
    if (ipHour >= LIMITS.IP_PER_HOUR) blocked = 'ip_hourly';
    else if (ipDay >= LIMITS.IP_PER_DAY) blocked = 'ip_daily';
    else if (emailDay >= LIMITS.EMAIL_PER_DAY) blocked = 'email_daily';
    else if (phoneDay >= LIMITS.PHONE_PER_DAY) blocked = 'phone_daily';

    if (blocked) {
      /* Logged so a legitimate customer who complains can be found and let
         through by hand. The IP is already in this table; nothing new is
         exposed by naming it here. */
      console.warn(JSON.stringify({
        event: 'order_rate_limited',
        reason: blocked, order_id, ip, email, phone: phoneNorm,
        counts: { ipHour, ipDay, emailDay, phoneDay },
        at: new Date().toISOString(),
      }));
      /* 429 with a machine-readable reason. The customer-facing wording lives
         in the front ends — this response is never shown raw to anyone. */
      return json({
        ok: false,
        error: 'rate_limited',
        reason: blocked,
        retry_after_seconds: blocked === 'ip_hourly' ? 3600 : 86400,
      }, 429);
    }

    /* Idempotent on order_id. The caller may retry after a network blip, and a
       customer who double-taps submit must not produce two rows for one order.
       ignoreDuplicates means a repeat is a no-op rather than an error, so the
       client never sees a failure for something that already succeeded. The
       explicit check above handles the common case; this keeps the guarantee
       under a race between two concurrent requests for the same id. */
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
        /* Null when Cloudflare was unreachable and verification was skipped.
           The unique index on this column is partial for exactly that reason. */
        turnstile_token_hash: tokenHash,
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

    /* ── RECORD THE COUNTERS ────────────────────────────────────────────────
       Written only after the row is confirmed stored. A failed insert must not
       consume anyone's allowance: "resubmitting after a failed write must
       always get through" depends on this, because a genuine failure leaves no
       counter behind and the retry starts from the same position.

       Best effort. If the counters cannot be written the order is already safe,
       and refusing it at that point would trade a real order for a bookkeeping
       problem. The gap is logged instead. */
    const events: Array<{ kind: string; value: string; order_id: string }> = [
      { kind: 'ip', value: ip, order_id },
      { kind: 'email', value: email, order_id },
    ];
    if (phoneNorm) events.push({ kind: 'phone', value: phoneNorm, order_id });

    const { error: rlErr } = await supabase.from('order_rate_events').insert(events);
    if (rlErr) {
      console.error(JSON.stringify({
        event: 'rate_events_insert_failed',
        order_id, pg_code: rlErr.code ?? null, pg_message: rlErr.message ?? null,
        at: new Date().toISOString(),
      }));
    }

    /* Sweep rows that can no longer affect any decision. Probabilistic so the
       cost is amortised across requests and no scheduled job is needed; at this
       volume one sweep in ten is far more than enough to keep the table small. */
    if (Math.random() < SWEEP_PROBABILITY) {
      const cutoff = new Date(now - SWEEP_OLDER_THAN_MS).toISOString();
      const { error: sweepErr } = await supabase
        .from('order_rate_events').delete().lt('created_at', cutoff);
      if (sweepErr) console.warn('rate_events sweep failed: ' + sweepErr.message);
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

  // ── ADMIN: SUGGEST USERNAME ────────────────────────────────────────────────
  /* Proposes a free username derived from the customer's email, for the admin
     to use when creating the account by hand. This function does NOT create the
     account and never touches the users table except to read existing names.

     Lives server-side purely because it has to know which usernames are already
     taken; the browser cannot be allowed to read the users table to find out.
     Admin-only, so the enumeration it performs is not a disclosure. */
  if (action === 'admin_suggest_username') {
    const { admin_id, admin_username, email } = body as {
      admin_id: string; admin_username: string; email: string;
    };
    if (!await verifyAdmin(admin_id, admin_username)) return json({ ok: false, error: 'unauthorized' }, 403);

    const raw = str(email, 200).toLowerCase();
    const at = raw.indexOf('@');
    if (at < 1) return json({ ok: false, error: 'invalid_email' }, 400);

    const strip = (s: string) => s.replace(/[^a-z0-9]/g, '');
    let base = strip(raw.slice(0, at));

    /* Both client apps require at least 3 characters and reject anything
       outside [a-z0-9_]. A very short local part ("ab@…") would otherwise
       produce a username the admin cannot actually create, so it borrows from
       the domain rather than being padded with filler. */
    if (base.length < 3) base += strip(raw.slice(at + 1).split('.')[0] ?? '');
    if (base.length < 3) base = 'user';
    base = base.slice(0, 20);

    /* One query, then decide in memory: fetching every name that starts with
       the base costs a single round trip regardless of how many collisions
       there are. */
    const { data: taken, error } = await supabase
      .from('users')
      .select('username')
      .like('username', base + '%')
      .limit(500);

    if (error) return json({ ok: false, error: 'server_error' }, 500);

    const used = new Set((taken ?? []).map(u => (u.username ?? '').toLowerCase()));
    let suggestion = base;
    /* Bounded so a pathological set of collisions cannot spin. 200 variants of
       one base is far past anything real. */
    for (let n = 2; used.has(suggestion) && n < 200; n++) suggestion = base + n;

    return json({ ok: true, username: suggestion, base, collided: suggestion !== base });
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
