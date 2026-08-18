// meta-capi — Supabase Edge Function
// Sends a server-side Purchase event to the Meta Conversions API.
//
// Deploy: supabase functions deploy meta-capi
//
// ─────────────────────────────────────────────────────────────────────────────
// WHY THIS EXISTS
// Payment for the course happens OFF-SITE, via Bit / Paybox or PayPal, with no
// callback into any system we control. Nothing in the browser can therefore
// prove that money changed hands, which is why no client-side Purchase event is
// fired anywhere in either front end. The only events the browser reports are
// InitiateCheckout (submit click) and Lead (thank-you page).
//
// This function is the single place a Purchase is ever recorded, and it is
// called by hand from the admin confirmation page after a payment has actually
// been seen. Treat its output as the revenue number.
//
// DEDUPLICATION
// The client mints an order id at submit time (SLA-<epoch>-<suffix>) and uses it
// as the Meta `eventID` on InitiateCheckout and Lead. This function sends the
// same value as `event_id` on the Purchase. Meta collapses a server event and a
// browser event that share an event_id + event_name pair, so re-confirming the
// same order twice cannot double-count it.
//
// AUTH
// Follows the same pattern as smart-function's verifyAdmin: the caller supplies
// admin_id + admin_username, admin status is re-derived from the `users` table
// on every call, and a client-supplied username is never trusted on its own.
// This function is strictly additive — it reads the users table and touches
// nothing else. It does not read, write or alter sessions, passwords or keys.
// ─────────────────────────────────────────────────────────────────────────────

import { serve } from 'https://deno.land/std@0.177.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

/* Set with:
     supabase secrets set META_PIXEL_ID=27572902432409101
     supabase secrets set META_CAPI_TOKEN=<system user access token>
   Both are read at request time rather than at module load, so setting them
   takes effect on the next invocation without a redeploy. */
const META_ENV_PIXEL = 'META_PIXEL_ID';
const META_ENV_TOKEN = 'META_CAPI_TOKEN';

const ADMIN_USERNAME = 'lidor_admin';
const GRAPH_VERSION = 'v21.0';

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

/* Plain SHA-256 hex — the encoding Meta requires for every PII field. */
async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/* Meta matches on normalised values, so normalisation has to happen BEFORE the
   hash or the hash simply will not match anything on their side.
   Email: trimmed, lowercased. */
async function hashEmail(raw: string): Promise<string | null> {
  const e = (raw || '').trim().toLowerCase();
  if (!e || !e.includes('@')) return null;
  return await sha256Hex(e);
}

/* Phone: digits only, with country code, no leading + or zeros.
   Israeli mobiles are typed locally as 054-6667812; Meta wants 972546667812.
   A number that already carries the country code is left alone. */
async function hashPhone(raw: string): Promise<string | null> {
  let d = (raw || '').replace(/\D/g, '');
  if (!d) return null;
  if (d.startsWith('00')) d = d.slice(2);
  if (d.startsWith('0')) d = '972' + d.slice(1);
  else if (d.length === 9 && /^5/.test(d)) d = '972' + d; // 546667812, no leading 0
  if (d.length < 8 || d.length > 15) return null;
  return await sha256Hex(d);
}

/* Names are matched lowercased with whitespace stripped. */
async function hashName(raw: string): Promise<string | null> {
  const n = (raw || '').trim().toLowerCase().replace(/\s+/g, '');
  if (!n) return null;
  return await sha256Hex(n);
}

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ ok: false, error: 'invalid_json' }, 400); }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

  // ── AUTH ───────────────────────────────────────────────────────────────────
  /* Checked FIRST, before the Meta credentials are even looked at. An
     unauthenticated caller must not be able to probe which secrets are set. */
  const { admin_id, admin_username } = body as { admin_id?: string; admin_username?: string };

  if (!admin_id || !admin_username) return json({ ok: false, error: 'unauthorized' }, 403);
  if (admin_username !== ADMIN_USERNAME) return json({ ok: false, error: 'unauthorized' }, 403);

  const { data: adminRows } = await supabase
    .from('users')
    .select('id, is_active')
    .eq('id', admin_id)
    .eq('username', ADMIN_USERNAME)
    .limit(1);

  if (!adminRows || adminRows.length === 0 || !adminRows[0].is_active) {
    return json({ ok: false, error: 'unauthorized' }, 403);
  }

  // ── CREDENTIALS ────────────────────────────────────────────────────────────
  const PIXEL_ID = Deno.env.get(META_ENV_PIXEL) || '';
  const CAPI_TOKEN = Deno.env.get(META_ENV_TOKEN) || '';

  if (!PIXEL_ID || !CAPI_TOKEN) {
    const missing: string[] = [];
    if (!PIXEL_ID) missing.push(META_ENV_PIXEL);
    if (!CAPI_TOKEN) missing.push(META_ENV_TOKEN);
    /* 503, not 500: the function is healthy, it is the configuration that is
       incomplete. The response names exactly what is missing and how to set it
       so this never turns into a silent no-op that looks like success. */
    return json({
      ok: false,
      error: 'missing_credentials',
      missing,
      message:
        'Meta Conversions API credentials are not configured. ' +
        'The Purchase event was NOT sent. Set the secrets below and retry.',
      how_to_fix: missing
        .map(k => `supabase secrets set ${k}=<value> --project-ref flcakringwxebpeifhke`)
        .join(' && '),
    }, 503);
  }

  // ── INPUT ──────────────────────────────────────────────────────────────────
  const {
    order_id, value, currency, email, phone, name, event_source_url, test_event_code,
  } = body as {
    order_id?: string; value?: number | string; currency?: string;
    email?: string; phone?: string; name?: string;
    event_source_url?: string; test_event_code?: string;
  };

  /* The order id is the deduplication key. Without it a Purchase cannot be tied
     to the browser events it belongs to, so it is required rather than
     defaulted. Same alphabet the thank-you page validates against. */
  if (!order_id || typeof order_id !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(order_id)) {
    return json({ ok: false, error: 'invalid_order_id' }, 400);
  }

  const amount = typeof value === 'string' ? parseFloat(value) : value;
  if (typeof amount !== 'number' || !isFinite(amount) || amount <= 0 || amount > 1000000) {
    return json({ ok: false, error: 'invalid_value' }, 400);
  }

  const cur = (currency || 'ILS').toUpperCase();
  if (!/^[A-Z]{3}$/.test(cur)) return json({ ok: false, error: 'invalid_currency' }, 400);

  /* At least one matchable identifier is required — a Purchase with no user_data
     cannot be attributed to anyone and is worth nothing to Meta. */
  const em = await hashEmail(email || '');
  const ph = await hashPhone(phone || '');
  const fn = await hashName(name || '');
  if (!em && !ph) return json({ ok: false, error: 'missing_user_identifier' }, 400);

  const user_data: Record<string, unknown> = {};
  if (em) user_data.em = [em];
  if (ph) user_data.ph = [ph];
  if (fn) user_data.fn = [fn];

  // ── SEND ───────────────────────────────────────────────────────────────────
  const payload: Record<string, unknown> = {
    data: [{
      event_name: 'Purchase',
      /* Seconds, not milliseconds. Meta rejects events dated more than 7 days
         back, which is the practical limit on confirming an old order. */
      event_time: Math.floor(Date.now() / 1000),
      /* Same id the browser used as eventID on InitiateCheckout and Lead. */
      event_id: order_id,
      action_source: 'website',
      event_source_url: event_source_url || 'https://lidorfiliba.github.io/thank-you.html',
      user_data,
      custom_data: {
        value: amount,
        currency: cur,
        order_id,
        content_name: 'StockLens Academy',
        content_category: 'course',
      },
    }],
  };
  /* Optional: routes the event to Meta's Test Events tab instead of live
     reporting, so the wiring can be checked without inventing revenue. */
  if (test_event_code) payload.test_event_code = test_event_code;

  let metaStatus = 0;
  let metaBody: unknown = null;
  try {
    const r = await fetch(
      `https://graph.facebook.com/${GRAPH_VERSION}/${PIXEL_ID}/events?access_token=${encodeURIComponent(CAPI_TOKEN)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      },
    );
    metaStatus = r.status;
    try { metaBody = await r.json(); } catch { metaBody = await r.text(); }
  } catch (e) {
    return json({ ok: false, error: 'meta_request_failed', detail: String(e) }, 502);
  }

  if (metaStatus < 200 || metaStatus >= 300) {
    /* Surfaced verbatim so a bad token or an expired one is obvious on the
       admin page rather than being swallowed into a generic failure. */
    return json({ ok: false, error: 'meta_rejected', status: metaStatus, meta: metaBody }, 502);
  }

  return json({
    ok: true,
    order_id,
    value: amount,
    currency: cur,
    matched_on: { email: !!em, phone: !!ph, name: !!fn },
    meta: metaBody,
  });
});
