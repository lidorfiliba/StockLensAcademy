// StockLens Academy — Edge Function: get-key
//
// Returns the course decryption key, and only to a caller holding a live
// server-issued session token.
//
// The previous version handed the key to anyone who posted a user_id. That
// code path is gone: the request body is never read here at all. Identity comes
// exclusively from the X-Course-Token header, which is matched against a
// SHA-256 hash stored in course_sessions.
//
// The key itself lives in the COURSE_KEY secret and is never written to a file.

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-course-token',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

// One message for every rejection. The caller never learns whether the token,
// the account or the plan was the reason.
function denied() {
  return new Response(JSON.stringify({ error: 'unauthorized' }), {
    status: 401,
    headers: Object.assign({ 'Content-Type': 'application/json' }, CORS),
  });
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest))
    .map(function (b) { return b.toString(16).padStart(2, '0'); })
    .join('');
}

Deno.serve(async function (req) {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });

  try {
    const courseKey = Deno.env.get('COURSE_KEY');
    if (!courseKey) {
      // Server misconfiguration, not an auth decision — and it leaks nothing
      // about the caller, so it stays distinguishable for debugging.
      console.error('get-key: COURSE_KEY secret is not set');
      return new Response(JSON.stringify({ error: 'server_error' }), {
        status: 500,
        headers: Object.assign({ 'Content-Type': 'application/json' }, CORS),
      });
    }

    const token = req.headers.get('x-course-token');
    if (!token) return denied();

    const sb = createClient(
      Deno.env.get('SUPABASE_URL'),
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'),
      { auth: { persistSession: false, autoRefreshToken: false } }
    );

    // 1. The token must match a stored session hash.
    const tokenHash = await sha256Hex(token);
    const session = await sb
      .from('course_sessions')
      .select('id, user_id, revoked, expires_at')
      .eq('token_hash', tokenHash)
      .maybeSingle();

    if (session.error || !session.data) return denied();

    // 2. That session must be live.
    if (session.data.revoked === true) return denied();
    if (!session.data.expires_at) return denied();
    if (new Date(session.data.expires_at).getTime() <= Date.now()) return denied();

    // 3. The account behind it must still be active.
    const user = await sb
      .from('users')
      .select('id, is_active, plan')
      .eq('id', session.data.user_id)
      .maybeSingle();

    if (user.error || !user.data) return denied();
    if (user.data.is_active !== true) return denied();

    // 4. The plan must include course content. Mirrors index.html, where a
    //    missing plan means 'full' and 'tools' means analyzer-only.
    const plan = user.data.plan || 'full';
    if (plan === 'tools') return denied();

    // 5. Record the hit so account sharing shows up in admin_list_sessions.
    await sb
      .from('course_sessions')
      .update({ last_seen_at: new Date().toISOString() })
      .eq('id', session.data.id);

    return new Response(JSON.stringify({ key: courseKey }), {
      status: 200,
      headers: Object.assign({ 'Content-Type': 'application/json' }, CORS),
    });
  } catch (e) {
    console.error('get-key error:', e && e.message ? e.message : String(e));
    return denied();
  }
});
