// StockLens Academy — Edge Function: smart-function
//
// Handles all authentication / admin operations for the course app.
//
// IMPORTANT — this file was RECONSTRUCTED from the way index.html calls this
// endpoint, because the original source was never committed to this repository.
// Behaviour preserved: login (username + password hash), change_password,
// forgot_password, admin_list_users, admin_create_user, admin_toggle_user.
// Added: opaque session tokens, a 2-active-session cap, logout, and the two
// admin session actions.
//
// Before deploying, sanity-check two reconstructed details against your current
// deployed function:
//   1. forgot_password sends mail through Resend using the RESEND_API_KEY /
//      RESEND_FROM secrets. If your existing function uses a different provider
//      or secret name, port that block over instead of deploying this as-is.
//   2. admin_list_users now orders by username (the original ordering column is
//      unknown). Cosmetic only.
//
// No secret is hardcoded here. Everything sensitive comes from Deno.env.

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

// ── Constants ────────────────────────────────────────────────────────────────
// Not a secret: this salt is already public inside index.html, and the server
// must use the exact same scheme so browser-side hashes keep matching.
const PASSWORD_SALT = 'sl_salt_2024';
const ADMIN_USERNAME = 'lidor_admin';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MAX_ACTIVE_SESSIONS = 2;
const TEMP_PASSWORD_CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-course-token',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

// ── Helpers ──────────────────────────────────────────────────────────────────
function json(body, status) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: Object.assign({ 'Content-Type': 'application/json' }, CORS),
  });
}

// Handled errors return HTTP 200 with ok:false — the existing client reads
// data.error after parsing the body, so this keeps every message mapping intact.
function fail(error) {
  return json({ ok: false, error: error });
}

function toHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(function (b) { return b.toString(16).padStart(2, '0'); })
    .join('');
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return toHex(digest);
}

// Same scheme as hashPassword() in index.html.
function hashPassword(plain) {
  return sha256Hex(plain + PASSWORD_SALT);
}

// 32 cryptographically random bytes, base64url encoded.
function generateToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function generateTempPassword() {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += TEMP_PASSWORD_CHARS[bytes[i] % TEMP_PASSWORD_CHARS.length];
  }
  return out;
}

function db() {
  return createClient(
    Deno.env.get('SUPABASE_URL'),
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'),
    { auth: { persistSession: false, autoRefreshToken: false } }
  );
}

// ── Sessions ─────────────────────────────────────────────────────────────────

// Creates a session row and returns the RAW token. Only the SHA-256 of the
// token is persisted; the raw value is never stored and never logged.
async function createSession(sb, userId, userAgent) {
  const now = Date.now();

  // Enforce the active-session cap before inserting the new one.
  const existing = await sb
    .from('course_sessions')
    .select('id')
    .eq('user_id', userId)
    .eq('revoked', false)
    .gt('expires_at', new Date(now).toISOString())
    .order('created_at', { ascending: true });

  if (!existing.error && existing.data && existing.data.length >= MAX_ACTIVE_SESSIONS) {
    const surplus = existing.data.length - MAX_ACTIVE_SESSIONS + 1;
    const staleIds = existing.data.slice(0, surplus).map(function (r) { return r.id; });
    await sb.from('course_sessions').update({ revoked: true }).in('id', staleIds);
  }

  const token = generateToken();
  const tokenHash = await sha256Hex(token);

  const inserted = await sb.from('course_sessions').insert({
    user_id: userId,
    token_hash: tokenHash,
    expires_at: new Date(now + SESSION_TTL_MS).toISOString(),
    last_seen_at: new Date(now).toISOString(),
    revoked: false,
    user_agent: (userAgent || '').slice(0, 400),
  });

  if (inserted.error) throw new Error('session_insert_failed');
  return token;
}

async function revokeAllSessions(sb, userId) {
  await sb
    .from('course_sessions')
    .update({ revoked: true })
    .eq('user_id', userId)
    .eq('revoked', false);
}

// Resolves the caller from the X-Course-Token header. Returns the user row, or
// null if the token is missing / unknown / revoked / expired / the user is
// inactive. Never trusts anything the client put in the request body.
async function resolveCaller(req, sb) {
  const token = req.headers.get('x-course-token');
  if (!token) return null;

  const tokenHash = await sha256Hex(token);
  const session = await sb
    .from('course_sessions')
    .select('id, user_id, revoked, expires_at')
    .eq('token_hash', tokenHash)
    .maybeSingle();

  if (session.error || !session.data) return null;
  if (session.data.revoked === true) return null;
  if (!session.data.expires_at || new Date(session.data.expires_at).getTime() <= Date.now()) return null;

  const user = await sb
    .from('users')
    .select('id, username, email, plan, is_active')
    .eq('id', session.data.user_id)
    .maybeSingle();

  if (user.error || !user.data) return null;
  if (user.data.is_active !== true) return null;

  return { user: user.data, sessionId: session.data.id };
}

// Admin proof is server-side only: the session token identifies the caller, and
// the username is read from the database — never from the request body.
async function requireAdmin(req, sb) {
  const caller = await resolveCaller(req, sb);
  if (!caller) return null;
  if (caller.user.username !== ADMIN_USERNAME) return null;
  return caller;
}

// ── Actions ──────────────────────────────────────────────────────────────────

async function actionLogin(req, sb, body) {
  const username = (body.username || '').trim();
  const passwordHash = body.passwordHash || body.password_hash || '';
  if (!username || !passwordHash) return fail('user_not_found');

  const found = await sb
    .from('users')
    .select('id, username, email, plan, is_active, password_hash')
    .eq('username', username)
    .maybeSingle();

  if (found.error) return fail('server_error');
  if (!found.data) return fail('user_not_found');
  if (found.data.password_hash !== passwordHash) return fail('wrong_password');
  if (found.data.is_active !== true) return fail('account_suspended');

  const token = await createSession(sb, found.data.id, req.headers.get('user-agent'));

  return json({
    ok: true,
    token: token,
    user: {
      id: found.data.id,
      username: found.data.username,
      email: found.data.email,
      plan: found.data.plan || 'full',
    },
  });
}

async function actionLogout(req, sb) {
  const token = req.headers.get('x-course-token');
  if (token) {
    const tokenHash = await sha256Hex(token);
    await sb.from('course_sessions').update({ revoked: true }).eq('token_hash', tokenHash);
  }
  // Always ok — never reveal whether the token existed.
  return json({ ok: true });
}

async function actionChangePassword(sb, body) {
  const username = (body.username || '').trim();
  const email = (body.email || '').trim();
  const oldHash = body.oldHash || '';
  const newHash = body.newHash || '';
  if (!username || !email || !oldHash || !newHash) return fail('user_not_found');

  const found = await sb
    .from('users')
    .select('id, is_active, password_hash')
    .eq('username', username)
    .eq('email', email)
    .maybeSingle();

  if (found.error) return fail('server_error');
  if (!found.data) return fail('user_not_found');
  if (found.data.password_hash !== oldHash) return fail('wrong_password');
  if (found.data.is_active !== true) return fail('account_suspended');

  const updated = await sb
    .from('users')
    .update({ password_hash: newHash })
    .eq('id', found.data.id);

  if (updated.error) return fail('server_error');

  // A password change invalidates every device that was logged in with the old one.
  await revokeAllSessions(sb, found.data.id);
  return json({ ok: true });
}

async function actionForgotPassword(sb, body) {
  const username = (body.username || '').trim();
  if (!username) return fail('user_not_found');

  const found = await sb
    .from('users')
    .select('id, username, email, is_active')
    .eq('username', username)
    .maybeSingle();

  if (found.error) return fail('server_error');
  if (!found.data) return fail('user_not_found');
  if (found.data.is_active !== true) return fail('account_suspended');

  const apiKey = Deno.env.get('RESEND_API_KEY');
  const from = Deno.env.get('RESEND_FROM');
  if (!apiKey || !from) {
    console.error('forgot_password: mail transport not configured');
    return fail('server_error');
  }

  const tempPassword = generateTempPassword();
  const tempHash = await hashPassword(tempPassword);

  const updated = await sb
    .from('users')
    .update({ password_hash: tempHash })
    .eq('id', found.data.id);

  if (updated.error) return fail('server_error');

  // The old password is gone, so every existing session must go with it.
  await revokeAllSessions(sb, found.data.id);

  const mail = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + apiKey },
    body: JSON.stringify({
      from: from,
      to: [found.data.email],
      subject: 'StockLens Academy — סיסמה זמנית',
      html:
        '<div dir="rtl" style="font-family:Arial,sans-serif;font-size:15px;line-height:1.8">' +
        '<p>שלום ' + found.data.username + ',</p>' +
        '<p>הסיסמה הזמנית שלך היא: <strong style="font-size:18px">' + tempPassword + '</strong></p>' +
        '<p>התחבר איתה לקורס והחלף אותה מיד דרך לשונית "שינוי סיסמה".</p>' +
        '<p>StockLens Academy</p></div>',
    }),
  });

  if (!mail.ok) {
    console.error('forgot_password: mail send failed with status ' + mail.status);
    return fail('server_error');
  }

  return json({ ok: true });
}

async function actionAdminListUsers(sb) {
  const rows = await sb
    .from('users')
    .select('id, username, email, is_active, plan')
    .order('username', { ascending: true });

  if (rows.error) return fail('server_error');
  return json({ ok: true, users: rows.data || [] });
}

async function actionAdminCreateUser(sb, body) {
  const username = (body.username || '').trim();
  const email = (body.email || '').trim();
  const passwordHash = body.password_hash || body.passwordHash || '';
  if (!username || !email || !passwordHash) return fail('missing_fields');

  const inserted = await sb.from('users').insert({
    username: username,
    email: email,
    password_hash: passwordHash,
    is_active: true,
    plan: body.plan || 'full',
  });

  // The client looks for "duplicate" in this string to show a friendly message.
  if (inserted.error) return fail(inserted.error.message || 'server_error');
  return json({ ok: true });
}

async function actionAdminToggleUser(sb, body) {
  const targetId = body.target_id || body.id;
  const isActive = body.is_active === true;
  if (!targetId) return fail('missing_fields');

  const updated = await sb
    .from('users')
    .update({ is_active: isActive })
    .eq('id', targetId);

  if (updated.error) return fail('server_error');

  // Suspending an account must also kick every device it is signed in on.
  if (!isActive) await revokeAllSessions(sb, targetId);

  return json({ ok: true });
}

async function actionAdminListSessions(sb, body) {
  const nowIso = new Date().toISOString();
  let query = sb
    .from('course_sessions')
    .select('id, user_id, created_at, last_seen_at, user_agent')
    .eq('revoked', false)
    .gt('expires_at', nowIso)
    .order('created_at', { ascending: false });

  const filterId = body.target_id || body.user_id;
  if (filterId) query = query.eq('user_id', filterId);

  const sessions = await query;
  if (sessions.error) return fail('server_error');

  const rows = sessions.data || [];
  const userIds = [];
  for (let i = 0; i < rows.length; i++) {
    if (userIds.indexOf(rows[i].user_id) === -1) userIds.push(rows[i].user_id);
  }

  const names = {};
  if (userIds.length > 0) {
    const users = await sb.from('users').select('id, username, email').in('id', userIds);
    if (!users.error && users.data) {
      for (let i = 0; i < users.data.length; i++) {
        names[users.data[i].id] = users.data[i];
      }
    }
  }

  const grouped = userIds.map(function (id) {
    const own = rows.filter(function (r) { return r.user_id === id; });
    const meta = names[id] || {};
    return {
      user_id: id,
      username: meta.username || null,
      email: meta.email || null,
      session_count: own.length,
      sessions: own.map(function (r) {
        return {
          id: r.id,
          created_at: r.created_at,
          last_seen_at: r.last_seen_at,
          user_agent: r.user_agent,
        };
      }),
    };
  });

  // Busiest accounts first — the likely sharers.
  grouped.sort(function (a, b) { return b.session_count - a.session_count; });

  return json({ ok: true, users: grouped });
}

async function actionAdminRevokeSessions(sb, body) {
  const targetId = body.target_id || body.user_id;
  if (!targetId) return fail('missing_fields');
  await revokeAllSessions(sb, targetId);
  return json({ ok: true });
}

// ── Entry point ──────────────────────────────────────────────────────────────

Deno.serve(async function (req) {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });

  try {
    const sb = db();

    let body = {};
    try {
      body = await req.json();
    } catch (_e) {
      body = {};
    }

    // No action field means login — that is how index.html has always called it.
    const action = body.action || 'login';

    if (action === 'login') return await actionLogin(req, sb, body);
    if (action === 'logout') return await actionLogout(req, sb);
    if (action === 'change_password') return await actionChangePassword(sb, body);
    if (action === 'forgot_password') return await actionForgotPassword(sb, body);

    const adminActions = [
      'admin_list_users',
      'admin_create_user',
      'admin_toggle_user',
      'admin_list_sessions',
      'admin_revoke_sessions',
    ];

    if (adminActions.indexOf(action) !== -1) {
      const admin = await requireAdmin(req, sb);
      if (!admin) return fail('unauthorized');

      if (action === 'admin_list_users') return await actionAdminListUsers(sb);
      if (action === 'admin_create_user') return await actionAdminCreateUser(sb, body);
      if (action === 'admin_toggle_user') return await actionAdminToggleUser(sb, body);
      if (action === 'admin_list_sessions') return await actionAdminListSessions(sb, body);
      if (action === 'admin_revoke_sessions') return await actionAdminRevokeSessions(sb, body);
    }

    return fail('unknown_action');
  } catch (e) {
    console.error('smart-function error:', e && e.message ? e.message : String(e));
    return fail('server_error');
  }
});
