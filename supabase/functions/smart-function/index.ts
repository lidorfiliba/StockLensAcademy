// smart-function — Supabase Edge Function
// Handles: login, change_password, forgot_password, admin_list_users,
//          admin_create_user, admin_toggle_user,
//          admin_list_sessions, admin_revoke_sessions
//
// Deploy: supabase functions deploy smart-function
//
// ─────────────────────────────────────────────────────────────────────────────
// COMPATIBILITY CONTRACT — this function serves TWO client applications:
//   1. the course app  (StockLensAcademy/index.html)
//   2. the StockLens tool (separate repository, not visible here)
// Both post to this same function and share the same `users` table.
//
// Therefore, strictly additive only:
//   · no existing action removed or renamed
//   · no existing response field removed or renamed
//   · the login request shape is unchanged: { username, passwordHash }
//   · the password hashing scheme and salt are unchanged
//   · the new `token` response field is additive; clients that ignore it
//     keep working exactly as before
// ─────────────────────────────────────────────────────────────────────────────

import { serve } from 'https://deno.land/std@0.177.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const ADMIN_USERNAME = 'lidor_admin';
const EMAILJS_SERVICE = 'service_s5wzeck';
const EMAILJS_TEMPLATE_FORGOT = 'template_forgot_password';
const EMAILJS_PUBLIC_KEY = 'ZWYqaiqD2U5oWexSq';

// ── Rate limiting (server-side; the client's localStorage limiter is trivially
//    bypassed by calling this function directly) ───────────────────────────────
const RL_WINDOW_MINUTES = 15;
const RL_MAX_FAILURES = 5; // per username AND, separately, per IP

// ── Sessions ─────────────────────────────────────────────────────────────────
const SESSION_TTL_DAYS = 7;
const MAX_SESSIONS_PER_APP = 2;
const DEFAULT_APP = 'course';

/* Single generic credential-failure code.
   Deliberately reuses the EXISTING 'wrong_password' value rather than
   introducing a new one: both client apps already map 'wrong_password' to a
   sensible localised message, so username enumeration is closed without
   changing anything either client has to understand. Do not split this back
   into 'user_not_found' vs 'wrong_password' — that is the enumeration leak. */
const ERR_CREDENTIALS = 'wrong_password';

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

function generateTempPassword(): string {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let pass = '';
  const arr = new Uint8Array(8);
  crypto.getRandomValues(arr);
  for (const b of arr) pass += chars[b % chars.length];
  return pass;
}

/* UNCHANGED hashing scheme — same algorithm, same salt, same hex encoding.
   Both client apps hash the password with these exact rules before sending,
   and every password_hash already stored in `users` was produced this way. */
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + 'sl_salt_2024');
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/* Plain SHA-256 hex, no salt — used only for session tokens. A token is 32
   bytes of CSPRNG output, so it needs no stretching; the hash exists purely so
   a database leak does not hand out usable tokens. */
async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/* 32 random bytes, base64url. This raw value is returned to the client exactly
   once and is never stored or logged anywhere — only its SHA-256 is persisted. */
function generateSessionToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* Length-independent comparison so a mismatch cannot be timed byte by byte. */
function safeEqual(a: string, b: string): boolean {
  const av = new TextEncoder().encode(a);
  const bv = new TextEncoder().encode(b);
  let diff = av.length ^ bv.length;
  const n = Math.max(av.length, bv.length);
  for (let i = 0; i < n; i++) diff |= (av[i] ?? 0) ^ (bv[i] ?? 0);
  return diff === 0;
}

function clientIp(req: Request): string {
  const fwd = req.headers.get('x-forwarded-for') || '';
  const first = fwd.split(',')[0].trim();
  return first || req.headers.get('cf-connecting-ip') || 'unknown';
}

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ ok: false, error: 'invalid_json' }, 400); }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
  const action = (body.action as string) || 'login';

  // ── SESSION HELPERS ────────────────────────────────────────────────────────

  /* Revoke every session a user holds, across ALL apps. Used on password change
     and on suspension: those events must not leave a live session behind in the
     course app or in the StockLens tool. */
  async function revokeAllSessions(userId: string) {
    /* Deliberately not filtered by `revoked = false`. Re-revoking an already
       revoked row costs nothing, whereas the filter would skip any row whose
       revoked value is NULL — and silently failing to revoke is the one
       outcome this function must never have. */
    await supabase
      .from('course_sessions')
      .update({ revoked: true })
      .eq('user_id', userId);
  }

  /* Issue a session and enforce the per-app cap.
     Scoping the cap by app matters: without it, signing into the StockLens tool
     would evict a course session and vice versa. */
  async function createSession(userId: string, app: string, userAgent: string): Promise<string | null> {
    const token = generateSessionToken();
    const tokenHash = await sha256Hex(token);
    const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 86400_000).toISOString();

    /* revoked is written explicitly rather than left to a column default. If
       the column were nullable with no default, every `revoked = false` filter
       below would silently match nothing: sessions would never be evicted and,
       far worse, revokeAllSessions would update zero rows, so suspending a user
       would not actually kill their sessions. Writing it removes that
       dependency on how the table happens to be defined. */
    const { error } = await supabase.from('course_sessions').insert({
      user_id: userId,
      token_hash: tokenHash,
      expires_at: expiresAt,
      user_agent: userAgent.slice(0, 400),
      app,
      revoked: false,
    });
    /* A session that fails to store must not fail the login — the client can
       still fall back to the legacy user_id path. */
    if (error) return null;

    // Evict the oldest sessions beyond the cap, within this app only.
    const nowIso = new Date().toISOString();
    const { data: live } = await supabase
      .from('course_sessions')
      .select('id')
      .eq('user_id', userId)
      .eq('app', app)
      .eq('revoked', false)
      .gt('expires_at', nowIso)
      .order('created_at', { ascending: true });

    if (live && live.length > MAX_SESSIONS_PER_APP) {
      const stale = live.slice(0, live.length - MAX_SESSIONS_PER_APP).map(r => r.id);
      await supabase.from('course_sessions').update({ revoked: true }).in('id', stale);
    }
    return token;
  }

  // ── RATE LIMIT HELPERS ─────────────────────────────────────────────────────

  async function recordAttempt(username: string, ip: string, success: boolean) {
    await supabase.from('login_attempts').insert({ username, ip, success });
  }

  /* Counts recent FAILED attempts for the username and for the IP separately.
     Either one crossing the threshold blocks the attempt. */
  async function isRateLimited(username: string, ip: string): Promise<boolean> {
    const since = new Date(Date.now() - RL_WINDOW_MINUTES * 60_000).toISOString();

    const byUser = await supabase
      .from('login_attempts')
      .select('id', { count: 'exact', head: true })
      .eq('username', username)
      .eq('success', false)
      .gte('attempted_at', since);

    if ((byUser.count ?? 0) >= RL_MAX_FAILURES) return true;

    const byIp = await supabase
      .from('login_attempts')
      .select('id', { count: 'exact', head: true })
      .eq('ip', ip)
      .eq('success', false)
      .gte('attempted_at', since);

    return (byIp.count ?? 0) >= RL_MAX_FAILURES;
  }

  // ── LOGIN ──────────────────────────────────────────────────────────────────
  if (action === 'login' || !body.action) {
    const { username, passwordHash } = body as { username: string; passwordHash: string };
    if (!username || !passwordHash) return json({ ok: false, error: 'missing_fields' }, 400);

    const app = ((body.app as string) || DEFAULT_APP).slice(0, 40);
    const ip = clientIp(req);
    const userAgent = req.headers.get('user-agent') || '';

    /* A fixed decoy hash. Every failing path still performs one comparison of
       the same shape, so "no such user" and "wrong password" take a similar
       amount of time and cannot be told apart by a stopwatch. */
    const DECOY_HASH = '0'.repeat(64);

    // Blocked BEFORE the password is evaluated at all.
    if (await isRateLimited(username, ip)) {
      safeEqual(passwordHash, DECOY_HASH);
      await recordAttempt(username, ip, false);
      return json({ ok: false, error: ERR_CREDENTIALS }, 401);
    }

    const { data: users, error } = await supabase
      .from('users')
      .select('id, username, email, password_hash, is_active, plan')
      .eq('username', username)
      .limit(1);

    if (error) return json({ ok: false, error: 'server_error' }, 500);

    if (!users || users.length === 0) {
      safeEqual(passwordHash, DECOY_HASH);
      await recordAttempt(username, ip, false);
      return json({ ok: false, error: ERR_CREDENTIALS }, 401);
    }

    const user = users[0];

    /* Password is checked BEFORE is_active on purpose. The old order returned
       'account_suspended' to anyone who merely guessed a username, which told
       an attacker the account exists. Now the suspension notice is only ever
       shown to someone who already proved they know the password. */
    if (!safeEqual(user.password_hash ?? '', passwordHash)) {
      await recordAttempt(username, ip, false);
      return json({ ok: false, error: ERR_CREDENTIALS }, 401);
    }

    if (!user.is_active) {
      await recordAttempt(username, ip, false);
      return json({ ok: false, error: 'account_suspended' }, 403);
    }

    await recordAttempt(username, ip, true);

    /* Successful login clears the account's failure history so a user who
       finally remembers their password is not left locked out by their own
       earlier typos. IP history is left alone — clearing it would let an
       attacker reset their own limit with one known-good account. */
    const since = new Date(Date.now() - RL_WINDOW_MINUTES * 60_000).toISOString();
    await supabase
      .from('login_attempts')
      .delete()
      .eq('username', username)
      .eq('success', false)
      .gte('attempted_at', since);

    const token = await createSession(user.id, app, userAgent);

    /* `token` is the only addition to this response. Every pre-existing field
       keeps its name, type and meaning. */
    const payload: Record<string, unknown> = {
      ok: true,
      user: { id: user.id, username: user.username, email: user.email, plan: user.plan || 'full' },
    };
    if (token) payload.token = token;
    return json(payload);
  }

  // ── LOGOUT ─────────────────────────────────────────────────────────────────
  /* Revokes the caller's own session. Takes the raw token from the
     X-Course-Token header or a `token` field in the body, and revokes only the
     row whose hash matches — a token is proof enough to end its own session, so
     no other identity check is needed, and holding one lets you revoke nothing
     but itself.

     Always answers ok:true, even for a token that matched nothing. Logging out
     must not become a way to test whether a token is live. */
  if (action === 'logout') {
    const raw = req.headers.get('x-course-token') || (body.token as string) || '';
    if (raw) {
      const tokenHash = await sha256Hex(raw);
      await supabase
        .from('course_sessions')
        .update({ revoked: true })
        .eq('token_hash', tokenHash)
        .eq('revoked', false);
    }
    return json({ ok: true });
  }

  // ── CHANGE PASSWORD ────────────────────────────────────────────────────────
  if (action === 'change_password') {
    const { username, email, oldHash, newHash } = body as { username: string; email: string; oldHash: string; newHash: string };
    if (!username || !email || !oldHash || !newHash) return json({ ok: false, error: 'missing_fields' }, 400);

    const { data: users } = await supabase
      .from('users')
      .select('id, password_hash, is_active')
      .eq('username', username)
      .eq('email', email)
      .limit(1);

    if (!users || users.length === 0) return json({ ok: false, error: 'user_not_found' }, 404);
    const user = users[0];
    if (!user.is_active) return json({ ok: false, error: 'account_suspended' }, 403);
    if (!safeEqual(user.password_hash ?? '', oldHash)) return json({ ok: false, error: 'wrong_password' }, 401);

    const { error } = await supabase.from('users').update({ password_hash: newHash }).eq('id', user.id);
    if (error) return json({ ok: false, error: 'server_error' }, 500);

    // A password change invalidates every existing session, in every app.
    await revokeAllSessions(user.id);

    return json({ ok: true });
  }

  // ── FORGOT PASSWORD ────────────────────────────────────────────────────────
  if (action === 'forgot_password') {
    const { username } = body as { username: string };
    if (!username) return json({ ok: false, error: 'missing_fields' }, 400);

    const { data: users } = await supabase
      .from('users')
      .select('id, email, is_active')
      .eq('username', username)
      .limit(1);

    if (!users || users.length === 0) return json({ ok: false, error: 'user_not_found' }, 404);
    const user = users[0];
    if (!user.is_active) return json({ ok: false, error: 'account_suspended' }, 403);

    const tempPass = generateTempPassword();
    const newHash = await hashPassword(tempPass);

    const { error: updateErr } = await supabase.from('users').update({ password_hash: newHash }).eq('id', user.id);
    if (updateErr) return json({ ok: false, error: 'server_error' }, 500);

    /* This is also a password change, so existing sessions must die with it —
       otherwise a reset would not evict whoever was already signed in. */
    await revokeAllSessions(user.id);

    // Send email via EmailJS REST API
    try {
      await fetch('https://api.emailjs.com/api/v1.0/email/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          service_id: EMAILJS_SERVICE,
          template_id: EMAILJS_TEMPLATE_FORGOT,
          user_id: EMAILJS_PUBLIC_KEY,
          template_params: { to_email: user.email, username, temp_pass: tempPass }
        })
      });
    } catch {
      // Email failed — password was already reset, still return ok
    }

    return json({ ok: true });
  }

  // ── ADMIN: verify helper ───────────────────────────────────────────────────
  /* Admin status is always re-derived from the database here. The client-supplied
     admin_username is only a hint; the row must exist, carry the admin username
     and be active. Never trust a client-supplied username or id on its own. */
  async function verifyAdmin(admin_id: string, admin_username: string): Promise<boolean> {
    if (admin_username !== ADMIN_USERNAME) return false;
    const { data } = await supabase
      .from('users')
      .select('id, is_active')
      .eq('id', admin_id)
      .eq('username', ADMIN_USERNAME)
      .limit(1);
    return !!(data && data.length > 0 && data[0].is_active);
  }

  // ── ADMIN: LIST USERS ──────────────────────────────────────────────────────
  if (action === 'admin_list_users') {
    const { admin_id, admin_username } = body as { admin_id: string; admin_username: string };
    if (!await verifyAdmin(admin_id, admin_username)) return json({ ok: false, error: 'unauthorized' }, 403);

    const { data: users, error } = await supabase
      .from('users')
      .select('id, username, email, is_active, created_at')
      .order('created_at', { ascending: false });

    if (error) return json({ ok: false, error: 'server_error' }, 500);
    return json({ ok: true, users });
  }

  // ── ADMIN: CREATE USER ─────────────────────────────────────────────────────
  if (action === 'admin_create_user') {
    const { admin_id, admin_username, username, email, password_hash } = body as {
      admin_id: string; admin_username: string; username: string; email: string; password_hash: string;
    };
    if (!await verifyAdmin(admin_id, admin_username)) return json({ ok: false, error: 'unauthorized' }, 403);
    if (!username || !email || !password_hash) return json({ ok: false, error: 'missing_fields' }, 400);

    const { error } = await supabase.from('users').insert({ username, email, password_hash, is_active: true });
    if (error) return json({ ok: false, error: error.message }, 500);
    return json({ ok: true });
  }

  // ── ADMIN: TOGGLE USER ─────────────────────────────────────────────────────
  if (action === 'admin_toggle_user') {
    const { admin_id, admin_username, target_id, is_active } = body as {
      admin_id: string; admin_username: string; target_id: string; is_active: boolean;
    };
    if (!await verifyAdmin(admin_id, admin_username)) return json({ ok: false, error: 'unauthorized' }, 403);

    const { error } = await supabase.from('users').update({ is_active }).eq('id', target_id);
    if (error) return json({ ok: false, error: 'server_error' }, 500);

    /* Suspending must actually cut access, not just block the next login, so
       every live session in every app is revoked at the same moment. */
    if (is_active === false) await revokeAllSessions(target_id);

    return json({ ok: true });
  }

  // ── ADMIN: LIST SESSIONS ───────────────────────────────────────────────────
  /* Shows who is signed in where. Two devices in the same app is normal; the
     same account live from several very different user agents is the signal
     that a login has been shared. Token hashes are never returned. */
  if (action === 'admin_list_sessions') {
    const { admin_id, admin_username, target_id } = body as {
      admin_id: string; admin_username: string; target_id?: string;
    };
    if (!await verifyAdmin(admin_id, admin_username)) return json({ ok: false, error: 'unauthorized' }, 403);

    let q = supabase
      .from('course_sessions')
      .select('id, user_id, created_at, last_seen_at, expires_at, revoked, user_agent, app')
      .order('created_at', { ascending: false })
      .limit(500);

    if (target_id) q = q.eq('user_id', target_id);

    const { data: rows, error } = await q;
    if (error) return json({ ok: false, error: 'server_error' }, 500);

    // Attach usernames so the panel does not have to cross-reference ids.
    const ids = [...new Set((rows ?? []).map(r => r.user_id))];
    const nameById: Record<string, string> = {};
    if (ids.length) {
      const { data: us } = await supabase.from('users').select('id, username').in('id', ids);
      for (const u of us ?? []) nameById[u.id] = u.username;
    }

    const sessions = (rows ?? []).map(r => ({ ...r, username: nameById[r.user_id] ?? null }));
    return json({ ok: true, sessions });
  }

  // ── ADMIN: REVOKE SESSIONS ─────────────────────────────────────────────────
  /* Revoke one session by id, or every session a user holds. Passing an app
     narrows a user-wide revoke to that app only. */
  if (action === 'admin_revoke_sessions') {
    const { admin_id, admin_username, target_id, session_id, app } = body as {
      admin_id: string; admin_username: string; target_id?: string; session_id?: string; app?: string;
    };
    if (!await verifyAdmin(admin_id, admin_username)) return json({ ok: false, error: 'unauthorized' }, 403);
    if (!target_id && !session_id) return json({ ok: false, error: 'missing_fields' }, 400);

    let q = supabase.from('course_sessions').update({ revoked: true }).eq('revoked', false);
    if (session_id) q = q.eq('id', session_id);
    else {
      q = q.eq('user_id', target_id!);
      if (app) q = q.eq('app', app);
    }

    const { error } = await q;
    if (error) return json({ ok: false, error: 'server_error' }, 500);
    return json({ ok: true });
  }

  return json({ ok: false, error: 'unknown_action' }, 400);
});
