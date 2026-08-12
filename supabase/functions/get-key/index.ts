// supabase/functions/get-key/index.ts
// Deploy: supabase functions deploy get-key
//
// Returns a course decryption key. There is exactly ONE way to prove you may
// have it: an opaque session token in the X-Course-Token header, issued by
// smart-function at login and verified against the course_sessions table on
// every single request. There is no other path.
//
// ─────────────────────────────────────────────────────────────────────────────
// KEY VERSIONING — why two keys exist at once
//
// The course HTML is served by GitHub Pages behind a CDN that keeps serving a
// stale index.html for minutes after a push. If this function returned only the
// new key, every client still holding the old cached index.html would receive a
// key that cannot decrypt the payload it has, and the course would fail to open
// for those users until the CDN caught up.
//
// So the client tells us which payload it is holding:
//
//   version 1, or absent  ->  KEY_V1  (the old key, for stale cached clients)
//   version 2             ->  KEY_V2  (the new key, for the pushed client)
//
// Both require a valid session. KEY_V1 is retired — and the leaked key with it
// — by deleting the v1 branch below once the CDN has fully flipped.
// ─────────────────────────────────────────────────────────────────────────────

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-course-token",
};

/* Plans that do NOT include the course. 'tools' buys the StockLens Analyzer
   only. A denylist rather than an allowlist on purpose: an unrecognised or
   missing plan keeps today's behaviour (access granted) instead of silently
   locking out a paying customer whose plan string we did not anticipate. */
const PLANS_WITHOUT_COURSE = new Set(["tools"]);

function unauthorized() {
  /* One identical response for every failure: absent token, bad token, revoked
     token, expired token, unknown user, suspended user, wrong plan. Never say
     which, and never include key material of any kind. */
  return new Response(
    JSON.stringify({ error: "Unauthorized" }),
    { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}

function serverError() {
  return new Response(
    JSON.stringify({ error: "Server error" }),
    { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
  );
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    /* ── AUTH FIRST ───────────────────────────────────────────────────────────
       The token is checked before any key is read from the environment, so an
       unauthenticated request never touches key material at all. */
    const token = req.headers.get("x-course-token");
    if (!token) return unauthorized();

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    /* The body is read only for the key version. Any `user_id` an older client
       still sends is ignored: it is not an identity here and never will be
       again. The legacy path that trusted it has been deleted, not disabled. */
    let version = 1;
    try {
      const parsed = await req.json();
      const raw = parsed?.version;
      if (raw !== undefined && raw !== null) version = Number(raw);
    } catch {
      version = 1;
    }
    if (version !== 1 && version !== 2) {
      return new Response(
        JSON.stringify({ error: "Unsupported version" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // ── SESSION: verified against the server-side store, every request ────────
    const tokenHash = await sha256Hex(token);

    const { data: sessions } = await supabase
      .from("course_sessions")
      .select("id, user_id, revoked, expires_at, app")
      .eq("token_hash", tokenHash)
      .limit(1);

    if (!sessions || sessions.length === 0) return unauthorized();
    const session = sessions[0];

    if (session.revoked) return unauthorized();
    if (!session.expires_at || new Date(session.expires_at).getTime() <= Date.now()) {
      return unauthorized();
    }

    /* APP SCOPING — still not enforced, and enforcing it here would be a false
       assurance. The Analyzer does not send an `app` field at login, so
       smart-function tags its sessions 'course' by default; an `app === 'course'`
       test would therefore pass for Analyzer tokens and change nothing. Make the
       Analyzer send app:'analyzer' first, then enable this:
           if (session.app !== 'course') return unauthorized(); */

    const { data: users } = await supabase
      .from("users")
      .select("id, is_active, plan")
      .eq("id", session.user_id)
      .limit(1);

    if (!users || users.length === 0) return unauthorized();
    const user = users[0];

    if (!user.is_active) return unauthorized();
    if (PLANS_WITHOUT_COURSE.has(user.plan ?? "")) return unauthorized();

    // ── KEY SELECTION ────────────────────────────────────────────────────────
    /* Keys are only ever read from the environment. Never hardcode one here,
       never log one, never return one on any path above this line.

       KEY_V1 falls back to the pre-rotation secret names so that a deploy which
       lands before the new secrets are set still serves the old key correctly
       rather than 500ing every request. KEY_V2 has no fallback on purpose: if
       it is unset, the honest answer is a server error, not the wrong key. */
    const key = version === 2
      ? Deno.env.get("KEY_V2")
      : (Deno.env.get("KEY_V1") ?? Deno.env.get("COURSE_KEY") ?? Deno.env.get("COURSE_DECRYPTION_KEY"));

    if (!key) return serverError();

    // Best effort — a failed touch must not deny a valid request.
    await supabase
      .from("course_sessions")
      .update({ last_seen_at: new Date().toISOString() })
      .eq("id", session.id);

    return new Response(
      JSON.stringify({ key }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (_err) {
    return serverError();
  }
});
