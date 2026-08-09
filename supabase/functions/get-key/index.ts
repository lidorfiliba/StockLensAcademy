// supabase/functions/get-key/index.ts
// Deploy: supabase functions deploy get-key
//
// Returns the course decryption key. Two ways to prove you may have it:
//
//   1. NEW  — an opaque session token in the X-Course-Token header, issued by
//             smart-function at login and verified against course_sessions.
//   2. OLD  — a user_id in the JSON body, exactly as before.
//
// ─────────────────────────────────────────────────────────────────────────────
// REMOVE AFTER ROLLOVER
// Path 2 is the pre-existing behaviour and is the weak one: user_id sits in
// plaintext in every customer's localStorage, so anyone who shares that one
// string hands over the whole course. It is kept ON PURPOSE and TEMPORARILY so
// that customers still running a cached copy of the old client are not locked
// out the moment this function is deployed.
//
// Retire it only once all of the following are true:
//   · the updated course client has been live long enough for caches to turn
//     over (the service worker serves index.html network-first, so this is
//     days, not weeks)
//   · the StockLens tool has been checked — if it calls get-key at all, it must
//     send X-Course-Token first
//   · course_sessions shows token traffic and the legacy path has gone quiet
// Then delete the block marked "LEGACY PATH" below and this comment with it.
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
  /* One identical response for every failure: bad token, revoked token, expired
     token, unknown user, suspended user, wrong plan. Never say which. */
  return new Response(
    JSON.stringify({ error: "Unauthorized" }),
    { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
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
    /* The key is only ever read from the environment. Never hardcode it here,
       and never log it. COURSE_KEY is the current secret name; the fallback
       keeps the previously deployed name working if COURSE_KEY is unset. */
    const COURSE_KEY = Deno.env.get("COURSE_KEY") ?? Deno.env.get("COURSE_DECRYPTION_KEY");
    if (!COURSE_KEY) {
      return new Response(
        JSON.stringify({ error: "Server error" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    const token = req.headers.get("x-course-token");

    // Body is optional when a token is supplied.
    let user_id: string | undefined;
    try {
      const parsed = await req.json();
      user_id = parsed?.user_id;
    } catch {
      user_id = undefined;
    }

    // ── PATH 1: session token ────────────────────────────────────────────────
    if (token) {
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

      /* APP SCOPING — intentionally NOT enforced yet. Uncomment once it is
         confirmed whether the StockLens tool calls get-key; enabling it before
         that would lock the tool out.
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

      // Best effort — a failed touch must not deny a valid request.
      await supabase
        .from("course_sessions")
        .update({ last_seen_at: new Date().toISOString() })
        .eq("id", session.id);

      return new Response(
        JSON.stringify({ key: COURSE_KEY }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // ── PATH 2: LEGACY user_id — REMOVE AFTER ROLLOVER ───────────────────────
    /* Byte-for-byte the same checks the deployed version performs today:
       the user must exist and be active. No plan check is added here on
       purpose — adding one would change the behaviour of the path that every
       existing customer is currently using, which is exactly the kind of
       change that locked people out before. The plan check lives on the token
       path, and becomes universal when this block is deleted. */
    if (!user_id) {
      return new Response(
        JSON.stringify({ error: "Missing user_id" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { data: user, error } = await supabase
      .from("users")
      .select("id, is_active")
      .eq("id", user_id)
      .single();

    if (error || !user || !user.is_active) return unauthorized();

    return new Response(
      JSON.stringify({ key: COURSE_KEY }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (_err) {
    return new Response(
      JSON.stringify({ error: "Server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
