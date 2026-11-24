// Deploy with Supabase CLI: supabase functions deploy admin-invites
// Required function secrets: SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY
// The service-role key stays on the server and must never be shipped in the APK.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function newInviteCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !anonKey || !serviceKey) return json({ error: "Server is not configured" }, 500);

  const authorization = req.headers.get("Authorization");
  if (!authorization?.startsWith("Bearer ")) return json({ error: "Sign-in required" }, 401);

  const authClient = createClient(url, anonKey, {
    global: { headers: { Authorization: authorization } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: userData, error: userError } = await authClient.auth.getUser();
  if (userError || !userData.user) return json({ error: "Invalid session" }, 401);

  const admin = createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  let body: { action?: string; inviteCode?: string };
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  if (body.action === "create") {
    const { data: profile, error } = await admin
      .from("launcher_profiles")
      .select("role,is_blocked")
      .eq("user_id", userData.user.id)
      .maybeSingle();
    if (error) return json({ error: "Could not verify permissions" }, 500);
    if (!profile || profile.role !== "owner" || profile.is_blocked) {
      return json({ error: "Only the active owner can create admin invitations" }, 403);
    }

    const code = newInviteCode();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    const { error: insertError } = await admin.from("admin_invites").insert({
      invite_code_hash: await sha256(code),
      created_by: userData.user.id,
      expires_at: expiresAt,
    });
    if (insertError) return json({ error: "Could not create invitation" }, 500);
    return json({ inviteCode: code, expiresAt });
  }

  if (body.action === "redeem") {
    const code = body.inviteCode?.trim();
    if (!code || code.length < 32 || code.length > 128) {
      return json({ error: "Invalid invitation code" }, 400);
    }

    const hash = await sha256(code);
    const now = new Date().toISOString();
    const { data: invite, error: findError } = await admin
      .from("admin_invites")
      .select("id,expires_at,used_at")
      .eq("invite_code_hash", hash)
      .gt("expires_at", now)
      .is("used_at", null)
      .maybeSingle();

    if (findError) return json({ error: "Could not verify invitation" }, 500);
    if (!invite) return json({ error: "Invitation is invalid, expired, or already used" }, 400);

    // Conditional update makes a one-time code unusable after the first successful claim.
    const { data: claimed, error: claimError } = await admin
      .from("admin_invites")
      .update({ used_by: userData.user.id, used_at: now })
      .eq("id", invite.id)
      .is("used_at", null)
      .select("id")
      .maybeSingle();

    if (claimError) return json({ error: "Could not claim invitation" }, 500);
    if (!claimed) return json({ error: "Invitation has already been used" }, 409);

    const { error: promoteError } = await admin
      .from("launcher_profiles")
      .update({ role: "admin" })
      .eq("user_id", userData.user.id)
      .eq("role", "player");

    if (promoteError) return json({ error: "Invitation claimed; contact the owner for role activation" }, 500);
    return json({ success: true, role: "admin" });
  }

  return json({ error: "Unknown action" }, 400);
});
