// Deploy: supabase functions deploy launcher-auth
// Secrets: SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY
// Username accounts use an internal, non-mailbox address. No email is sent.
// Never expose SUPABASE_SERVICE_ROLE_KEY to Android clients.
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

const validUsername = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9_]{3,24}$/.test(value);
const internalEmail = (username: string) =>
  `${username.toLowerCase()}@accounts.karabakhnw.mcsh.gg`;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !anonKey || !serviceKey) return json({ error: "Server is not configured" }, 500);

  let body: { action?: string; username?: string; password?: string };
  try { body = await req.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
  if (!validUsername(body.username)) return json({ error: "Username must be 3-24 letters, numbers, or underscores" }, 400);
  if (typeof body.password !== "string" || body.password.length < 8 || body.password.length > 72) {
    return json({ error: "Password must be 8-72 characters" }, 400);
  }

  const username = body.username;
  const email = internalEmail(username);
  const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const client = createClient(url, anonKey, { auth: { persistSession: false, autoRefreshToken: false } });

  if (body.action === "register") {
    const { data: existing, error: lookupError } = await admin
      .from("launcher_profiles").select("user_id").ilike("username", username).maybeSingle();
    if (lookupError) return json({ error: "Could not check username" }, 500);
    if (existing) return json({ error: "Username is already taken" }, 409);

    const { data: created, error: createError } = await admin.auth.admin.createUser({
      email,
      password: body.password,
      email_confirm: true,
      user_metadata: { username },
    });
    if (createError || !created.user) return json({ error: "Could not create account" }, 400);

    const { data: session, error: signInError } = await client.auth.signInWithPassword({
      email, password: body.password,
    });
    if (signInError || !session.session) return json({ error: "Account created; sign-in failed. Please log in." }, 201);
    return json({
      access_token: session.session.access_token,
      refresh_token: session.session.refresh_token,
      expires_in: session.session.expires_in,
      token_type: session.session.token_type,
      user: { id: created.user.id, username },
    }, 201);
  }

  if (body.action === "login") {
    const { data: profile, error: profileError } = await admin
      .from("launcher_profiles").select("user_id,username,is_blocked")
      .ilike("username", username).maybeSingle();
    if (profileError) return json({ error: "Could not verify account" }, 500);
    if (!profile || profile.is_blocked) return json({ error: "Account not found or blocked" }, 403);

    const { data, error } = await client.auth.signInWithPassword({ email, password: body.password });
    if (error || !data.session) return json({ error: "Incorrect username or password" }, 401);
    return json({
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in,
      token_type: data.session.token_type,
      user: { id: profile.user_id, username: profile.username },
    });
  }

  return json({ error: "Unknown action" }, 400);
});
