# KarabakhLauncher backend

This folder contains the Supabase database schema and Edge Functions for launcher accounts and role management.

## 1. Create the project
Create a Supabase project, then open **SQL Editor** and run the complete contents of `supabase/schema.sql`.

## 2. Configure Edge Function secrets
In Supabase Dashboard → Edge Functions → Secrets, configure:
- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY` (server only; never send it in chat or put it in the APK/repository)

Deploy both functions with the Supabase CLI:
```sh
supabase functions deploy launcher-auth
supabase functions deploy admin-invites
```

## 3. Username/password accounts
The `launcher-auth` function exposes POST actions:
- `{"action":"register","username":"Player_01","password":"at-least-8-characters"}`
- `{"action":"login","username":"Player_01","password":"at-least-8-characters"}`

It maps usernames to internal non-mailbox addresses under `accounts.karabakhnw.mcsh.gg`; users do not need to enter an email address. This setup does not send email or provide email-based password recovery. Add a verified recovery process before public production use.

New profiles are always created as `player`. The function rejects blocked accounts at login.

## 4. Make the first account the owner
Register your own account once. In Supabase Dashboard → Authentication → Users, copy that account's UUID. Run the one-time owner update shown at the bottom of `supabase/schema.sql`, replacing `YOUR_AUTH_USER_UUID`. Never create a public owner-registration path.

## 5. Admin invitations
An authenticated owner calls `admin-invites` with `{"action":"create"}`. The returned random invitation is valid for 24 hours and can be used once. The invited user must already have a launcher account, then calls `{"action":"redeem","inviteCode":"..." }`. The server checks the caller's session and uses a database function to redeem the code atomically.

## Security
- Clients cannot write role or blocked-state fields.
- Owner/admin privileges are checked server-side.
- The service-role key is server-only.
- Do not treat the launcher as having a connected login UI until Android integration and device testing are complete.
