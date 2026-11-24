# KarabakhLauncher backend setup

This folder contains the initial Supabase database security schema for launcher accounts and roles.

## Setup
1. Create a Supabase project in your own Supabase account.
2. Open **SQL Editor** and run `schema.sql`.
3. Create the first launcher account through the future launcher registration flow.
4. In Supabase Dashboard, find that user's UUID in Authentication → Users.
5. Replace the placeholders in the one-time owner bootstrap SQL at the bottom of `schema.sql`, execute it manually, then remove/comment that bootstrap statement.
6. Keep the project's `service_role` key private. It must never be placed in the APK, GitHub repository, or sent in chat.

## Security model
- New accounts default to `player`.
- A client cannot promote itself, edit its role, or change its blocked state.
- Owner/admin checks are performed by database functions.
- Admin invites must be generated and redeemed by a server-side Edge Function with expiry and one-time use.
- The owner account is assigned manually once; there is no public owner-registration path.

## Still required before account login works
- Supabase project URL and publishable/anon key configured as public Android client settings.
- Server-side Edge Function for username/password sign-in and admin invitations.
- Android login/register UI wired to Supabase Auth and the username mapping flow.
- Server-side account blocking checks before privileged actions.

This is a secure schema foundation, not a finished or connected authentication system. Do not treat the launcher as having working login/admin access until the remaining items are implemented and tested.
