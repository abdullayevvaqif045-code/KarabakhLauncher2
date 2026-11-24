-- KarabakhLauncher account roles and access control
-- Run in Supabase SQL Editor only after creating the Supabase project.
-- Never put the service_role key in the Android app.

create table if not exists public.launcher_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (char_length(username) between 3 and 24),
  role text not null default 'player' check (role in ('player','admin','owner')),
  is_blocked boolean not null default false,
  created_at timestamptz not null default now()
);

-- Create a player profile automatically after Supabase Auth signup.
create or replace function public.handle_new_launcher_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $
declare
  requested_username text;
begin
  requested_username := new.raw_user_meta_data ->> 'username';
  if requested_username is null
     or requested_username !~ '^[A-Za-z0-9_]{3,24}
  id bigint generated always as identity primary key,
  invite_code_hash text not null unique,
  created_by uuid not null references auth.users(id),
  expires_at timestamptz not null,
  used_by uuid references auth.users(id),
  used_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.launcher_profiles enable row level security;
alter table public.admin_invites enable row level security;

-- Users may read their own profile. They cannot change their role or blocked status.
drop policy if exists "read own launcher profile" on public.launcher_profiles;
create policy "read own launcher profile"
on public.launcher_profiles for select
to authenticated
using (auth.uid() = user_id);

-- Admin invite rows are never directly readable or writable by clients.
revoke all on public.admin_invites from anon, authenticated;
revoke insert, update, delete on public.launcher_profiles from anon, authenticated;
grant select on public.launcher_profiles to authenticated;

create or replace function public.launcher_is_owner()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.launcher_profiles p
    where p.user_id = auth.uid() and p.role = 'owner' and not p.is_blocked
  );
$$;

create or replace function public.launcher_is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.launcher_profiles p
    where p.user_id = auth.uid()
      and p.role in ('owner','admin')
      and not p.is_blocked
  );
$$;

revoke all on function public.launcher_is_owner() from public;
revoke all on function public.launcher_is_admin() from public;
grant execute on function public.launcher_is_owner() to authenticated;
grant execute on function public.launcher_is_admin() to authenticated;

-- One-time owner bootstrap. Replace the UUID with the account's auth.users id.
-- Execute manually in the Supabase SQL Editor, then delete/comment this block.
-- Do NOT expose an owner-registration button or a shared owner password in the APK.
-- insert into public.launcher_profiles (user_id, username, role)
-- values ('YOUR_AUTH_USER_UUID', 'YOUR_OWNER_USERNAME', 'owner')
-- on conflict (user_id) do update set role = 'owner';

-- Admin creation must be implemented through a server-side Edge Function that:
-- 1) verifies the caller with Supabase Auth,
-- 2) checks launcher_is_owner(),
-- 3) generates a random one-time invite token and stores only its hash,
-- 4) accepts it once, with expiry, and sets the invited user's role to admin.
-- Do not implement role changes using client-side table updates.
 then
    raise exception 'A valid launcher username is required';
  end if;

  insert into public.launcher_profiles (user_id, username, role)
  values (new.id, requested_username, 'player');
  return new;
end;
$;

drop trigger if exists on_auth_user_created_launcher_profile on auth.users;
create trigger on_auth_user_created_launcher_profile
after insert on auth.users
for each row execute function public.handle_new_launcher_user();

create table if not exists public.admin_invites (
  id bigint generated always as identity primary key,
  invite_code_hash text not null unique,
  created_by uuid not null references auth.users(id),
  expires_at timestamptz not null,
  used_by uuid references auth.users(id),
  used_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.launcher_profiles enable row level security;
alter table public.admin_invites enable row level security;

-- Users may read their own profile. They cannot change their role or blocked status.
drop policy if exists "read own launcher profile" on public.launcher_profiles;
create policy "read own launcher profile"
on public.launcher_profiles for select
to authenticated
using (auth.uid() = user_id);

-- Admin invite rows are never directly readable or writable by clients.
revoke all on public.admin_invites from anon, authenticated;
revoke insert, update, delete on public.launcher_profiles from anon, authenticated;
grant select on public.launcher_profiles to authenticated;

create or replace function public.launcher_is_owner()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.launcher_profiles p
    where p.user_id = auth.uid() and p.role = 'owner' and not p.is_blocked
  );
$$;

create or replace function public.launcher_is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.launcher_profiles p
    where p.user_id = auth.uid()
      and p.role in ('owner','admin')
      and not p.is_blocked
  );
$$;

revoke all on function public.launcher_is_owner() from public;
revoke all on function public.launcher_is_admin() from public;
grant execute on function public.launcher_is_owner() to authenticated;
grant execute on function public.launcher_is_admin() to authenticated;

-- One-time owner bootstrap. Replace the UUID with the account's auth.users id.
-- Execute manually in the Supabase SQL Editor, then delete/comment this block.
-- Do NOT expose an owner-registration button or a shared owner password in the APK.
-- insert into public.launcher_profiles (user_id, username, role)
-- values ('YOUR_AUTH_USER_UUID', 'YOUR_OWNER_USERNAME', 'owner')
-- on conflict (user_id) do update set role = 'owner';

-- Admin creation must be implemented through a server-side Edge Function that:
-- 1) verifies the caller with Supabase Auth,
-- 2) checks launcher_is_owner(),
-- 3) generates a random one-time invite token and stores only its hash,
-- 4) accepts it once, with expiry, and sets the invited user's role to admin.
-- Do not implement role changes using client-side table updates.
