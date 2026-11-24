-- KarabakhLauncher Supabase schema
-- Run once in Supabase SQL Editor. Never put the service-role key in the APK.

create table if not exists public.launcher_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  role text not null default 'player' check (role in ('player', 'admin', 'owner')),
  is_blocked boolean not null default false,
  created_at timestamptz not null default now()
);

create unique index if not exists launcher_profiles_username_lower_uq
  on public.launcher_profiles (lower(username));

create table if not exists public.admin_invites (
  id bigint generated always as identity primary key,
  invite_code_hash text not null unique,
  created_by uuid not null references auth.users(id),
  expires_at timestamptz not null,
  used_by uuid references auth.users(id),
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_launcher_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  requested_username text;
begin
  requested_username := new.raw_user_meta_data ->> 'username';
  if requested_username is null
     or requested_username !~ '^[A-Za-z0-9_]{3,24}$' then
    raise exception 'A valid launcher username is required';
  end if;

  insert into public.launcher_profiles (user_id, username, role)
  values (new.id, lower(requested_username), 'player');
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_launcher_profile on auth.users;
create trigger on_auth_user_created_launcher_profile
after insert on auth.users
for each row execute function public.handle_new_launcher_user();

alter table public.launcher_profiles enable row level security;
alter table public.admin_invites enable row level security;

drop policy if exists "read own launcher profile" on public.launcher_profiles;
create policy "read own launcher profile"
on public.launcher_profiles for select
to authenticated
using (auth.uid() = user_id);

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
      and p.role in ('owner', 'admin')
      and not p.is_blocked
  );
$$;

revoke all on function public.launcher_is_owner() from public;
revoke all on function public.launcher_is_admin() from public;
grant execute on function public.launcher_is_owner() to authenticated;
grant execute on function public.launcher_is_admin() to authenticated;

-- Atomic, single-use admin invite redemption. Called only by the Edge Function
-- using the service-role key; never grant this function to client roles.
create or replace function public.redeem_launcher_admin_invite(
  p_code_hash text,
  p_user_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  claimed_id bigint;
begin
  update public.admin_invites
     set used_by = p_user_id, used_at = now()
   where invite_code_hash = p_code_hash
     and used_at is null
     and expires_at > now()
  returning id into claimed_id;

  if claimed_id is null then
    return false;
  end if;

  update public.launcher_profiles
     set role = 'admin'
   where user_id = p_user_id
     and role = 'player'
     and not is_blocked;

  if not found then
    raise exception 'Account cannot be promoted';
  end if;
  return true;
end;
$$;

revoke all on function public.redeem_launcher_admin_invite(text, uuid) from public, anon, authenticated;
grant execute on function public.redeem_launcher_admin_invite(text, uuid) to service_role;

-- One-time owner bootstrap: after registering the first launcher account,
-- copy its auth.users UUID from Authentication -> Users and run this manually.
-- Then remove this statement from your SQL editor history where appropriate.
-- update public.launcher_profiles
--    set role = 'owner'
--  where user_id = 'YOUR_AUTH_USER_UUID';
