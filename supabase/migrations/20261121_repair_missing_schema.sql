-- Repair schema objects that were skipped by earlier non-idempotent
-- migrations on an already-migrated project.
-- Idempotent.

create table if not exists public.message_user_state (
  message_id uuid not null references public.messages(id) on delete cascade,
  user_id uuid not null,
  is_starred boolean not null default false,
  is_pinned boolean not null default false,
  pinned_until timestamptz,
  updated_at timestamptz not null default now(),
  primary key (message_id, user_id)
);

alter table public.message_user_state enable row level security;
grant select, insert, update, delete on public.message_user_state to authenticated;
revoke all on public.message_user_state from anon;

drop policy if exists "mus_select_own" on public.message_user_state;
create policy "mus_select_own" on public.message_user_state for select to authenticated using (user_id = (select auth.uid()));
drop policy if exists "mus_insert_own" on public.message_user_state;
create policy "mus_insert_own" on public.message_user_state for insert to authenticated with check (user_id = (select auth.uid()));
drop policy if exists "mus_update_own" on public.message_user_state;
create policy "mus_update_own" on public.message_user_state for update to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
drop policy if exists "mus_delete_own" on public.message_user_state;
create policy "mus_delete_own" on public.message_user_state for delete to authenticated using (user_id = (select auth.uid()));

create index if not exists idx_message_user_state_user_starred on public.message_user_state (user_id, is_starred);
create index if not exists idx_message_user_state_user_pinned on public.message_user_state (user_id, is_pinned);

do $mig$
begin
  if to_regclass('private.message_authors') is not null then
    insert into public.message_user_state
      (message_id, user_id, is_starred, is_pinned, pinned_until, updated_at)
    select
      m.id, coalesce(ma.author_id, m.sender_id) as user_id,
      coalesce(m.is_starred, false), coalesce(m.is_pinned, false),
      null::timestamptz, now()
    from public.messages m
    left join private.message_authors ma on ma.message_id = m.id
    where (m.is_starred is true or m.is_pinned is true)
      and coalesce(ma.author_id, m.sender_id) is not null
    on conflict (message_id, user_id) do nothing;
  else
    insert into public.message_user_state
      (message_id, user_id, is_starred, is_pinned, pinned_until, updated_at)
    select m.id, m.sender_id, coalesce(m.is_starred, false), coalesce(m.is_pinned, false), null::timestamptz, now()
    from public.messages m
    where (m.is_starred is true or m.is_pinned is true)
      and m.sender_id is not null
    on conflict (message_id, user_id) do nothing;
  end if;
end
$mig$;

create table if not exists public.user_key_material (
  user_id uuid primary key references auth.users(id) on delete cascade,
  encrypted_private_key text,
  private_key_salt text,
  private_key_iv text,
  x25519_private_key text,
  x25519_salt text,
  x25519_iv text,
  ratchet_keys_encrypted text,
  ratchet_keys_salt text,
  ratchet_keys_iv text,
  updated_at timestamptz not null default now()
);

alter table public.user_key_material enable row level security;
drop policy if exists "ukm_owner_all" on public.user_key_material;
create policy "ukm_owner_all" on public.user_key_material for all to authenticated
using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
revoke all on public.user_key_material from anon, public;
grant select, insert, update, delete on public.user_key_material to authenticated;

do $rev$
declare
  col text;
begin
  foreach col in array array['encrypted_private_key','private_key_salt','private_key_iv','x25519_private_key','x25519_salt','x25519_iv','ratchet_keys_encrypted','ratchet_keys_salt','ratchet_keys_iv','password_hash']
  loop
    if exists (select 1 from information_schema.columns where table_schema='public' and table_name='profiles' and column_name=col) then
      execute format('revoke select (%I) on public.profiles from anon', col);
      if col = 'password_hash' then
        execute format('revoke select (%I) on public.profiles from authenticated', col);
      end if;
    end if;
  end loop;
end
$rev$;

drop policy if exists "otpk_update_consume" on public.one_time_prekeys;
create policy "otpk_update_consume" on public.one_time_prekeys for update to authenticated
using (is_used = false) with check (is_used = true);

do $doc$
begin
  if to_regclass('public.documents') is not null then
    execute 'drop policy if exists "view_authenticated_documents" on public.documents';
  end if;
end
$doc$;
