-- Wings8 retention purge on pg_cron (no Edge Function / service-role secret needed).
-- Deletes delivered/read messages older than 24h. Media objects are removed by Storage lifecycle/API.

create or replace function public.wings8_purge_relayed()
returns integer
language plpgsql
security definer
set search_path = public, pg_temp
as $fn$
declare
  removed integer;
begin
  with candidates as (
    select id, media_url
    from public.messages
    where status in ('delivered','read')
      and created_at < now() - interval '24 hours'
    limit 200
  ),
  deleted as (
    delete from public.messages m
    using candidates c
    where m.id = c.id
    returning m.id
  )
  select count(*) into removed from deleted;
  return coalesce(removed, 0);
end;
$fn$;

revoke all on function public.wings8_purge_relayed() from public, anon, authenticated;

do $job$
begin
  perform cron.unschedule('nephtys-purge-relayed');
exception when others then
  null;
end
$job$;

select cron.schedule(
  'nephtys-purge-relayed',
  '37 * * * *',
  'select public.wings8_purge_relayed();'
);
