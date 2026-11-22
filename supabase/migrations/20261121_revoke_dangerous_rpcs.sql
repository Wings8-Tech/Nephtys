-- Revoke execution of server-only SECURITY DEFINER helpers from client roles.
-- Applied to the shared Wings8 Supabase project after the initial migration run.

revoke all on function public.wings8_exec_sql(text) from public, anon, authenticated;
grant execute on function public.wings8_exec_sql(text) to wings8_migrator;

revoke all on function public.handle_new_user() from public, anon, authenticated;
grant execute on function public.handle_new_user() to supabase_auth_admin;

revoke all on function public.purge_auth_login_failures() from public, anon, authenticated;
revoke all on function public.purge_auth_throttle() from public, anon, authenticated;

revoke all on function public.record_auth_failure(text, text, text) from public, anon, authenticated;
revoke all on function public.count_auth_failures(text, text, text, integer) from public, anon, authenticated;
revoke all on function public.clear_auth_failures(text, text, text) from public, anon, authenticated;
