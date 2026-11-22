-- ============================================================================
-- Correctif sécurité : exposition des clés privées / hash via public.profiles
-- ============================================================================
-- CONSTAT (base DÉPLOYÉE, vérifié par appel REST anonyme) :
--   • Policy `profiles_read` : TO public USING(true)
--       → une requête ANONYME (clé anon, sans JWT) lit toutes les lignes.
--   • Le rôle `anon` a le privilège SELECT sur les colonnes de clés privées
--     chiffrées (encrypted_private_key, x25519_private_key,
--     ratchet_keys_encrypted, ...).
--   → FUITE : n'importe qui sur Internet récupère les clés privées chiffrées
--     de tous les utilisateurs (force brute hors-ligne → clés E2EE cassées).
--
-- CE CORRECTIF (minimal, ne casse pas l'app connectée) :
--   1. révoque le SELECT des colonnes sensibles pour `anon` ;
--   2. révoque `password_hash` pour anon + authenticated (0/8 peuplé, 0 usage) ;
--   3. durcit la policy UPDATE des one-time prekeys.
--
-- RESTE À FAIRE (volontairement NON appliqué ici) :
--   `authenticated` peut encore lire les colonnes de clés privées de N'IMPORTE
--   QUEL utilisateur — la RLS est au niveau ligne, pas colonne, et la policy
--   SELECT est USING(true). Correctif propre = RPC SECURITY DEFINER
--   `get_my_key_material()` + révocation des colonnes pour authenticated,
--   avec adaptation des 5 lectures client (e2eeX25519, mediaEncryption,
--   passphraseKeyStore). À faire en PR testée (chemin critique de récupération
--   des clés).
-- ============================================================================

-- 1) anon ne doit jamais lire les colonnes de clés privées
do $rev$
declare
  col text;
begin
  foreach col in array array[
    'encrypted_private_key','private_key_salt','private_key_iv',
    'x25519_private_key','x25519_salt','x25519_iv',
    'ratchet_keys_encrypted','ratchet_keys_salt','ratchet_keys_iv'
  ]
  loop
    if exists (
      select 1 from information_schema.columns
      where table_schema = 'public' and table_name = 'profiles' and column_name = col
    ) then
      execute format('revoke select (%I) on public.profiles from anon', col);
    end if;
  end loop;
end
$rev$;

-- 2) password_hash : jamais exposé au client
do $pw$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'profiles' and column_name = 'password_hash'
  ) then
    revoke select (password_hash) on public.profiles from anon, authenticated;
  end if;
end
$pw$;

-- 3) one_time_prekeys : UPDATE limité à la consommation (is_used false -> true)
DROP POLICY IF EXISTS "otpk_update_consume" ON public.one_time_prekeys;
CREATE POLICY "otpk_update_consume"
    ON public.one_time_prekeys FOR UPDATE
    TO authenticated
    USING (is_used = false)
    WITH CHECK (is_used = true);
