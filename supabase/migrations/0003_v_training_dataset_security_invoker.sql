-- ============================================================
-- v_training_dataset rodava com os privilégios do dono da view
-- (comportamento padrão de views no Postgres, equivalente a
-- SECURITY DEFINER na prática), o que faz a checagem de RLS da
-- tabela base (as_attack_samples) rodar no contexto do dono da view
-- em vez de quem está consultando. Como o dono normalmente é uma
-- role que bypassa RLS (ex: postgres), a policy da tabela base podia
-- ser ignorada na prática — mesmo não havendo impacto observável hoje
-- (a policy de as_attack_samples já libera SELECT para todo
-- autenticado com "using (true)"), é o comportamento correto e o que
-- o linter de segurança do Supabase recomenda.
-- ============================================================

alter view public.v_training_dataset set (security_invoker = true);
