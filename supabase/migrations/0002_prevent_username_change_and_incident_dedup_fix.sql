-- ============================================================
-- Correções descobertas ao comparar com o projeto real em produção
-- (Lovable Cloud "Vigilância Sampa"), via consulta ao Lovable AI:
--
--   1) A dedup de asn_incidents em produção NÃO considera `status` —
--      só (asn, hora-do-created_at, signals). O índice criado em
--      0001 incluía `status`, o que é mais permissivo que o real.
--      Substituído por incident_dedup_key(), que replica o
--      comportamento confirmado da produção.
--   2) prevent_username_change: trigger real de produção que faltava
--      — impede update de profiles.username exceto por master_admin.
--   3) `user_permissions`: tabela confirmada como resquício morto
--      (zero referências no código, zero linhas) — decisão consciente
--      de NÃO recriar.
-- ============================================================

drop index if exists public.asn_incidents_dedup_idx;

-- Nota: diferente do wrapper plpgsql usado em 0001 pra date_trunc/
-- array_to_string, aqui a função é "language sql" mas com
-- "set search_path = public" — essa cláusula SET também impede o
-- planejador de inlinear a função (mesmo efeito prático do plpgsql
-- opaco), e é o padrão que a produção real já usava.
create or replace function public.incident_dedup_key(p_created_at timestamptz, p_signals text[])
returns text
language sql
immutable
set search_path = public
as $$
  select md5(date_trunc('hour', p_created_at)::text || '|' || array_to_string(p_signals, '||'))
$$;

create unique index idx_asn_incidents_dedup
  on public.asn_incidents (asn, incident_dedup_key(created_at, signals));

-- Wrappers de 0001 não são mais necessários (só existiam pro índice antigo)
drop function if exists public.immutable_date_trunc(text, timestamptz);
drop function if exists public.immutable_array_to_string(text[], text);

create or replace function public.prevent_username_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.username is distinct from old.username then
    if not public.is_master_admin() then
      raise exception 'Username changes are not allowed';
    end if;
  end if;
  return new;
end;
$$;

create trigger prevent_username_change_trigger
  before update on public.profiles
  for each row execute function public.prevent_username_change();
