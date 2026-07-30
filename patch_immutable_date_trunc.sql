-- Patch v2: a versão "language sql" foi desmontada (inlined) pelo
-- planejador do Postgres, que voltou a ver o date_trunc original (STABLE)
-- e rejeitou o índice de novo. Troquei para "language plpgsql", que o
-- planejador trata como caixa-preta e não desmonta.
--
-- Rode isso se a tabela asn_incidents já existe mas o índice de dedup
-- falhou com o erro 42P17 (mesmo depois do patch anterior).

drop function if exists public.immutable_date_trunc(text, timestamptz);

create or replace function public.immutable_date_trunc(field text, ts timestamptz)
returns timestamptz
language plpgsql
immutable
as $$
begin
  return date_trunc(field, ts);
end;
$$;

create unique index if not exists asn_incidents_dedup_idx
  on public.asn_incidents (asn, status, (array_to_string(signals, '|')), (public.immutable_date_trunc('hour', created_at)));
