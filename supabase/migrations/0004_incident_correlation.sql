-- ============================================================
-- Correlação entre ataques nos ASNs próprios da K2 (AS267458, AS266953)
-- e incidentes BGP nos ASNs concorrentes monitorados — usado pela UI
-- pra distinguir "ataque isolado" (possível alvo direto) de "evento
-- correlacionado" (padrão regional afetando vários ASNs brasileiros).
--
-- Por que não usar o status de asn_incidents (WARNING/UNDER_ATTACK)
-- direto: WARNING é ruído rotineiro de BGP, acontece o tempo todo em
-- qualquer ASN — correlacionar nisso dá falso positivo sempre (testado
-- com dados reais: 100% dos incidentes das últimas 24h apareciam como
-- "correlacionados" com essa abordagem ingênua). A base real precisa
-- ser o episódio de ataque CONFIRMADO pelo Wanguard
-- (as_attack_samples.wanguard_is_under_attack), e a correlação exige
-- pelo menos 2 concorrentes distintos com incidente na mesma janela —
-- um só concorrente com ruído normal não conta.
-- ============================================================

create or replace function public.is_own_asn(p_asn text)
returns boolean
language sql
immutable
set search_path = public
as $$
  select p_asn in ('AS267458', 'AS266953')
$$;

-- Agrupa amostras contíguas de 5min sob ataque (gap > 5min quebra o
-- episódio) em episódios por ASN próprio.
create or replace view public.v_own_attack_episodes
with (security_invoker = true) as
with attack_samples as (
  select
    asn,
    "timestamp",
    wanguard_max_bps_30m,
    wanguard_max_pps_30m,
    "timestamp" - (
      row_number() over (partition by asn order by "timestamp") * interval '5 minutes'
    ) as grp
  from public.as_attack_samples
  where wanguard_is_under_attack = true
    and public.is_own_asn(asn)
)
select
  asn,
  min("timestamp") as start_time,
  max("timestamp") as end_time,
  max(wanguard_max_bps_30m) as peak_bps,
  max(wanguard_max_pps_30m) as peak_pps,
  count(*) as sample_count
from attack_samples
group by asn, grp;

create or replace view public.v_incident_correlation
with (security_invoker = true) as
select
  ep.asn,
  ep.start_time,
  ep.end_time,
  ep.peak_bps,
  ep.peak_pps,
  ep.sample_count,
  coalesce(comp.competitor_count, 0) >= 2 as correlated,
  coalesce(comp.competitor_asns, array[]::text[]) as correlated_with
from public.v_own_attack_episodes ep
left join lateral (
  select
    count(distinct c.asn) as competitor_count,
    array_agg(distinct c.asn) as competitor_asns
  from public.asn_incidents c
  where not public.is_own_asn(c.asn)
    and c.status in ('WARNING', 'UNDER_ATTACK')
    and c.created_at between ep.start_time - interval '20 minutes' and ep.end_time + interval '20 minutes'
) comp on true
order by ep.start_time desc;
