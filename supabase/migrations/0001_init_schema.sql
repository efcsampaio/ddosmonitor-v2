-- ============================================================
-- ASN Monitor — schema inicial (projeto Supabase novo)
-- Já incorpora as correções de segurança identificadas no projeto antigo:
--   1) Admin master deixa de ser detectado por username === 'edson'
--      e passa a ser um role ('master_admin') em user_roles,
--      checado via função SECURITY DEFINER (evita recursão de RLS).
--   2) Reset de senha deixa de usar senha fixa — o backend gera uma
--      senha temporária aleatória a cada reset (ver index.ts atualizado).
--   3) RLS habilitado em todas as tabelas, com policies explícitas.
-- ============================================================

-- ── Roles ──
-- 'master_admin' é o superusuário (era hardcoded como username === 'edson'
-- no código antigo). 'admin' / 'moderator' / 'user' são os níveis de acesso
-- normais, atribuíveis pela tela de Gestão de Usuários — mesmos valores já
-- usados no frontend (UserManagement.tsx / usePermissions.ts).
create type public.app_role as enum ('master_admin', 'admin', 'moderator', 'user');

create table public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  role public.app_role not null,
  created_at timestamptz not null default now(),
  -- Um usuário tem no máximo UMA role (nunca 'master_admin' + 'admin' ao
  -- mesmo tempo) — o frontend (usePermissions.ts) conta com isso ao usar
  -- .maybeSingle() na consulta de user_roles.
  unique (user_id)
);

alter table public.user_roles enable row level security;

-- Função SECURITY DEFINER: checar role sem cair em recursão de RLS
create or replace function public.has_role(_user_id uuid, _role public.app_role)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.user_roles
    where user_id = _user_id and role = _role
  )
$$;

-- RPC usada pelo frontend (src/hooks/usePermissions.ts, via supabase.rpc
-- ("is_master_admin")) — não recebe argumentos, resolve o usuário atual
-- através de auth.uid() dentro da própria função.
create or replace function public.is_master_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.has_role(auth.uid(), 'master_admin');
$$;

create policy "Usuário vê seus próprios roles"
  on public.user_roles for select
  using (auth.uid() = user_id);

create policy "Master admin gerencia todos os roles"
  on public.user_roles for all
  using (public.has_role(auth.uid(), 'master_admin'))
  with check (public.has_role(auth.uid(), 'master_admin'));

-- ── Profiles (1:1 com auth.users) ──
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  display_name text,
  must_change_password boolean not null default false,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "Usuário vê o próprio perfil"
  on public.profiles for select
  using (auth.uid() = id);

create policy "Usuário atualiza o próprio perfil"
  on public.profiles for update
  using (auth.uid() = id);

create policy "Master admin vê todos os perfis"
  on public.profiles for select
  using (public.has_role(auth.uid(), 'master_admin'));

create policy "Master admin atualiza qualquer perfil"
  on public.profiles for update
  using (public.has_role(auth.uid(), 'master_admin'));

-- Cria o profile automaticamente quando um usuário é criado via Admin API
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, username, display_name, must_change_password)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'username', split_part(new.email, '@', 1)),
    coalesce(new.raw_user_meta_data->>'display_name', new.raw_user_meta_data->>'username'),
    coalesce((new.raw_user_meta_data->>'must_change_password')::boolean, false)
  );
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ── Monitored ASNs (por usuário) ──
create table public.monitored_asns (
  id uuid primary key default gen_random_uuid(),
  asn text not null,
  name text,
  user_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  unique (asn, user_id)
);

alter table public.monitored_asns enable row level security;

create policy "Usuário gerencia seus ASNs monitorados"
  on public.monitored_asns for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Master admin vê todos os ASNs monitorados"
  on public.monitored_asns for select
  using (public.has_role(auth.uid(), 'master_admin'));

-- ── Telegram — configuração por usuário e histórico de alertas ──
create table public.telegram_config (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  chat_id text not null,
  enabled boolean not null default true,
  notify_attacks boolean not null default true,
  notify_warnings boolean not null default true,
  notify_recovery boolean not null default true,
  created_at timestamptz not null default now(),
  unique (user_id, chat_id)
);

alter table public.telegram_config enable row level security;

create policy "Usuário gerencia sua própria config de Telegram"
  on public.telegram_config for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Sem policy de SELECT para outros usuários — notifyAllUsersForAsn no
-- telegram-notify usa o service role (bypassa RLS) para ler configs de
-- todos os usuários que monitoram um ASN.

create table public.alerts_history (
  id uuid primary key default gen_random_uuid(),
  asn text not null,
  risk_score numeric,
  risk_label text,
  sources jsonb not null default '{}',
  ti_summary text,
  alerted_at timestamptz not null default now()
);

create index alerts_history_alerted_at_idx on public.alerts_history (alerted_at desc);
create index alerts_history_asn_idx on public.alerts_history (asn);

alter table public.alerts_history enable row level security;

create policy "Usuários autenticados leem histórico de alertas"
  on public.alerts_history for select
  to authenticated
  using (true);

-- Nenhuma policy de INSERT — só o service role (Edge Functions) grava.

-- ── Threat Intelligence (AbuseIPDB / GreyNoise) e estado de alerta ──
-- Estrutura confirmada por enrich-ip-reputation: UMA linha por IP (upsert
-- onConflict:"ip"), com os campos do AbuseIPDB e do GreyNoise juntos na
-- mesma linha — não é uma linha por (ip, source).
create table public.ip_reputation (
  ip text primary key,
  source text not null default 'abuseipdb',
  reputation_score numeric,
  reports_count integer not null default 0,
  last_seen_at timestamptz,
  last_checked_at timestamptz,
  gn_noise boolean,
  gn_riot boolean,
  gn_classification text,
  gn_last_checked timestamptz,
  created_at timestamptz not null default now()
);

create index ip_reputation_score_idx on public.ip_reputation (reputation_score desc);

alter table public.ip_reputation enable row level security;

create policy "Usuários autenticados leem reputação de IP"
  on public.ip_reputation for select
  to authenticated
  using (true);

-- Agregados por ASN/janela de tempo, usados tanto pelo scoring quanto
-- (provavelmente) pela aba "Inteligência de Ameaças" no frontend.
-- Constraint composta necessária para o upsert onConflict de
-- enrich-ip-reputation: (asn, window_start, window_end, source).
create table public.asn_ip_reputation_window (
  id uuid primary key default gen_random_uuid(),
  asn text not null,
  source text not null,
  window_start timestamptz not null,
  window_end timestamptz not null,
  ips_total integer not null default 0,
  ips_with_score integer not null default 0,
  high_score_ips integer not null default 0,
  avg_score numeric,
  gn_noise_ratio numeric,
  gn_malicious_ratio numeric,
  gn_riot_ratio numeric,
  created_at timestamptz not null default now(),
  unique (asn, window_start, window_end, source)
);

create index asn_ip_reputation_window_asn_idx on public.asn_ip_reputation_window (asn, window_start);

alter table public.asn_ip_reputation_window enable row level security;

create policy "Usuários autenticados leem janelas de reputação"
  on public.asn_ip_reputation_window for select
  to authenticated
  using (true);

-- Estado interno de cooldown dos alertas de risco HIGH — não é dado de
-- dashboard, só as Edge Functions (service role) leem/escrevem aqui.
create table public.asn_alert_state (
  asn text primary key,
  last_alert_at timestamptz,
  last_risk_score numeric,
  last_risk_label text,
  updated_at timestamptz not null default now()
);

alter table public.asn_alert_state enable row level security;
-- Sem nenhuma policy de propósito: só o service role acessa esta tabela.

-- ── Dataset de treino do modelo de risco (v_training_dataset) ──
-- Definição confirmada pelo usuário a partir do projeto antigo. A tabela
-- as_attack_samples é populada pela Edge Function generate-dataset —
-- unique(asn, "timestamp") CONFIRMADO pelo upsert onConflict:"asn,timestamp"
-- usado lá (não é mais suposição).
create table public.as_attack_samples (
  id uuid primary key default gen_random_uuid(),
  asn text not null,
  "timestamp" timestamptz not null,
  wanguard_attack_count_30m integer not null default 0,
  wanguard_max_bps_30m numeric,
  wanguard_max_pps_30m numeric,
  wanguard_severity_class text, -- 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH'
  wanguard_is_under_attack boolean not null default false,
  external_anomalies_count_30m integer not null default 0,
  external_strong_anomalies_count_30m integer not null default 0,
  qrator_events_count_30m integer not null default 0,
  rpki_events_count_30m integer not null default 0,
  ripestat_events_count_30m integer not null default 0,
  bgp_events_count_30m integer not null default 0,
  ripe_events_count_30m integer not null default 0,
  ti_ips_total integer not null default 0,
  ti_abuse_avg_score numeric,
  ti_abuse_high_ratio numeric,
  gn_noise_ratio numeric,
  gn_malicious_ratio numeric,
  gn_riot_ratio numeric,
  ti_combined_score numeric,
  created_at timestamptz not null default now(),
  unique (asn, "timestamp")
);

create index as_attack_samples_asn_idx on public.as_attack_samples (asn, "timestamp");

-- Confirmado por useWanguardAttacks.ts: o frontend lê essa tabela
-- diretamente (correlação de "possível ataque" no WanguardTab), então
-- precisa de leitura liberada pra autenticados — não é só uso interno do
-- service role como pensado inicialmente.
alter table public.as_attack_samples enable row level security;

create policy "Usuários autenticados leem amostras de treino"
  on public.as_attack_samples for select
  to authenticated
  using (true);

create view public.v_training_dataset as
select
  asn,
  "timestamp",
  wanguard_attack_count_30m,
  wanguard_max_bps_30m,
  wanguard_severity_class,
  external_anomalies_count_30m,
  external_strong_anomalies_count_30m,
  external_strong_anomalies_count_30m as strong_count,
  qrator_events_count_30m,
  qrator_events_count_30m as qrator_count,
  rpki_events_count_30m,
  rpki_events_count_30m as rpki_count,
  ripestat_events_count_30m,
  ripestat_events_count_30m as ripestat_count,
  bgp_events_count_30m,
  bgp_events_count_30m as bgp_count,
  ripe_events_count_30m,
  external_strong_anomalies_count_30m > 0 as has_strong_external,
  qrator_events_count_30m > 0 as has_qrator,
  ripe_events_count_30m > 0 as has_ripe,
  rpki_events_count_30m > 0 as has_rpki,
  ripestat_events_count_30m > 0 as has_ripestat,
  bgp_events_count_30m > 0 as has_bgp,
  (
    case when qrator_events_count_30m > 0 then 1 else 0 end +
    case when rpki_events_count_30m > 0 then 1 else 0 end +
    case when ripestat_events_count_30m > 0 then 1 else 0 end +
    case when bgp_events_count_30m > 0 then 1 else 0 end
  ) >= 2 as has_combo_strong,
  wanguard_is_under_attack = true
    and wanguard_severity_class = any (array['MEDIUM'::text, 'HIGH'::text]) as is_attack,
  ti_ips_total,
  ti_abuse_avg_score,
  ti_abuse_high_ratio,
  gn_noise_ratio,
  gn_malicious_ratio,
  gn_riot_ratio,
  ti_combined_score
from public.as_attack_samples;

-- ── Incidentes ──
create table public.asn_incidents (
  id uuid primary key default gen_random_uuid(),
  asn text not null,
  name text,
  status text not null check (status in ('HEALTHY', 'WARNING', 'UNDER_ATTACK')),
  signals text[] not null default '{}',
  visibility_percent numeric,
  packet_loss_percent numeric,
  bgp_state text,
  withdrawals integer default 0,
  announcements integer default 0,
  created_at timestamptz not null default now()
);

-- date_trunc(text, timestamptz) é STABLE no Postgres (depende do TimeZone da
-- sessão), não IMMUTABLE — por isso não pode ser usado direto numa expressão
-- de índice (erro 42P17). Este wrapper força a declaração IMMUTABLE.
-- IMPORTANTE: precisa ser "language plpgsql", não "language sql" — funções
-- SQL simples são desmontadas ("inlined") pelo planejador, que aí enxerga o
-- date_trunc original por baixo e rejeita de novo. plpgsql é opaco pro
-- planejador, então a declaração immutable é respeitada.
create or replace function public.immutable_date_trunc(field text, ts timestamptz)
returns timestamptz
language plpgsql
immutable
as $$
begin
  return date_trunc(field, ts);
end;
$$;

-- array_to_string(anyarray, text) também é STABLE (não IMMUTABLE) no
-- Postgres — mesmo problema do date_trunc acima, mesmo wrapper opaco.
create or replace function public.immutable_array_to_string(arr text[], sep text)
returns text
language plpgsql
immutable
as $$
begin
  return array_to_string(arr, sep);
end;
$$;

-- Dedup: no máximo 1 incidente por ASN/status/conjunto-de-sinais por hora
create unique index asn_incidents_dedup_idx
  on public.asn_incidents (asn, status, (public.immutable_array_to_string(signals, '|')), (public.immutable_date_trunc('hour', created_at)));

create index asn_incidents_created_at_idx on public.asn_incidents (created_at desc);
create index asn_incidents_asn_idx on public.asn_incidents (asn);

alter table public.asn_incidents enable row level security;

-- Leitura liberada para qualquer usuário autenticado (dashboard precisa disso)
create policy "Usuários autenticados leem incidentes"
  on public.asn_incidents for select
  to authenticated
  using (true);

-- Nenhuma policy de INSERT/UPDATE/DELETE para usuários — só o service role
-- (usado pelas Edge Functions) grava incidentes, o que já contorna RLS.

-- ============================================================
-- Passo manual após aplicar esta migration:
--   1. Crie seu usuário normalmente pelo fluxo de auth (ou Admin API).
--   2. Rode manualmente:
--        insert into public.user_roles (user_id, role)
--        values ('<seu-user-id>', 'master_admin');
--      para virar o primeiro master admin (não existe bootstrap automático
--      de propósito — evita qualquer admin "hardcoded" no código).
-- ============================================================
