# Monitor DDoS — contexto do projeto

App de monitoramento de ASNs / detecção de DDoS pra K2 Network (frontend
React/Vite/shadcn + backend Supabase Edge Functions em Deno). Monitora o
ASN da própria K2 (AS267458, mais AS266953 = Argo Telecom) e 3 ASNs
concorrentes fixos (AS268538 Conecta Network, AS267530 TJ Telecom,
AS268726 TOPNET).

## Histórico e decisão de arquitetura

Existia um repo antigo (`github.com/efcsampaio/ddosmonitor`, privado) com
vários problemas de segurança. Em vez de corrigir em cima do projeto
antigo, a decisão foi recomeçar num projeto Supabase NOVO, já com as
correções aplicadas desde o início. Este diretório contém tudo que foi
revisado/corrigido até agora numa sessão de chat anterior (não neste
Claude Code) — os arquivos aqui são o ponto de partida, não um repo
completo. Ainda faltam vários arquivos do app original que nunca foram
enviados para revisão (páginas, componentes menores, utils).

## Três correções de segurança sistêmicas (aplicadas em toda function)

1. **CORS aberto (`Access-Control-Allow-Origin: "*"`)** → trocado por
   `ALLOWED_ORIGINS` (env var, lista separada por vírgula) +
   `buildCorsHeaders(origin)` calculado por request. Mesmo padrão
   copiado em todas as Edge Functions.
2. **Admin master hardcoded como `username === "edson"`** (existia em
   asn-monitor, UserManagement.tsx, usePermissions.ts,
   telegram-hourly-ranking) → substituído por uma role `master_admin`
   na tabela `user_roles`, checada via `has_role()` / `is_master_admin()`
   (funções SQL SECURITY DEFINER). O frontend (`usePermissions.ts`) já
   esperava um RPC `is_master_admin()`, confirmando que esse era o
   design pretendido.
3. **Reset de senha com senha fixa (`"Monitor@2026!"`)** → agora gera
   senha aleatória a cada reset (`generateTempPassword()`), mostrada
   uma vez ao admin.

## Schema (supabase/migrations/0001_init_schema.sql)

Tabelas (todas com RLS): `user_roles`, `profiles`, `monitored_asns`,
`telegram_config`, `alerts_history` (coluna `alerted_at`, não
`created_at`), `ip_reputation` (PK é só `ip`, uma linha por IP
mistura campos AbuseIPDB+GreyNoise), `asn_ip_reputation_window`
(unique asn+window_start+window_end+source), `asn_alert_state`,
`as_attack_samples` (unique asn+timestamp; tem policy de SELECT
autenticado porque o frontend lê direto) + view `v_training_dataset`,
`asn_incidents`.

**Bug já corrigido na migration**: um índice usava
`date_trunc('hour', created_at)` direto, o que dá erro
`42P17: functions in index expression must be marked IMMUTABLE`
(date_trunc com timestamptz é STABLE, não IMMUTABLE). A correção foi
um wrapper `public.immutable_date_trunc()` — **precisa ser
`language plpgsql`, não `language sql`**, porque funções SQL simples
são desmontadas ("inlined") pelo planejador do Postgres, o que faria
ele enxergar o date_trunc original de novo e rejeitar. plpgsql é opaco
pro planejador, então funciona. Ver `patch_immutable_date_trunc.sql`
como referência do que já foi aplicado manualmente no banco (caso a
migration completa precise ser re-rodada do zero, ela já está com a
versão corrigida).

**Status no banco real**: o schema já foi aplicado com sucesso no
projeto Supabase novo ("Monitor DDoS", org efcsampaio's Org). Ainda
faltava, na última atualização: rodar o `insert` manual pra virar
`master_admin`, configurar os secrets, e recriar os cron jobs.

## Edge Functions (9 revisadas, todas em supabase/functions/)

| Function | Auth exigida |
|---|---|
| asn-monitor | role master_admin real para `/admin/*` |
| wanguard-proxy | JWT de usuário real OU service-role (service-role é usado pela chamada interna do próprio asn-monitor) |
| telegram-notify | service-role para `/notify`,`/risk-alert`,`/third-party-alert`; dono do chat_id para `/test` |
| telegram-hourly-ranking | service-role only (cron) |
| estimate-attack-risk | JWT de usuário real |
| enrich-ip-reputation | service-role only (cron, sem chamador conhecido no frontend) |
| generate-dataset | service-role OU usuário real com role admin/moderator/master_admin (o botão "Gerar dataset" do ComparativoK2.tsx chama direto; também roda via cron diário às 03:00 UTC) |
| learning-metrics | JWT de usuário real |

Cron jobs a recriar no projeto novo (mandar
`Authorization: Bearer <service_role_key>` no header do pg_cron):
generate-dataset (diário 03:00 UTC), enrich-ip-reputation (a cada
30min), telegram-hourly-ranking (a cada hora).

## Frontend revisado (todos os arquivos aqui já corrigidos ou confirmados limpos)

Auth/permissões: usePermissions.ts, UserManagement.tsx — corrigidos.
Serviços/hooks: asnApi.ts, wanguardService.ts — corrigidos (usam
`session.access_token` em vez da anon key pra chamar functions que
agora exigem sessão real).
Páginas: ComparativoK2.tsx — corrigido (2 chamadas fetch + removido
hardcode "Bem-vindo, Edson").
Componentes: ASNCard.tsx, ApiStatusMonitor.tsx — corrigidos pelo mesmo
motivo (sessão real em vez de anon key; ApiStatusMonitor também passou
a tratar 401/403 como "saudável" pra functions que são só-service-role).

**IMPORTANTE**: qualquer arquivo NOVO que chame uma dessas 9 Edge
Functions usando `Authorization: Bearer <anon key>` vai quebrar — elas
agora exigem sessão de usuário real (`session.access_token`) ou, em
alguns casos, a service role key. Ao portar arquivos que ainda não
foram revisados, procurar por esse padrão e corrigir.

## Pendências conhecidas (não é bug, decisão consciente de não mexer)

- `MY_ASNS`/`K2_OWN_ASN` = `[267458, 266953]` está hardcoded e duplicado
  em 3 lugares (telegram-notify, useWanguardAttacks.ts, asn-monitor) —
  é dado de negócio, não falha de segurança.
- O toggle "Recuperação" em TelegramSettings não tem efeito nenhum —
  telegram-notify nunca envia notificação de status HEALTHY. Bug
  pré-existente do app original, não corrigido.

## Arquivos que AINDA faltam revisar (nunca foram enviados nesta análise)

generate-dataset é a única function citada como rodando via cron; ainda
não vimos o código completo de `enrich-ip-reputation`'s caller (se
existe algum), nem qualquer página/componente além dos listados acima.
Praticamente todo o restante do frontend (Index.tsx e outros
componentes menores podem já ter sido vistos numa sessão anterior —
conferir o resumo acima antes de assumir que algo precisa de revisão).
