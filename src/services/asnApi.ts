// Dados de monitoramento ASN via RIPEstat
import { supabase } from "@/integrations/supabase/client";

export type BgpState = "STABLE" | "FLAPPING" | "WITHDRAWN";
export type AsnStatus = "HEALTHY" | "WARNING" | "UNDER_ATTACK";

export interface AsnNeighbour {
  asn: number;
  name: string;
  type: "upstream" | "peer" | "downstream";
}

export interface BgpVisibility {
  v4Percent: number;
  v6Percent: number;
  totalPercent: number;
}

export interface SecurityAlert {
  type: "hijack" | "route_leak" | "path_anomaly";
  severity: "critical" | "warning" | "info";
  description: string;
  details?: string;
}

export interface AsnMetrics {
  asn: string;
  name: string;
  status: AsnStatus;
  latency: { avgMs: number; minMs: number; maxMs: number };
  packetLossPercent: number;
  bgp: { state: BgpState; lastChange: string };
  bgpVisibility: BgpVisibility;
  bgpUpdates?: { announcements: number; withdrawals: number; period: string };
  neighbours: { list: AsnNeighbour[]; total: number; upstreams: number; downstreams: number; peers: number };
  prefixCount: number;
  prefixes: string[];
  lastUpdated: string;
  dataSource?: "ripestat" | "simulated";
  detectionSignals?: string[];
  securityAlerts?: SecurityAlert[];
  attackScope?: AttackScope;
}

// ── Attack scope correlation ("blast radius") ──
export type AttackScopeLevel = "LOCALIZADO" | "MULTI_PROVEDOR" | "AMPLO";

export interface AffectedAsnInfo {
  asn: string;
  name: string;
  status: string;
  detectedAt: string;
}

export interface AffectedBlockInfo {
  prefix: string;
  bps?: number;
  pps?: number;
}

export interface AttackScope {
  level: AttackScopeLevel;
  windowMinutes: number;
  affectedAsns: AffectedAsnInfo[];
  affectedRatio: number;
  totalMonitored: number;
  sharedUpstream: { asn: number; name: string }[] | null;
  ownBlocksUnderAttack: AffectedBlockInfo[];
}

async function getAuthHeaders(): Promise<Record<string, string>> {
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
  const anonKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
  const headers: Record<string, string> = { "apikey": anonKey };
  const { data: { session } } = await supabase.auth.getSession();
  if (session?.access_token) {
    headers["authorization"] = `Bearer ${session.access_token}`;
  }
  return headers;
}

export async function fetchAsnStatus(): Promise<AsnMetrics[]> {
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
  const headers = await getAuthHeaders();
  const response = await fetch(`${supabaseUrl}/functions/v1/asn-monitor/status`, { headers });
  if (!response.ok) throw new Error(`Erro ao buscar status: ${response.status}`);
  return response.json();
}

/**
 * Busca status de ASNs específicos (sem filtro por user_id).
 * Usado para a aba Concorrentes com ASNs fixos.
 */
export async function fetchAsnStatusByList(asns: string[]): Promise<AsnMetrics[]> {
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
  const headers = await getAuthHeaders();
  const param = asns.join(",");
  const response = await fetch(`${supabaseUrl}/functions/v1/asn-monitor/status?asns=${encodeURIComponent(param)}`, { headers });
  if (!response.ok) throw new Error(`Erro ao buscar status dos concorrentes: ${response.status}`);
  return response.json();
}

/**
 * Busca sob demanda a correlação de escopo do ataque ("blast radius") para um ASN.
 * Normalmente não é necessário chamar diretamente: o campo attackScope já vem
 * embutido em AsnMetrics quando o status não é HEALTHY.
 */
export async function fetchAttackScope(asn: string): Promise<AttackScope | null> {
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
  const headers = await getAuthHeaders();
  const response = await fetch(`${supabaseUrl}/functions/v1/asn-monitor/attack-scope/${encodeURIComponent(asn)}`, { headers });
  if (!response.ok) return null;
  return response.json();
}

export async function simularAtaqueAPI(asn: string): Promise<void> {
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
  const headers = await getAuthHeaders();
  const response = await fetch(`${supabaseUrl}/functions/v1/asn-monitor/simulate-attack/${asn}`, { method: "POST", headers: { ...headers, "Content-Type": "application/json" } });
  if (!response.ok) throw new Error("Falha ao simular ataque");
}

export async function adicionarAsnAPI(asn: string): Promise<void> {
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
  const headers = await getAuthHeaders();
  const response = await fetch(`${supabaseUrl}/functions/v1/asn-monitor/add-asn`, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify({ asn }) });
  if (!response.ok) { const data = await response.json().catch(() => ({})); throw new Error(data.error || "Falha ao adicionar ASN"); }
}

export async function removerAsnAPI(asn: string): Promise<void> {
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
  const headers = await getAuthHeaders();
  const response = await fetch(`${supabaseUrl}/functions/v1/asn-monitor/remove-asn/${asn}`, { method: "DELETE", headers });
  if (!response.ok) throw new Error("Falha ao remover ASN");
}

export interface IncidentRanking {
  asn: string;
  name: string;
  totalIncidents: number;
  attacks: number;
  warnings: number;
  avgPacketLoss: number;
  avgVisibility: number;
  totalWithdrawals: number;
  lastIncident: string;
  score: number;
}

export async function fetchIncidentRanking(hours = 720): Promise<IncidentRanking[]> {
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
  const headers = await getAuthHeaders();
  const response = await fetch(`${supabaseUrl}/functions/v1/asn-monitor/incidents/ranking?hours=${hours}`, { headers });
  if (!response.ok) throw new Error("Falha ao buscar ranking");
  return response.json();
}

export interface Incident {
  id: string;
  asn: string;
  name: string;
  status: string;
  signals: string[];
  visibility_percent: number | null;
  packet_loss_percent: number | null;
  bgp_state: string | null;
  withdrawals: number;
  announcements: number;
  created_at: string;
}

export async function fetchIncidents(params?: { asn?: string; days?: number }): Promise<Incident[]> {
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
  const headers = await getAuthHeaders();
  const searchParams = new URLSearchParams();
  if (params?.days) searchParams.set("days", String(params.days));
  if (params?.asn) searchParams.set("asn", params.asn);
  const response = await fetch(`${supabaseUrl}/functions/v1/asn-monitor/incidents?${searchParams}`, { headers });
  if (!response.ok) throw new Error("Falha ao buscar incidentes");
  return response.json();
}

export async function fetchIncidentCount(days = 365): Promise<number> {
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
  const headers = await getAuthHeaders();
  const response = await fetch(`${supabaseUrl}/functions/v1/asn-monitor/incidents/count?days=${days}`, { headers });
  if (!response.ok) throw new Error("Falha ao buscar contagem");
  const data = await response.json();
  return data.count || 0;
}
