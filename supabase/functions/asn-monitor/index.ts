import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const corsHeadersStatic = {
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

// CORS restrito por origem — antes era Access-Control-Allow-Origin: "*" em
// todas as respostas. Configure ALLOWED_ORIGINS como uma lista separada por
// vírgula (ex: "https://app.k2network.com,https://preview.lovable.app").
const ALLOWED_ORIGINS = (Deno.env.get("ALLOWED_ORIGINS") || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

function buildCorsHeaders(origin: string | null): Record<string, string> {
  const allowOrigin = origin && ALLOWED_ORIGINS.includes(origin)
    ? origin
    : (ALLOWED_ORIGINS[0] || "");
  return {
    ...corsHeadersStatic,
    "Access-Control-Allow-Origin": allowOrigin,
    "Vary": "Origin",
  };
}

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabase = createClient(supabaseUrl, supabaseKey);

type BgpState = "STABLE" | "FLAPPING" | "WITHDRAWN";
type AsnStatus = "HEALTHY" | "WARNING" | "UNDER_ATTACK";

interface AsnNeighbour {
  asn: number;
  name: string;
  type: "upstream" | "peer" | "downstream";
}

interface BgpVisibility {
  v4Percent: number;
  v6Percent: number;
  totalPercent: number;
}

interface SecurityAlert {
  type: "hijack" | "route_leak" | "path_anomaly";
  severity: "critical" | "warning" | "info";
  description: string;
  details?: string;
}

// ── Attack scope correlation ("blast radius") ──
type AttackScopeLevel = "LOCALIZADO" | "MULTI_PROVEDOR" | "AMPLO";

interface AffectedAsnInfo {
  asn: string;
  name: string;
  status: string;
  detectedAt: string;
}

interface AffectedBlockInfo {
  prefix: string;
  bps?: number;
  pps?: number;
}

interface AttackScope {
  level: AttackScopeLevel;
  windowMinutes: number;
  affectedAsns: AffectedAsnInfo[];
  affectedRatio: number; // 0-1
  totalMonitored: number;
  sharedUpstream: { asn: number; name: string }[] | null;
  ownBlocksUnderAttack: AffectedBlockInfo[];
}

interface AsnMetrics {
  asn: string;
  name: string;
  status: AsnStatus;
  latency: { avgMs: number; minMs: number; maxMs: number };
  packetLossPercent: number;
  bgp: { state: BgpState; lastChange: string };
  bgpVisibility: BgpVisibility;
  bgpUpdates: { announcements: number; withdrawals: number; period: string };
  neighbours: { list: AsnNeighbour[]; total: number; upstreams: number; downstreams: number; peers: number };
  prefixCount: number;
  prefixes: string[];
  lastUpdated: string;
  dataSource: "ripestat" | "simulated";
  detectionSignals: string[];
  securityAlerts: SecurityAlert[];
  attackScope?: AttackScope;
}

// Custom ASN name overrides (takes precedence over RIPEstat)
const ASN_NAME_OVERRIDES: Record<string, string> = {
  "AS266953": "Argo Telecom",
};

// In-memory state
const asnState: Record<string, AsnMetrics> = {};
const attackFlags: Record<string, boolean> = {};
const asnNames: Record<string, string> = { ...ASN_NAME_OVERRIDES };
const visibilityHistory: Record<string, number[]> = {};
const neighbourHistory: Record<string, number[]> = {};
const prefixHistory: Record<string, number[]> = {};

// Fornecedores de mitigação DDoS da K2 (aparecem como upstream de AS267458).
// Marca mudanças de presença desses ASNs no caminho BGP — não é evidência de
// nada, é só visibilidade adicional pra revisão manual quando o caminho de
// rede muda ao redor de um incidente.
const MITIGATION_VENDOR_ASNS: Record<number, string> = {
  268624: "Gamers Club Ltda (Rocket)",
  273478: "Sage Networks",
};
const vendorNeighbourHistory: Record<string, Set<number>> = {};
// Cache of user ASNs to survive DB outages
const userAsnCache: Record<string, { asns: string[]; ts: number }> = {};
const allAsnsCache: { asns: string[]; ts: number } = { asns: [], ts: 0 };

// Incident insert helper — relies on DB unique index for dedup (1 per ASN per hour per signals)
async function insertIncidentIfNew(data: {
  asn: string; name: string; status: string; signals: string[];
  visibility_percent: number; packet_loss_percent: number;
  bgp_state: string; withdrawals: number; announcements: number;
}) {
  const { error } = await supabase.from("asn_incidents").insert(data);
  // unique constraint violation = duplicate, ignore it
  if (error && error.code !== "23505") {
    console.error("Erro ao salvar incidente:", error);
  }
}

// Telegram notification helper — calls the telegram-notify edge function
const telegramNotifySent: Record<string, number> = {}; // dedup: asn -> timestamp
async function sendTelegramNotification(payload: {
  asn: string; name: string; status: "UNDER_ATTACK" | "WARNING" | "HEALTHY";
  signals: string[]; visibility_percent?: number; packet_loss_percent?: number;
}) {
  // Dedup: don't notify same ASN+status more than once per 10 minutes
  const key = `${payload.asn}:${payload.status}`;
  const now = Date.now();
  if (telegramNotifySent[key] && now - telegramNotifySent[key] < 600_000) return;
  telegramNotifySent[key] = now;

  try {
    const fnUrl = `${supabaseUrl}/functions/v1/telegram-notify/notify`;
    await fetch(fnUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${supabaseKey}`,
      },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error("Failed to call telegram-notify:", err);
  }
}

// ============================================================
// Database helpers
// ============================================================

async function loadMonitoredAsns(userId?: string): Promise<string[]> {
  const cacheKey = userId || "__all__";
  try {
    let query = supabase.from("monitored_asns").select("asn").order("created_at", { ascending: true });
    if (userId) query = query.eq("user_id", userId);
    const { data, error } = await query;
    if (error) throw error;
    const asns = (data || []).map((r: { asn: string }) => r.asn);
    // Update cache on success
    if (userId) {
      userAsnCache[userId] = { asns, ts: Date.now() };
    }
    return asns;
  } catch (err) {
    console.error("Error loading ASNs, using cache:", err);
    // Fall back to cache
    if (userId && userAsnCache[userId]) return userAsnCache[userId].asns;
    // Fall back to in-memory state keys
    return Object.keys(asnState);
  }
}

async function loadAllMonitoredAsns(): Promise<string[]> {
  try {
    const { data, error } = await supabase.from("monitored_asns").select("asn, name").order("created_at", { ascending: true });
    if (error) throw error;
    // Pre-populate name cache from DB
    for (const r of (data || [])) {
      if (r.name && !asnNames[r.asn]) asnNames[r.asn] = r.name;
    }
    const asns = [...new Set((data || []).map((r: { asn: string }) => r.asn))];
    allAsnsCache.asns = asns;
    allAsnsCache.ts = Date.now();
    return asns;
  } catch (err) {
    console.error("Error loading all ASNs, using cache:", err);
    if (allAsnsCache.asns.length > 0) return allAsnsCache.asns;
    return Object.keys(asnState);
  }
}

async function addAsnToDb(asn: string, userId: string): Promise<boolean> {
  const { error } = await supabase.from("monitored_asns").insert({ asn, user_id: userId });
  if (error) { console.error("Error adding ASN:", error); return false; }
  return true;
}

async function removeAsnFromDb(asn: string, userId: string): Promise<boolean> {
  const { error } = await supabase.from("monitored_asns").delete().eq("asn", asn).eq("user_id", userId);
  if (error) { console.error("Error removing ASN:", error); return false; }
  return true;
}

// Extract user ID from JWT
function getUserIdFromRequest(req: Request): string | null {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;
  try {
    const token = authHeader.split(" ")[1];
    const payload = JSON.parse(atob(token.split(".")[1]));
    return payload.sub || null;
  } catch { return null; }
}

// Gera uma senha temporária aleatória para reset de senha administrativo.
// Antes: senha fixa "Monitor@2026!" hardcoded no código.
function generateTempPassword(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let pwd = "";
  for (const b of bytes) pwd += chars[b % chars.length];
  return pwd;
}

// ============================================================
// RIPEstat APIs
// ============================================================

async function fetchAsnName(asn: string): Promise<string> {
  // Always use override if defined
  if (ASN_NAME_OVERRIDES[asn]) return ASN_NAME_OVERRIDES[asn];
  // Return cached name if available
  if (asnNames[asn] && asnNames[asn] !== asn) return asnNames[asn];
  const num = asn.replace("AS", "");
  try {
    const res = await fetch(`https://stat.ripe.net/data/as-overview/data.json?resource=AS${num}`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return asnNames[asn] || asn;
    const data = await res.json();
    const name = data?.data?.holder || asn;
    if (name && name !== asn) {
      asnNames[asn] = name;
      // Persist name to DB (fire and forget)
      supabase.from("monitored_asns").update({ name }).eq("asn", asn).then(({ error }) => {
        if (error) console.error("Error caching ASN name:", error);
      });
    }
    return name;
  } catch { return asnNames[asn] || asn; }
}

interface RipeRoutingStatus {
  visibility: {
    v4: { ris_peers_seeing: number; total_ris_peers: number };
    v6: { ris_peers_seeing: number; total_ris_peers: number };
  };
  announced_space: { v4: { prefixes: number } };
  observed_neighbours: number;
}

async function fetchRoutingStatus(asn: string): Promise<RipeRoutingStatus | null> {
  const num = asn.replace("AS", "");
  try {
    const res = await fetch(`https://stat.ripe.net/data/routing-status/data.json?resource=AS${num}`, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return null;
    return (await res.json()).data as RipeRoutingStatus;
  } catch { return null; }
}

async function fetchAsnNeighbours(asn: string): Promise<AsnNeighbour[]> {
  const num = asn.replace("AS", "");
  try {
    const res = await fetch(`https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS${num}`, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return [];
    const neighbours = (await res.json()).data?.neighbours || [];
    const limited = neighbours.slice(0, 20);
    return await Promise.all(
      limited.map(async (n: { asn: number; type: string }) => ({
        asn: n.asn,
        name: await fetchAsnName(`AS${n.asn}`),
        type: n.type === "left" ? "upstream" as const : n.type === "right" ? "downstream" as const : "peer" as const,
      }))
    );
  } catch { return []; }
}

async function fetchAnnouncedPrefixes(asn: string): Promise<string[]> {
  const num = asn.replace("AS", "");
  try {
    const res = await fetch(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${num}`, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return [];
    return ((await res.json()).data?.prefixes || [])
      .map((p: { prefix: string }) => p.prefix)
      .filter((p: string) => !p.includes(":"));
  } catch { return []; }
}

async function fetchBgpUpdates(asn: string): Promise<{ announcements: number; withdrawals: number }> {
  const num = asn.replace("AS", "");
  const now = new Date();
  const ago = new Date(now.getTime() - 30 * 60000);
  const fmt = (d: Date) => d.toISOString().replace(/\.\d+Z$/, "");
  try {
    const res = await fetch(
      `https://stat.ripe.net/data/bgp-updates/data.json?resource=AS${num}&starttime=${fmt(ago)}&endtime=${fmt(now)}`,
      { signal: AbortSignal.timeout(10000) }
    );
    if (!res.ok) return { announcements: 0, withdrawals: 0 };
    const updates = (await res.json()).data?.updates || [];
    let announcements = 0, withdrawals = 0;
    for (const u of updates) {
      if (u.type === "A") announcements++;
      else if (u.type === "W") withdrawals++;
    }
    return { announcements, withdrawals };
  } catch { return { announcements: 0, withdrawals: 0 }; }
}

// ============================================================
// Qrator Radar — AS Paths analysis
// ============================================================

const QRATOR_API_KEY = Deno.env.get("QRATOR_API_KEY") || "";
const RIPE_ATLAS_API_KEY = Deno.env.get("RIPE_ATLAS_API_KEY") || "";

async function fetchQratorPaths(asn: string, prefixes: string[]): Promise<SecurityAlert[]> {
  if (!QRATOR_API_KEY || prefixes.length === 0) return [];
  const alerts: SecurityAlert[] = [];
  const num = parseInt(asn.replace("AS", ""), 10);
  const toCheck = prefixes.slice(0, 3);

  for (const prefix of toCheck) {
    try {
      const res = await fetch(
        `https://api.radar.qrator.net/v1/paths/${num}?prefix=${encodeURIComponent(prefix)}`,
        { headers: { "X-Qrator-Auth": QRATOR_API_KEY }, signal: AbortSignal.timeout(8000) }
      );
      if (!res.ok) continue;
      const json = await res.json();
      if (json?.meta?.status !== "success") continue;

      const origins = json.data?.[prefix] || [];
      if (origins.length === 0) continue;

      // Qrator returns origin ASNs for the prefix — deduplicate and detect hijacks
      const uniqueOrigins = [...new Set(origins.map((o: string) => parseInt(o, 10)).filter(Boolean))];

      // Check for unexpected origins (not our ASN)
      const foreignOrigins = uniqueOrigins.filter((o: number) => o !== num);
      if (foreignOrigins.length > 0) {
        alerts.push({
          type: "hijack",
          severity: "critical",
          description: `Possível hijack: prefixo ${prefix} também originado por AS${foreignOrigins.join(", AS")}`,
          details: `Esperado apenas AS${num}, mas Qrator detectou origens: ${uniqueOrigins.join(", ")}`,
        });
      }

      // Multiple unique origins = MOAS conflict
      if (uniqueOrigins.length > 1) {
        alerts.push({
          type: "route_leak",
          severity: "warning",
          description: `MOAS detectado: ${prefix} com ${uniqueOrigins.length} origens (${uniqueOrigins.join(", ")})`,
          details: `Qrator Radar detectou múltiplas origens para este prefixo`,
        });
      }

      // Single correct origin = add positive info signal
      if (uniqueOrigins.length === 1 && uniqueOrigins[0] === num) {
        alerts.push({
          type: "path_anomaly",
          severity: "info",
          description: `Qrator: ${prefix} — origem AS${num} verificada ✓`,
        });
      }
    } catch (e) {
      console.error(`Qrator paths error for ${prefix}:`, e);
    }
  }
  return alerts;
}

// ============================================================
// RIPEstat — Route Origin Validation (RPKI + RIS)
// ============================================================

async function fetchRouteOriginValidation(asn: string, prefixes: string[]): Promise<SecurityAlert[]> {
  if (prefixes.length === 0) return [];
  const alerts: SecurityAlert[] = [];
  // Only check 2 prefixes to avoid timeouts
  const toCheck = prefixes.slice(0, 2);

  // Run all RPKI checks in parallel with generous timeout
  const results = await Promise.allSettled(
    toCheck.map(async (prefix) => {
      const res = await fetch(
        `https://stat.ripe.net/data/rpki-validation/data.json?resource=${asn}&prefix=${encodeURIComponent(prefix)}`,
        { signal: AbortSignal.timeout(15000) }
      );
      if (!res.ok) return null;
      const json = await res.json();
      return { prefix, status: json?.data?.status };
    })
  );

  for (const r of results) {
    if (r.status === "fulfilled" && r.value) {
      if (r.value.status === "invalid") {
        alerts.push({
          type: "hijack",
          severity: "critical",
          description: `RPKI Inválido: prefixo ${r.value.prefix} falhou na validação de origem`,
          details: `Validação RPKI retornou status "invalid" para ${asn} → ${r.value.prefix}`,
        });
      } else if (r.value.status === "valid") {
        alerts.push({
          type: "path_anomaly",
          severity: "info",
          description: `RPKI Válido: ${r.value.prefix} — origem verificada ✓`,
        });
      } else if (r.value.status === "unknown" || r.value.status === "not-found") {
        alerts.push({
          type: "path_anomaly",
          severity: "warning",
          description: `RPKI não configurado para ${r.value.prefix} — sem proteção ROA`,
        });
      }
    }
  }

  // Check for route leaks via BGP looking glass
  try {
    const num = asn.replace("AS", "");
    const res = await fetch(
      `https://stat.ripe.net/data/looking-glass/data.json?resource=AS${num}`,
      { signal: AbortSignal.timeout(15000) }
    );
    if (res.ok) {
      const json = await res.json();
      const rrcs = json?.data?.rrcs || [];
      // Detect suspicious patterns: same prefix seen with different origins
      const originMap: Record<string, Set<string>> = {};
      for (const rrc of rrcs) {
        for (const entry of (rrc.entries || [])) {
          const path = entry.as_path || "";
          const hops = path.split(" ").filter(Boolean);
          const origin = hops[hops.length - 1];
          const pfx = entry.prefix || "";
          if (pfx && origin) {
            if (!originMap[pfx]) originMap[pfx] = new Set();
            originMap[pfx].add(origin);
          }
        }
      }
      // Multiple origins for same prefix = possible leak/hijack
      for (const [pfx, origins] of Object.entries(originMap)) {
        if (origins.size > 1) {
          const originList = Array.from(origins).join(", ");
          alerts.push({
            type: "route_leak",
            severity: "warning",
            description: `Múltiplas origens para ${pfx}: AS ${originList}`,
            details: `Possível route leak ou MOAS conflict detectado`,
          });
        }
      }
    }
  } catch (e) {
    console.error(`Looking glass error:`, e);
  }

  return alerts;
}


// ============================================================
// RIPE Atlas — Active Probing (real packet loss & latency)
// ============================================================

interface AtlasProbeResult {
  packetLoss: number;   // 0-100
  avgLatency: number;   // ms
  probeCount: number;
  reachable: boolean;
}

async function fetchAtlasProbe(prefixes: string[]): Promise<AtlasProbeResult | null> {
  if (!RIPE_ATLAS_API_KEY || prefixes.length === 0) return null;
  // Use first prefix as target
  const target = prefixes[0].split("/")[0];
  try {
    // Check for existing measurements targeting this prefix
    const res = await fetch(
      `https://atlas.ripe.net/api/v2/measurements/?target=${encodeURIComponent(target)}&type=ping&status=2&sort=-id&page_size=1`,
      { headers: { "Authorization": `Key ${RIPE_ATLAS_API_KEY}` }, signal: AbortSignal.timeout(8000) }
    );
    if (!res.ok) return null;
    const json = await res.json();
    const measurements = json?.results || [];
    if (measurements.length === 0) return null;

    // Get latest results
    const msmId = measurements[0].id;
    const resultsRes = await fetch(
      `https://atlas.ripe.net/api/v2/measurements/${msmId}/latest/?format=json`,
      { headers: { "Authorization": `Key ${RIPE_ATLAS_API_KEY}` }, signal: AbortSignal.timeout(8000) }
    );
    if (!resultsRes.ok) return null;
    const results = await resultsRes.json();
    if (!Array.isArray(results) || results.length === 0) return null;

    let totalSent = 0, totalReceived = 0, latencySum = 0, latencyCount = 0;
    for (const probe of results.slice(0, 20)) {
      const sent = probe.sent || 0;
      const rcvd = probe.rcvd || 0;
      totalSent += sent;
      totalReceived += rcvd;
      if (probe.avg !== undefined && probe.avg > 0) {
        latencySum += probe.avg;
        latencyCount++;
      }
    }

    const packetLoss = totalSent > 0 ? ((totalSent - totalReceived) / totalSent) * 100 : 0;
    return {
      packetLoss: Math.round(packetLoss * 100) / 100,
      avgLatency: latencyCount > 0 ? Math.round(latencySum / latencyCount) : 0,
      probeCount: results.length,
      reachable: totalReceived > 0,
    };
  } catch (e) {
    console.error("RIPE Atlas probe error:", e);
    return null;
  }
}

function trackHistory(store: Record<string, number[]>, key: string, value: number) {
  if (!store[key]) store[key] = [];
  store[key].push(value);
  if (store[key].length > 30) store[key].shift();
}

function detectAnomaly(history: number[], current: number, thresholdPercent: number): boolean {
  if (history.length < 2) return false; // reduced from 3 to 2 for faster detection
  const avg = history.slice(0, -1).reduce((a, b) => a + b, 0) / (history.length - 1);
  if (avg === 0) return current === 0 ? false : true;
  const change = ((avg - current) / avg) * 100;
  return change > thresholdPercent;
}

// Detect rapid changes between last 2 readings
function detectRapidChange(history: number[], thresholdPercent: number): boolean {
  if (history.length < 2) return false;
  const prev = history[history.length - 2];
  const curr = history[history.length - 1];
  if (prev === 0) return curr === 0 ? false : true;
  const change = Math.abs((prev - curr) / prev) * 100;
  return change > thresholdPercent;
}

function determineBgpState(ann: number, wdr: number, visRatio: number): BgpState {
  if (visRatio < 0.5) return "WITHDRAWN";
  if (ann + wdr > 100 || wdr > 30) return "FLAPPING"; // lowered from 200/50
  return "STABLE";
}

function estimateLatency(visRatio: number, neighbours: number): { avgMs: number; minMs: number; maxMs: number } {
  const base = Math.max(5, Math.round(50 - neighbours * 0.5));
  const factor = visRatio > 0.95 ? 1 : visRatio > 0.8 ? 2 : 4;
  const avg = Math.round(base * factor);
  return { avgMs: avg, minMs: Math.max(2, Math.round(avg * 0.4)), maxMs: Math.round(avg * 2.5) };
}

function estimatePacketLoss(visRatio: number): number {
  if (visRatio >= 0.98) return Math.round(Math.random() * 0.5 * 100) / 100;
  if (visRatio >= 0.9) return Math.round((1 + Math.random() * 4) * 100) / 100;
  if (visRatio >= 0.7) return Math.round((5 + Math.random() * 20) * 100) / 100;
  return Math.round((25 + Math.random() * 50) * 100) / 100;
}

interface DetectionResult {
  status: AsnStatus;
  signals: string[];
}

function detectStatus(
  bgpState: BgpState,
  visRatio: number,
  bgpUpdates: { announcements: number; withdrawals: number },
  asn: string,
  atlasProbe: AtlasProbeResult | null
): DetectionResult {
  const signals: string[] = [];
  let score = 0; // multi-signal scoring: >= 5 = UNDER_ATTACK, >= 2 = WARNING

  // Check visibility anomaly (more sensitive: 8% threshold)
  const visAnomaly = detectAnomaly(visibilityHistory[asn] || [], Math.round(visRatio * 100), 8);
  const visRapidDrop = detectRapidChange(visibilityHistory[asn] || [], 5);
  // Check neighbour count drop (more sensitive: 20% threshold)
  const neighAnomaly = detectAnomaly(neighbourHistory[asn] || [], (neighbourHistory[asn] || []).at(-1) || 0, 20);
  // Check prefix count drop
  const prefixAnomaly = detectAnomaly(prefixHistory[asn] || [], (prefixHistory[asn] || []).at(-1) || 0, 20);

  // === CRITICAL: Routes withdrawn ===
  if (bgpState === "WITHDRAWN") {
    signals.push("❌ Rotas BGP retiradas (visibility < 50%)");
    score += 10;
  }

  // === CRITICAL: Major visibility drop (lowered from 70% to 60%) ===
  if (visRatio < 0.6) {
    signals.push(`❌ Visibilidade BGP crítica: ${Math.round(visRatio * 100)}%`);
    score += 8;
  } else if (visRatio < 0.8) {
    signals.push(`🔶 Visibilidade BGP baixa: ${Math.round(visRatio * 100)}%`);
    score += 4;
  } else if (visRatio < 0.9) {
    signals.push(`⚠️ Visibilidade reduzida: ${Math.round(visRatio * 100)}%`);
    score += 2;
  }

  // === BGP Withdrawals (lowered thresholds) ===
  if (bgpUpdates.withdrawals > 50) {
    signals.push(`❌ ${bgpUpdates.withdrawals} withdrawals BGP nos últimos 30min`);
    score += 5;
  } else if (bgpUpdates.withdrawals > 15) {
    signals.push(`⚠️ ${bgpUpdates.withdrawals} withdrawals nos últimos 30min`);
    score += 2;
  } else if (bgpUpdates.withdrawals > 5) {
    signals.push(`📊 ${bgpUpdates.withdrawals} withdrawals nos últimos 30min`);
    score += 1;
  }

  // === BGP Flapping ===
  if (bgpState === "FLAPPING") {
    signals.push(`⚠️ BGP oscilando (${bgpUpdates.announcements}A/${bgpUpdates.withdrawals}W)`);
    score += 3;
  }

  // === High update rate (announcements + withdrawals) ===
  const totalUpdates = bgpUpdates.announcements + bgpUpdates.withdrawals;
  if (totalUpdates > 150) {
    signals.push(`🔶 Alta taxa de atualizações BGP: ${totalUpdates} em 30min`);
    score += 3;
  } else if (totalUpdates > 50) {
    signals.push(`⚠️ Taxa elevada de atualizações BGP: ${totalUpdates} em 30min`);
    score += 1;
  }

  // === Anomaly signals ===
  if (visAnomaly) {
    signals.push("📉 Queda anormal de visibilidade detectada");
    score += 3;
  }
  if (visRapidDrop) {
    signals.push("⚡ Queda rápida de visibilidade entre leituras");
    score += 2;
  }
  if (neighAnomaly) {
    signals.push("📉 Perda de vizinhos BGP");
    score += 2;
  }
  if (prefixAnomaly) {
    signals.push("📉 Perda de prefixos anunciados");
    score += 2;
  }

  // === RIPE Atlas active probing ===
  if (atlasProbe) {
    if (!atlasProbe.reachable) {
      signals.push("❌ RIPE Atlas: destino inalcançável");
      score += 6;
    } else if (atlasProbe.packetLoss > 30) {
      signals.push(`❌ RIPE Atlas: ${atlasProbe.packetLoss}% perda de pacotes (${atlasProbe.probeCount} probes)`);
      score += 5;
    } else if (atlasProbe.packetLoss > 10) {
      signals.push(`🔶 RIPE Atlas: ${atlasProbe.packetLoss}% perda de pacotes`);
      score += 3;
    } else if (atlasProbe.packetLoss > 3) {
      signals.push(`⚠️ RIPE Atlas: ${atlasProbe.packetLoss}% perda de pacotes`);
      score += 1;
    }

    if (atlasProbe.avgLatency > 500) {
      signals.push(`🔶 RIPE Atlas: latência alta ${atlasProbe.avgLatency}ms`);
      score += 2;
    } else if (atlasProbe.avgLatency > 200) {
      signals.push(`⚠️ RIPE Atlas: latência elevada ${atlasProbe.avgLatency}ms`);
      score += 1;
    }
  }

  // === Score-based determination ===
  if (score >= 5) {
    return { status: "UNDER_ATTACK", signals };
  }
  if (score >= 2) {
    return { status: "WARNING", signals };
  }

  signals.push("✅ Todos os sinais BGP normais");
  return { status: "HEALTHY", signals };
}

// ============================================================
// Metrics update
// ============================================================

async function updateAsnMetrics(asn: string): Promise<AsnMetrics> {
  const forceAttack = attackFlags[asn] || false;
  if (forceAttack) attackFlags[asn] = false;
  const now = new Date().toISOString();

  if (!asnNames[asn]) asnNames[asn] = await fetchAsnName(asn);
  const name = asnNames[asn];

  if (forceAttack) {
    const m: AsnMetrics = {
      asn, name, status: "UNDER_ATTACK",
      latency: { avgMs: 200 + Math.round(Math.random() * 300), minMs: 150, maxMs: 600 },
      packetLossPercent: Math.round((30 + Math.random() * 50) * 100) / 100,
      bgp: { state: Math.random() > 0.4 ? "FLAPPING" : "WITHDRAWN", lastChange: now },
      bgpVisibility: { v4Percent: Math.round(Math.random() * 30), v6Percent: 0, totalPercent: Math.round(Math.random() * 30) },
      bgpUpdates: { announcements: 0, withdrawals: 999, period: "30min (simulado)" },
      neighbours: { list: [], total: 0, upstreams: 0, downstreams: 0, peers: 0 },
      prefixCount: 0, prefixes: [], lastUpdated: now, dataSource: "simulated",
      detectionSignals: ["❌ Ataque simulado manualmente"],
      securityAlerts: [],
    };
    const simScope = await computeAttackScope(asn).catch(() => null);
    if (simScope) m.attackScope = simScope;
    asnState[asn] = m;
    return m;
  }

  const [routingStatus, bgpUpdates, neighboursList, prefixList] = await Promise.all([
    fetchRoutingStatus(asn), fetchBgpUpdates(asn), fetchAsnNeighbours(asn), fetchAnnouncedPrefixes(asn),
  ]);

  let visRatio = 1, v4Pct = 100, v6Pct = 100, prefixCount = 0;
  if (routingStatus) {
    const v4S = routingStatus.visibility.v4.ris_peers_seeing;
    const v4T = routingStatus.visibility.v4.total_ris_peers;
    const v6S = routingStatus.visibility.v6.ris_peers_seeing;
    const v6T = routingStatus.visibility.v6.total_ris_peers;
    visRatio = (v4T + v6T) > 0 ? (v4S + v6S) / (v4T + v6T) : 1;
    v4Pct = v4T > 0 ? Math.round((v4S / v4T) * 10000) / 100 : 100;
    v6Pct = v6T > 0 ? Math.round((v6S / v6T) * 10000) / 100 : 0;
    prefixCount = routingStatus.announced_space?.v4?.prefixes || 0;
  }

  // Track historical data for anomaly detection
  trackHistory(visibilityHistory, asn, Math.round(visRatio * 100));
  trackHistory(neighbourHistory, asn, neighboursList.length);
  trackHistory(prefixHistory, asn, prefixList.length || prefixCount);

  // Detecta entrada/saída dos fornecedores de mitigação no caminho BGP
  const currentVendorAsns = new Set(
    neighboursList.map((n) => n.asn).filter((a) => MITIGATION_VENDOR_ASNS[a] !== undefined)
  );
  const previousVendorAsns = vendorNeighbourHistory[asn];
  const vendorChangeSignals: string[] = [];
  if (previousVendorAsns) {
    for (const a of currentVendorAsns) {
      if (!previousVendorAsns.has(a)) {
        vendorChangeSignals.push(`🔍 Fornecedor de mitigação entrou no caminho BGP: AS${a} (${MITIGATION_VENDOR_ASNS[a]})`);
      }
    }
    for (const a of previousVendorAsns) {
      if (!currentVendorAsns.has(a)) {
        vendorChangeSignals.push(`🔍 Fornecedor de mitigação saiu do caminho BGP: AS${a} (${MITIGATION_VENDOR_ASNS[a]})`);
      }
    }
  }
  vendorNeighbourHistory[asn] = currentVendorAsns;

  // RIPE Atlas active probing (non-blocking, runs in parallel with security checks)
  const atlasProbe = await fetchAtlasProbe(prefixList).catch(() => null);

  const bgpState = determineBgpState(bgpUpdates.announcements, bgpUpdates.withdrawals, visRatio);
  const { status, signals } = detectStatus(bgpState, visRatio, bgpUpdates, asn, atlasProbe);
  const latency = atlasProbe?.avgLatency
    ? { avgMs: atlasProbe.avgLatency, minMs: Math.round(atlasProbe.avgLatency * 0.5), maxMs: Math.round(atlasProbe.avgLatency * 2) }
    : estimateLatency(visRatio, neighboursList.length);
  const packetLossPercent = atlasProbe ? atlasProbe.packetLoss : estimatePacketLoss(visRatio);
  const totalPercent = Math.round(visRatio * 10000) / 100;

  // Fetch security alerts (Qrator + RPKI) in parallel
  const [qratorAlerts, rpkiAlerts] = await Promise.all([
    fetchQratorPaths(asn, prefixList).catch(() => [] as SecurityAlert[]),
    fetchRouteOriginValidation(asn, prefixList).catch(() => [] as SecurityAlert[]),
  ]);
  const securityAlerts = [...qratorAlerts, ...rpkiAlerts];

  // Escalate status if critical security alerts found
  let finalStatus = status;
  const criticalAlerts = securityAlerts.filter(a => a.severity === "critical");
  if (criticalAlerts.length > 0 && finalStatus === "HEALTHY") {
    finalStatus = "WARNING";
  }
  // Garante que mudança de fornecedor de mitigação no caminho BGP vira
  // incidente registrado (visibilidade pra revisão manual), mesmo que
  // nenhum outro sinal tenha disparado.
  if (vendorChangeSignals.length > 0 && finalStatus === "HEALTHY") {
    finalStatus = "WARNING";
  }
  if (criticalAlerts.length >= 2 && finalStatus !== "UNDER_ATTACK") {
    finalStatus = "UNDER_ATTACK";
  }

  // Add security signals to detection signals
  const allSignals = [...signals, ...vendorChangeSignals];
  for (const alert of securityAlerts) {
    const icon = alert.severity === "critical" ? "🔴" : alert.severity === "warning" ? "🟡" : "🔵";
    allSignals.push(`${icon} [${alert.type.toUpperCase()}] ${alert.description}`);
  }

  const ups = neighboursList.filter(n => n.type === "upstream");
  const downs = neighboursList.filter(n => n.type === "downstream");
  const peers = neighboursList.filter(n => n.type === "peer");

  const metrics: AsnMetrics = {
    asn, name, status: finalStatus, latency, packetLossPercent,
    bgp: { state: bgpState, lastChange: now },
    bgpVisibility: { v4Percent: v4Pct, v6Percent: v6Pct, totalPercent },
    bgpUpdates: { ...bgpUpdates, period: "últimos 30 min" },
    neighbours: { list: neighboursList, total: neighboursList.length, upstreams: ups.length, downstreams: downs.length, peers: peers.length },
    prefixCount: prefixList.length || prefixCount, prefixes: prefixList,
    lastUpdated: now, dataSource: "ripestat",
    detectionSignals: allSignals,
    securityAlerts,
  };

  // Capture previous state BEFORE overwriting
  const prevMetrics = asnState[asn];
  asnState[asn] = metrics;

  // Log incident to database when status is not HEALTHY (DB unique index handles dedup)
  if (finalStatus === "WARNING" || finalStatus === "UNDER_ATTACK") {
    await insertIncidentIfNew({
      asn, name, status: finalStatus, signals: allSignals,
      visibility_percent: totalPercent, packet_loss_percent: packetLossPercent,
      bgp_state: bgpState, withdrawals: bgpUpdates.withdrawals, announcements: bgpUpdates.announcements,
    });

    // Send Telegram notification (fire and forget)
    sendTelegramNotification({
      asn, name, status: finalStatus as "UNDER_ATTACK" | "WARNING",
      signals: allSignals, visibility_percent: totalPercent, packet_loss_percent: packetLossPercent,
    }).catch(err => console.error("Telegram notify error:", err));
  }

  // Attack scope correlation ("blast radius") — only meaningful when not healthy
  if (finalStatus !== "HEALTHY") {
    const scope = await computeAttackScope(asn).catch(() => null);
    if (scope) {
      metrics.attackScope = scope;
      asnState[asn] = metrics;
    }
  }

  // Recovery detection — log only, no Telegram notification

  // Log security-specific incidents even when overall status is HEALTHY
  const securityIncidentAlerts = securityAlerts.filter(a => a.severity === "critical" || a.severity === "warning");
  if (securityIncidentAlerts.length > 0 && finalStatus === "HEALTHY") {
    const secSignals = securityIncidentAlerts.map(a => {
      const icon = a.severity === "critical" ? "🔴" : "🟡";
      return `${icon} [${a.type.toUpperCase()}] ${a.description}`;
    });
    const secStatus = securityIncidentAlerts.some(a => a.severity === "critical") ? "UNDER_ATTACK" : "WARNING";
    await insertIncidentIfNew({
      asn, name, status: secStatus, signals: secSignals,
      visibility_percent: totalPercent, packet_loss_percent: packetLossPercent,
      bgp_state: bgpState, withdrawals: bgpUpdates.withdrawals, announcements: bgpUpdates.announcements,
    });
  }

  // ── RIPEstat-specific incident signals ──
  await detectRipeStatAnomalies(asn, name, totalPercent, bgpUpdates, bgpState, packetLossPercent);

  return metrics;
}

// ============================================================
// RIPEstat — Dedicated incident detection
// ============================================================

const RIPESTAT_VISIBILITY_THRESHOLD = 80; // percent
const RIPESTAT_UPDATE_THRESHOLD = 100;    // total updates in 30min

async function detectRipeStatAnomalies(
  asn: string,
  name: string,
  visibilityPercent: number,
  bgpUpdates: { announcements: number; withdrawals: number },
  bgpState: string,
  packetLossPercent: number,
) {
  const signals: string[] = [];

  // 1) Visibility drop
  if (visibilityPercent < RIPESTAT_VISIBILITY_THRESHOLD) {
    signals.push(`RIPEstat [visibility_drop] Visibilidade ${visibilityPercent.toFixed(1)}% (limiar: ${RIPESTAT_VISIBILITY_THRESHOLD}%)`);
  }

  // 2) High BGP update rate (AS-PATH anomaly proxy)
  const totalUpdates = bgpUpdates.announcements + bgpUpdates.withdrawals;
  if (totalUpdates > RIPESTAT_UPDATE_THRESHOLD) {
    signals.push(`RIPEstat [aspath_anomaly] ${totalUpdates} updates BGP em 30min (limiar: ${RIPESTAT_UPDATE_THRESHOLD})`);
  }

  if (signals.length === 0) return;

  await insertIncidentIfNew({
    asn,
    name: "RIPEstat",
    status: "WARNING",
    signals,
    visibility_percent: visibilityPercent,
    packet_loss_percent: packetLossPercent,
    bgp_state: bgpState,
    withdrawals: bgpUpdates.withdrawals,
    announcements: bgpUpdates.announcements,
  });
}

// ============================================================
// Attack scope correlation ("blast radius")
// ============================================================

const SCOPE_WINDOW_MINUTES = 20;
const SCOPE_WIDE_RATIO = 0.4;
const K2_OWN_ASN = "AS267458";

async function fetchActiveWanguardBlocks(): Promise<AffectedBlockInfo[]> {
  // Contrato real confirmado com o código de supabase/functions/wanguard-proxy:
  // GET /wanguard-proxy?action=anomalies&start_date=YYYY-MM-DD&end_date=YYYY-MM-DD
  // → { anomalies: [{ prefix, sizeBps, sizePps, status: "Ativo"|"Mitigado"|"Encerrado", ... }], source, total }
  try {
    const fmt = (d: Date) => d.toISOString().slice(0, 10);
    const today = new Date();
    const yesterday = new Date(today.getTime() - 24 * 60 * 60000);
    const params = new URLSearchParams({
      action: "anomalies",
      start_date: fmt(yesterday),
      end_date: fmt(today),
    });
    const fnUrl = `${supabaseUrl}/functions/v1/wanguard-proxy?${params.toString()}`;
    const res = await fetch(fnUrl, {
      headers: { "Authorization": `Bearer ${supabaseKey}`, "apikey": supabaseKey },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return [];
    const json = await res.json();
    const anomalies = Array.isArray(json?.anomalies) ? json.anomalies : [];
    return anomalies
      .filter((a: Record<string, unknown>) => a.status === "Ativo" && a.prefix && a.prefix !== "N/A")
      .map((a: Record<string, unknown>) => ({
        prefix: String(a.prefix),
        bps: typeof a.sizeBps === "number" ? a.sizeBps : undefined,
        pps: typeof a.sizePps === "number" ? a.sizePps : undefined,
      }));
  } catch (err) {
    console.error("fetchActiveWanguardBlocks error:", err);
    return [];
  }
}

async function computeAttackScope(asn: string): Promise<AttackScope | null> {
  try {
    const since = new Date(Date.now() - SCOPE_WINDOW_MINUTES * 60000).toISOString();
    const { data, error } = await supabase
      .from("asn_incidents")
      .select("asn, name, status, created_at")
      .gte("created_at", since)
      .in("status", ["WARNING", "UNDER_ATTACK"])
      .order("created_at", { ascending: false });

    if (error) {
      console.error("computeAttackScope query error:", error);
      return null;
    }

    // Deduplicate by ASN — keep most recent row, but escalate to UNDER_ATTACK if seen
    const byAsn: Record<string, AffectedAsnInfo> = {};
    for (const row of (data || [])) {
      const existing = byAsn[row.asn];
      const shouldEscalate = row.status === "UNDER_ATTACK" && existing?.status !== "UNDER_ATTACK";
      if (!existing || shouldEscalate) {
        byAsn[row.asn] = {
          asn: row.asn,
          name: ASN_NAME_OVERRIDES[row.asn] || asnNames[row.asn] || row.name || row.asn,
          status: row.status,
          detectedAt: row.created_at,
        };
      }
    }

    const affectedAsns = Object.values(byAsn);
    const totalMonitored = monitoredASNs.length > 0 ? monitoredASNs.length : Object.keys(asnState).length;
    const affectedRatio = totalMonitored > 0 ? affectedAsns.length / totalMonitored : 0;

    let level: AttackScopeLevel = "LOCALIZADO";
    if (affectedAsns.length >= 2) level = "MULTI_PROVEDOR";
    if (totalMonitored > 0 && affectedRatio >= SCOPE_WIDE_RATIO) level = "AMPLO";

    // Check for shared upstream using already-collected BGP neighbour data in asnState
    let sharedUpstream: { asn: number; name: string }[] | null = null;
    if (affectedAsns.length >= 2) {
      const upstreamSets: Set<number>[] = [];
      for (const a of affectedAsns) {
        const m = asnState[a.asn];
        const ups = (m?.neighbours?.list || []).filter((n) => n.type === "upstream").map((n) => n.asn);
        if (ups.length > 0) upstreamSets.push(new Set(ups));
      }
      if (upstreamSets.length >= 2) {
        const common = [...upstreamSets[0]].filter((u) => upstreamSets.every((s) => s.has(u)));
        if (common.length > 0) {
          sharedUpstream = common.map((u) => {
            const found = affectedAsns
              .flatMap((a) => asnState[a.asn]?.neighbours?.list || [])
              .find((n) => n.asn === u);
            return { asn: u, name: found?.name || `AS${u}` };
          });
        }
      }
    }

    // Own blocks under attack via Wanguard — only meaningful for K2's own ASN
    let ownBlocksUnderAttack: AffectedBlockInfo[] = [];
    if (asn === K2_OWN_ASN) {
      ownBlocksUnderAttack = await fetchActiveWanguardBlocks();
    }

    return {
      level,
      windowMinutes: SCOPE_WINDOW_MINUTES,
      affectedAsns,
      affectedRatio: Math.round(affectedRatio * 10000) / 10000,
      totalMonitored,
      sharedUpstream,
      ownBlocksUnderAttack,
    };
  } catch (err) {
    console.error("computeAttackScope error:", err);
    return null;
  }
}

// ============================================================
// Init & loop
// ============================================================

let initialized = false;
let updating = false;
let monitoredASNs: string[] = [];

let initPromise: Promise<void> | null = null;

async function initializeAll() {
  if (initialized) return;
  if (initPromise) return initPromise;
  initPromise = (async () => {
    try {
      monitoredASNs = await loadAllMonitoredAsns();
      console.log("Loaded ASNs from DB:", monitoredASNs);
      const uncached = monitoredASNs.filter((a) => !asnNames[a] || asnNames[a] === a);
      console.log(`Names from DB cache: ${monitoredASNs.length - uncached.length}, fetching from API: ${uncached.length}`);
      // Fetch names in batches of 4 to avoid overwhelming external APIs
      for (let i = 0; i < uncached.length; i += 4) {
        const batch = uncached.slice(i, i + 4);
        await Promise.allSettled(batch.map(async (a) => { asnNames[a] = await fetchAsnName(a); }));
      }
      // Update metrics in batches of 3
      for (let i = 0; i < monitoredASNs.length; i += 3) {
        const batch = monitoredASNs.slice(i, i + 3);
        await Promise.allSettled(batch.map((asn) => updateAsnMetrics(asn)));
      }
      initialized = true;
      console.log("✅ Init complete — BGP-based detection active");
    } catch (err) {
      console.error("Init error (will retry):", err);
      // Mark as initialized anyway to serve partial data and not block requests
      initialized = true;
    } finally {
      initPromise = null;
    }
  })();
  return initPromise;
}

async function updateAll() {
  if (updating) return;
  updating = true;
  try {
    monitoredASNs = await loadAllMonitoredAsns();
    // Update metrics in batches of 3 to avoid overwhelming APIs
    for (let i = 0; i < monitoredASNs.length; i += 3) {
      const batch = monitoredASNs.slice(i, i + 3);
      await Promise.allSettled(batch.map((asn) => updateAsnMetrics(asn)));
    }
    for (const k of Object.keys(asnState)) {
      if (!monitoredASNs.includes(k)) {
        delete asnState[k]; delete asnNames[k];
        delete visibilityHistory[k]; delete neighbourHistory[k]; delete prefixHistory[k];
      }
    }
  } finally { updating = false; }
}

// Start initialization in background (non-blocking)
initializeAll().catch(console.error);
setInterval(() => updateAll().catch(console.error), 30000);

async function ensureMetricsAvailable(asns: string[]) {
  const missingAsns = [...new Set(asns)].filter((asn) => !asnState[asn]);
  if (missingAsns.length === 0) return;

  for (let i = 0; i < missingAsns.length; i += 3) {
    const batch = missingAsns.slice(i, i + 3);
    await Promise.allSettled(batch.map((asn) => updateAsnMetrics(asn)));
  }
}

// ============================================================
// HTTP Handler
// ============================================================

Deno.serve(async (req) => {
  const corsHeaders = buildCorsHeaders(req.headers.get("origin"));
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/asn-monitor/, "");

  if (req.method === "GET" && (path === "/status" || path === "" || path === "/")) {
    // Suporte a ?asns=AS1,AS2 para buscar ASNs específicos (ex: concorrentes)
    const asnsParam = url.searchParams.get("asns");
    let requestedAsns: string[];

    if (asnsParam) {
      // Lista explícita de ASNs — sem filtro por user_id
      requestedAsns = asnsParam.split(",").map(a => a.trim().toUpperCase()).filter(Boolean);
    } else {
      const userId = getUserIdFromRequest(req);
      requestedAsns = userId
        ? await loadMonitoredAsns(userId)
        : (monitoredASNs.length > 0 ? monitoredASNs : await loadAllMonitoredAsns());
    }

    if (requestedAsns.length > 0) {
      if (!initialized || requestedAsns.every((asn) => !asnState[asn])) {
        await initializeAll();
      }
      await ensureMetricsAvailable(requestedAsns);
    }

    const data = requestedAsns.map((asn) => asnState[asn]).filter(Boolean);
    return new Response(JSON.stringify(data), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  if (req.method === "POST" && path.startsWith("/simulate-attack/")) {
    const t = path.replace("/simulate-attack/", "");
    if (!monitoredASNs.includes(t)) return new Response(JSON.stringify({ error: "ASN não encontrado" }), { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    attackFlags[t] = true;
    await updateAsnMetrics(t);
    return new Response(JSON.stringify({ message: `Ataque simulado em ${t}`, data: asnState[t] }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  if (req.method === "POST" && path === "/add-asn") {
    const userId = getUserIdFromRequest(req);
    if (!userId) return new Response(JSON.stringify({ error: "Não autenticado" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    try {
      const body = await req.json();
      let asn = String(body?.asn || "").trim().toUpperCase();
      if (!asn.startsWith("AS")) asn = `AS${asn}`;
      if (!/^\d{1,10}$/.test(asn.replace("AS", ""))) return new Response(JSON.stringify({ error: "ASN inválido" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      // Check if this user already monitors this ASN
      const userAsns = await loadMonitoredAsns(userId);
      if (userAsns.includes(asn)) return new Response(JSON.stringify({ error: "ASN já monitorado por você" }), { status: 409, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      if (!await addAsnToDb(asn, userId)) return new Response(JSON.stringify({ error: "Erro ao salvar" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      asnNames[asn] = await fetchAsnName(asn);
      if (!monitoredASNs.includes(asn)) {
        monitoredASNs.push(asn);
        await updateAsnMetrics(asn);
      }
      return new Response(JSON.stringify({ message: `${asn} adicionado`, data: asnState[asn] }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    } catch {
      return new Response(JSON.stringify({ error: "Body inválido" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }

  if (req.method === "DELETE" && path.startsWith("/remove-asn/")) {
    const userId = getUserIdFromRequest(req);
    if (!userId) return new Response(JSON.stringify({ error: "Não autenticado" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    const t = path.replace("/remove-asn/", "").toUpperCase();
    if (!await removeAsnFromDb(t, userId)) return new Response(JSON.stringify({ error: "Erro ao remover" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    // Check if any user still monitors this ASN
    const allAsns = await loadAllMonitoredAsns();
    if (!allAsns.includes(t)) {
      const idx = monitoredASNs.indexOf(t);
      if (idx !== -1) monitoredASNs.splice(idx, 1);
      delete asnState[t]; delete asnNames[t];
    }
    return new Response(JSON.stringify({ message: `${t} removido` }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // GET /attack-scope/:asn — on-demand blast-radius correlation for one ASN
  if (req.method === "GET" && path.startsWith("/attack-scope/")) {
    const t = path.replace("/attack-scope/", "").toUpperCase();
    const scope = await computeAttackScope(t);
    if (!scope) {
      return new Response(JSON.stringify({ error: "Não foi possível calcular o escopo do ataque" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify(scope), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // GET /incidents/count — total count without row limit
  if (req.method === "GET" && path === "/incidents/count") {
    const days = parseInt(url.searchParams.get("days") || "365", 10);
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const { count, error } = await supabase
      .from("asn_incidents")
      .select("*", { count: "exact", head: true })
      .gte("created_at", since);

    if (error) {
      return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ count: count || 0 }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // GET /incidents — fetch incident history with optional filters (paginated)
  if (req.method === "GET" && path === "/incidents") {
    const asnFilter = url.searchParams.get("asn");
    const days = parseInt(url.searchParams.get("days") || "30", 10);
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "5000", 10), 5000);
    const since = new Date(Date.now() - days * 86400000).toISOString();

    let query = supabase
      .from("asn_incidents")
      .select("*")
      .gte("created_at", since)
      .order("created_at", { ascending: false })
      .limit(limit);

    if (asnFilter) query = query.eq("asn", asnFilter);

    const { data, error } = await query;
    if (error) {
      return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify(data || []), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // GET /incidents/ranking — aggregated ranking by ASN
  if (req.method === "GET" && path === "/incidents/ranking") {
    const hoursParam = url.searchParams.get("hours");
    const daysParam = url.searchParams.get("days");
    const hours = hoursParam ? parseInt(hoursParam, 10) : (daysParam ? parseInt(daysParam, 10) * 24 : 720);
    const since = new Date(Date.now() - hours * 3600000).toISOString();

    const { data, error } = await supabase
      .from("asn_incidents")
      .select("*")
      .gte("created_at", since)
      .order("created_at", { ascending: false })
      .limit(5000);

    if (error) {
      return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // Aggregate per ASN
    const agg: Record<string, { asn: string; name: string; totalIncidents: number; attacks: number; warnings: number; avgPacketLoss: number; avgVisibility: number; totalWithdrawals: number; lastIncident: string }> = {};
    for (const row of (data || [])) {
      // Apply name override
      const displayName = ASN_NAME_OVERRIDES[row.asn] || row.name;
      if (!agg[row.asn]) {
        agg[row.asn] = { asn: row.asn, name: displayName, totalIncidents: 0, attacks: 0, warnings: 0, avgPacketLoss: 0, avgVisibility: 0, totalWithdrawals: 0, lastIncident: row.created_at };
      }
      const a = agg[row.asn];
      a.totalIncidents++;
      if (row.status === "UNDER_ATTACK") a.attacks++;
      if (row.status === "WARNING") a.warnings++;
      a.avgPacketLoss += (row.packet_loss_percent || 0);
      a.avgVisibility += (row.visibility_percent || 0);
      a.totalWithdrawals += (row.withdrawals || 0);
      if (row.created_at > a.lastIncident) a.lastIncident = row.created_at;
    }

    const ranking = Object.values(agg).map(a => ({
      ...a,
      avgPacketLoss: a.totalIncidents > 0 ? Math.round((a.avgPacketLoss / a.totalIncidents) * 100) / 100 : 0,
      avgVisibility: a.totalIncidents > 0 ? Math.round((a.avgVisibility / a.totalIncidents) * 100) / 100 : 0,
      score: Math.round((a.attacks * 10 + a.warnings * 3 + a.totalWithdrawals * 0.1) * 10) / 10,
    })).sort((a, b) => b.score - a.score);

    return new Response(JSON.stringify(ranking), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }

  // ============================================================
  // Admin endpoints (master admin only - edson)
  // ============================================================

  async function verifyMasterAdmin(req: Request): Promise<boolean> {
    const userId = getUserIdFromRequest(req);
    if (!userId) return false;
    // Antes: checava profiles.username === "edson" (admin fixo no código).
    // Agora: checa o role 'master_admin' na tabela user_roles.
    const { data, error } = await supabase
      .from("user_roles")
      .select("role")
      .eq("user_id", userId)
      .eq("role", "master_admin")
      .maybeSingle();
    if (error) {
      console.error("verifyMasterAdmin error:", error);
      return false;
    }
    return !!data;
  }

  if (req.method === "POST" && path === "/admin/create-user") {
    if (!await verifyMasterAdmin(req)) {
      return new Response(JSON.stringify({ error: "Acesso negado" }), { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    try {
      const body = await req.json();
      const { username, password, role } = body;
      if (!username || !password) return new Response(JSON.stringify({ error: "Username e senha obrigatórios" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });

      const email = `${username.toLowerCase()}@monitor.local`;

      // Check if user already exists
      const { data: existingProfiles } = await supabase.from("profiles").select("id, username").eq("username", username.toLowerCase());
      if (existingProfiles && existingProfiles.length > 0) {
        return new Response(JSON.stringify({ error: `Usuário '${username}' já existe` }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // Create user via admin API
      const { data: newUser, error: createErr } = await supabase.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: { username, display_name: username, must_change_password: true },
      });

      if (createErr) {
        console.error("Error creating user:", createErr);
        return new Response(JSON.stringify({ error: createErr.message }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // Assign role
      if (newUser?.user && role) {
        await supabase.from("user_roles").insert({ user_id: newUser.user.id, role });
      }

      return new Response(JSON.stringify({ message: `Usuário ${username} criado`, userId: newUser?.user?.id }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    } catch (err) {
      console.error("Create user error:", err);
      return new Response(JSON.stringify({ error: `Erro interno: ${err instanceof Error ? err.message : String(err)}` }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }

  if (req.method === "POST" && path === "/admin/update-role") {
    if (!await verifyMasterAdmin(req)) {
      return new Response(JSON.stringify({ error: "Acesso negado" }), { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    try {
      const { userId, role } = await req.json();
      // Delete existing role
      await supabase.from("user_roles").delete().eq("user_id", userId);
      // Insert new role
      const { error } = await supabase.from("user_roles").insert({ user_id: userId, role });
      if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      return new Response(JSON.stringify({ message: "Role atualizada" }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    } catch {
      return new Response(JSON.stringify({ error: "Erro interno" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }

  if (req.method === "POST" && path === "/admin/reset-password") {
    if (!await verifyMasterAdmin(req)) {
      return new Response(JSON.stringify({ error: "Acesso negado" }), { status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    try {
      const { userId } = await req.json();
      if (!userId) return new Response(JSON.stringify({ error: "userId obrigatório" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      
      console.log("Resetting password for userId:", userId);
      const tempPassword = generateTempPassword();
      const { error } = await supabase.auth.admin.updateUserById(userId, { password: tempPassword });
      if (error) {
        console.error("Reset password error:", error);
        return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      // Set must_change_password flag
      await supabase.from("profiles").update({ must_change_password: true }).eq("id", userId);
      return new Response(JSON.stringify({ message: "Senha resetada", tempPassword }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    } catch (err) {
      console.error("Reset password catch:", err);
      return new Response(JSON.stringify({ error: `Erro interno: ${err instanceof Error ? err.message : String(err)}` }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }

  // ============================================================
  // Ping endpoint - ICMP real via check-host.net API
  // ============================================================
  if (req.method === "POST" && path === "/ping") {
    try {
      const { prefixes } = await req.json();
      if (!prefixes || !Array.isArray(prefixes) || prefixes.length === 0) {
        return new Response(JSON.stringify({ error: "Prefixes required" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      const getFirstIp = (prefix: string): string => {
        const base = prefix.split("/")[0];
        const parts = base.split(".");
        parts[3] = "1";
        return parts.join(".");
      };

      const getCidr = (prefix: string): number => {
        const parts = prefix.split("/");
        return parts.length > 1 ? parseInt(parts[1], 10) : 32;
      };

      // Sort prefixes: prioritize /22, then larger blocks (/21, /20...), then smaller (/23, /24...)
      const sorted = [...prefixes].sort((a, b) => {
        const ca = getCidr(a), cb = getCidr(b);
        const da = Math.abs(ca - 22), db = Math.abs(cb - 22);
        if (da !== db) return da - db;
        return ca - cb; // prefer larger block if equidistant
      });

      // Try each prefix until one responds
      let lastError = "";
      for (const prefix of sorted.slice(0, 4)) {
        const ip = getFirstIp(prefix);

        // Step 1: Request ping check from check-host.net
        const checkResp = await fetch(`https://check-host.net/check-ping?host=${ip}&max_nodes=4`, {
          headers: { "Accept": "application/json" },
        });

        if (!checkResp.ok) {
          lastError = `check-host.net retornou ${checkResp.status} para ${prefix}`;
          await checkResp.text(); // consume body
          continue; // try next prefix
        }

        const checkData = await checkResp.json();
        const requestId = checkData.request_id;

        if (!requestId) {
          lastError = `Sem request_id para ${prefix}`;
          continue;
        }

        // Step 2: Wait for results (poll)
        let results = null;
        await new Promise(r => setTimeout(r, 1000));
        for (let attempt = 0; attempt < 7; attempt++) {
          try {
            const resultResp = await fetch(`https://check-host.net/check-result/${requestId}`, {
              headers: { "Accept": "application/json" },
            });
            if (resultResp.ok) {
              const data = await resultResp.json();
              const values = Object.values(data);
              const hasResults = values.length > 0 && values.some(v => v !== null);
              if (hasResults) {
                results = data;
                break;
              }
            }
          } catch { /* retry */ }
          await new Promise(r => setTimeout(r, 2000));
        }

        if (!results) {
          lastError = `Timeout para ${prefix} (${ip})`;
          continue; // try next prefix
        }

        // Step 3: Parse results — check if we got actual responses
        const nodes = checkData.nodes || {};
        const parsedResults: Array<{
          node: string; location: string; country: string;
          pings: Array<{ status: string; rttMs: number }>;
          avgMs: number; minMs: number; maxMs: number; packetLoss: number;
        }> = [];

        for (const [nodeId, rawData] of Object.entries(results)) {
          if (!rawData || !Array.isArray(rawData)) continue;
          const nodeInfo = nodes[nodeId];
          const location = Array.isArray(nodeInfo) ? `${nodeInfo[2]}, ${nodeInfo[1]}` : nodeId;
          const country = Array.isArray(nodeInfo) ? String(nodeInfo[0]).toUpperCase() : "??";
          const pingArray = Array.isArray(rawData[0]) ? rawData[0] : rawData;
          const pings: Array<{ status: string; rttMs: number }> = [];
          let successCount = 0;
          for (const ping of pingArray) {
            if (!Array.isArray(ping)) continue;
            const [status, rtt] = ping;
            if (status === "OK") {
              pings.push({ status: "OK", rttMs: Math.round((rtt as number) * 1000) });
              successCount++;
            } else {
              pings.push({ status: "TIMEOUT", rttMs: 0 });
            }
          }
          const successPings = pings.filter(p => p.status === "OK").map(p => p.rttMs);
          const avgMs = successPings.length > 0 ? Math.round(successPings.reduce((a, b) => a + b, 0) / successPings.length) : 0;
          const minMs = successPings.length > 0 ? Math.min(...successPings) : 0;
          const maxMs = successPings.length > 0 ? Math.max(...successPings) : 0;
          const packetLoss = pings.length > 0 ? Math.round(((pings.length - successCount) / pings.length) * 100) : 100;
          parsedResults.push({ node: nodeId, location, country, pings, avgMs, minMs, maxMs, packetLoss });
        }

        // If all nodes show 100% loss, try next prefix
        const allLost = parsedResults.every(n => n.packetLoss === 100);
        if (allLost && sorted.indexOf(prefix) < sorted.length - 1) {
          lastError = `100% perda para ${prefix} (${ip}), tentando próximo prefixo`;
          continue;
        }

        return new Response(JSON.stringify({
          ip, prefix, method: "ICMP", source: "check-host.net",
          requestId,
          reportUrl: `https://check-host.net/check-report/${requestId}`,
          nodes: parsedResults,
          timestamp: new Date().toISOString(),
          triedPrefixes: sorted.slice(0, sorted.indexOf(prefix) + 1),
        }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      } // end prefix loop

      return new Response(JSON.stringify({ error: `Nenhum prefixo respondeu ao ping. ${lastError}`, triedPrefixes: sorted.slice(0, 4) }), { status: 504, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    } catch (err) {
      return new Response(JSON.stringify({ error: "Erro ao executar ping", details: String(err) }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
  }

  return new Response(JSON.stringify({ error: "Rota não encontrada" }), { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
});
