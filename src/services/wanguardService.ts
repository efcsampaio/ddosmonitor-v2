// Wanguard Service
// Calls the wanguard-proxy edge function for live data only

export interface WanguardEvent {
  id: string;
  date: string;
  startTime: string;
  endTime: string;
  durationMinutes: number;
  prefix: string;
  sizeBps: number;
  sizePps: number;
  attackType: string;
  status: "Ativo" | "Mitigado" | "Encerrado";
  timestamp: Date;
  sensorName?: string;
  comments?: string;
}

export interface ExternalAnomaly {
  id: string;
  date: string;
  time: string;
  source: "RIPEstat" | "Qrator" | "RPKI";
  anomalyType: string;
  severity: "Alta" | "Média" | "Baixa";
  prefix: string | null;
  timestamp: Date;
}

export interface WanguardStatus {
  online: boolean;
  checkedAt: string;
}

// --- Proxy helper ---

function getProxyUrl(): string {
  const projectId = import.meta.env.VITE_SUPABASE_PROJECT_ID;
  return `https://${projectId}.supabase.co/functions/v1/wanguard-proxy`;
}

// Antes: usava a anon key também como Authorization bearer — o backend
// agora exige um JWT de sessão real (mesma correção aplicada em
// estimate-attack-risk / ASNCard.tsx). O apikey continua sendo a anon key,
// que é o identificador do projeto, não credencial de usuário.
async function getHeaders(): Promise<Record<string, string> | null> {
  const { supabase } = await import("@/integrations/supabase/client");
  const anonKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
  const { data: { session } } = await supabase.auth.getSession();
  if (!session?.access_token) return null;
  return {
    "Authorization": `Bearer ${session.access_token}`,
    "apikey": anonKey,
  };
}

async function proxyFetch(params: Record<string, string>): Promise<Response | null> {
  const headers = await getHeaders();
  if (!headers) return null;
  const url = new URL(getProxyUrl());
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }
  return fetch(url.toString(), { headers });
}

function formatDate(d: Date): string {
  return d.toISOString().split("T")[0];
}

// --- Public API ---

export async function fetchWanguardEvents(
  startDate: Date,
  endDate: Date,
  _asn: string = "AS267458"
): Promise<{ events: WanguardEvent[]; source: "live" | "error"; error?: string }> {
  try {
    const res = await proxyFetch({
      action: "anomalies",
      start_date: formatDate(startDate),
      end_date: formatDate(endDate),
    });

    if (!res) {
      return { events: [], source: "error", error: "Não autenticado" };
    }

    if (!res.ok) {
      const err = await res.text();
      console.error("Wanguard API error:", err);
      return { events: [], source: "error", error: err };
    }

    const json = await res.json();

    if (json.source === "live" && Array.isArray(json.anomalies)) {
      const events: WanguardEvent[] = json.anomalies.map((a: any) => {
        const start = a.start ? new Date(a.start) : new Date();
        const end = a.end ? new Date(a.end) : new Date(start.getTime() + (a.durationMinutes || 10) * 60000);
        return {
          id: String(a.id),
          date: start.toLocaleDateString("pt-BR"),
          startTime: start.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }),
          endTime: end.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }),
          durationMinutes: a.durationMinutes || Math.round((end.getTime() - start.getTime()) / 60000),
          prefix: a.prefix || "—",
          sizeBps: a.sizeBps || 0,
          sizePps: a.sizePps || 0,
          attackType: a.attackType || "—",
          status: (a.status as WanguardEvent["status"]) || "Encerrado",
          timestamp: start,
          sensorName: a.sensorName || "",
          comments: a.comments || "",
        };
      });
      return { events, source: "live" };
    }

    return { events: [], source: "error", error: "Formato de resposta inesperado da API" };
  } catch (e) {
    console.error("Wanguard fetch failed:", e);
    return { events: [], source: "error", error: String(e) };
  }
}

export async function fetchWanguardStatus(): Promise<WanguardStatus> {
  try {
    const res = await proxyFetch({ action: "status" });
    if (!res || !res.ok) return { online: false, checkedAt: new Date().toISOString() };
    return await res.json();
  } catch {
    return { online: false, checkedAt: new Date().toISOString() };
  }
}

export async function fetchExternalAnomalies(
  startDate: Date,
  endDate: Date,
  asn: string = "AS267458"
): Promise<ExternalAnomaly[]> {
  const { supabase } = await import("@/integrations/supabase/client");

  const { data, error } = await supabase
    .from("asn_incidents")
    .select("id, asn, name, status, signals, created_at, visibility_percent, packet_loss_percent")
    .eq("asn", asn)
    .gte("created_at", startDate.toISOString())
    .lte("created_at", endDate.toISOString())
    .order("created_at", { ascending: false })
    .limit(1000);

  if (error || !data) {
    console.error("Erro ao buscar anomalias externas:", error);
    return [];
  }

  const anomalies: ExternalAnomaly[] = [];

  for (const row of data) {
    const signalsStr = (row.signals ?? []).join(" ");
    const source = detectSource(row.name, signalsStr);
    if (!source) continue; // skip non-external sources (e.g. BGP interno puro)

    const ts = new Date(row.created_at);
    const severity = mapSeverity(row.status);
    const anomalyType = extractAnomalyType(row.name, signalsStr);
    const prefix = extractPrefix(signalsStr);

    anomalies.push({
      id: row.id,
      date: ts.toLocaleDateString("pt-BR"),
      time: ts.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" }),
      source,
      anomalyType,
      severity,
      prefix,
      timestamp: ts,
    });
  }

  return anomalies;
}

function detectSource(name: string, signals: string): ExternalAnomaly["source"] | null {
  const lower = (name + " " + signals).toLowerCase();
  if (lower.includes("qrator")) return "Qrator";
  if (lower.includes("rpki")) return "RPKI";
  if (lower.includes("ripestat")) return "RIPEstat";
  return null;
}

function mapSeverity(status: string): ExternalAnomaly["severity"] {
  if (status === "CRITICAL") return "Alta";
  if (status === "WARNING") return "Média";
  return "Baixa";
}

function extractAnomalyType(name: string, signals: string): string {
  const combined = signals || name;
  if (/PATH_ANOMALY/i.test(combined)) return "Path Anomaly";
  if (/VISIBILITY_DROP/i.test(combined)) return "Visibility Drop";
  if (/ASPATH_ANOMALY/i.test(combined)) return "AS-Path Anomaly";
  if (/RPKI/i.test(combined)) return "RPKI Alert";
  if (/perda de vizinhos/i.test(combined)) return "Perda de vizinhos BGP";
  if (/perda de prefixos/i.test(combined)) return "Perda de prefixos";
  return name || "Anomalia";
}

function extractPrefix(signals: string): string | null {
  const match = signals.match(/(\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2})/);
  return match ? match[1] : null;
}
