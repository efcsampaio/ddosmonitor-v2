const corsHeadersStatic = {
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// Mesmo esquema de CORS restrito usado em asn-monitor — antes era
// Access-Control-Allow-Origin: "*" em todas as respostas.
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

// Antes: chamadas do frontend usavam a anon key como Authorization bearer —
// qualquer um com a anon key (pública) conseguia bater na API real do
// Wanguard através deste proxy, sem estar logado. Agora exige OU um JWT de
// sessão real de usuário, OU a service role key — esta última é usada pela
// chamada interna feita por asn-monitor (fetchActiveWanguardBlocks, para o
// "Contexto do Ataque"), que não tem sessão de usuário associada.
const supabaseServiceKeyEnv = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";

function getUserIdFromRequest(req: Request): string | null {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;
  try {
    const token = authHeader.split(" ")[1];
    const payload = JSON.parse(atob(token.split(".")[1]));
    return payload.sub || null;
  } catch { return null; }
}

function isServiceRoleRequest(req: Request): boolean {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return false;
  return supabaseServiceKeyEnv.length > 0 && authHeader.slice("Bearer ".length) === supabaseServiceKeyEnv;
}

function isAuthorized(req: Request): boolean {
  return getUserIdFromRequest(req) !== null || isServiceRoleRequest(req);
}

const WANGUARD_BASE_URL = "https://lvwanguard-k2network.lv.network";

function getBasicAuth(): string | null {
  const user = Deno.env.get("WANGUARD_USER");
  const pass = Deno.env.get("WANGUARD_PASS");
  if (!user || !pass) return null;
  const encoder = new TextEncoder();
  const encoded = encoder.encode(`${user}:${pass}`);
  return btoa(String.fromCharCode(...encoded));
}

async function wanguardFetch(path: string, params?: Record<string, string>): Promise<Response> {
  const basicAuth = getBasicAuth();
  if (!basicAuth) throw new Error("WANGUARD_USER/WANGUARD_PASS not configured");

  const url = new URL(`${WANGUARD_BASE_URL}/wanguard-api/v1${path}`);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      url.searchParams.set(k, v);
    }
  }

  console.log(`Wanguard fetch: ${url.toString()}`);
  const res = await fetch(url.toString(), {
    headers: {
      "Authorization": `Basic ${basicAuth}`,
      "Accept": "application/json",
    },
  });

  if (!res.ok) {
    const errText = await res.text();
    console.error(`Wanguard API ${res.status}:`, errText.substring(0, 500));
    throw new Error(`Wanguard API error ${res.status}: ${errText.substring(0, 300)}`);
  }

  return res;
}

async function parseJsonResponse(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return [];
  try {
    return JSON.parse(text);
  } catch {
    console.error("Invalid JSON from Wanguard:", text.substring(0, 300));
    throw new Error("Invalid JSON response from Wanguard API");
  }
}

Deno.serve(async (req) => {
  const corsHeaders = buildCorsHeaders(req.headers.get("origin"));

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (!isAuthorized(req)) {
    return new Response(
      JSON.stringify({ error: "Não autenticado" }),
      { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  try {
    const url = new URL(req.url);
    const action = url.searchParams.get("action") || "anomalies";

    // Check credentials
    if (!Deno.env.get("WANGUARD_USER") || !Deno.env.get("WANGUARD_PASS")) {
      return new Response(JSON.stringify({ error: "WANGUARD_USER and WANGUARD_PASS secrets not configured" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const jsonResponse = (body: unknown, status = 200) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });

    switch (action) {
      case "anomalies": {
        const startDate = url.searchParams.get("start_date");
        const endDate = url.searchParams.get("end_date");
        if (!startDate || !endDate) {
          return new Response(JSON.stringify({ error: "start_date and end_date required (YYYY-MM-DD)" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        const queryParams: Record<string, string> = {
          from: `>=${startDate}`,
          until: `<=${endDate}T23:59:59`,
        };
        // Request all useful fields inline to avoid needing per-anomaly fetches
        const fields = url.searchParams.get("fields") ||
          "anomaly_id,status,prefix,ip_group,direction,decoder,from,until,duration,pkts/s,bits/s,severity,classification,comments,sensor_name,value,latest_value";
        queryParams.fields = fields;
        
        const res = await wanguardFetch("/anomalies", queryParams);
        const data = await parseJsonResponse(res);
        // Log first raw item to discover available fields
        const rawItems = Array.isArray(data) ? data : [];
        if (rawItems.length > 0) {
          console.log("WANGUARD_RAW_SAMPLE:", JSON.stringify(rawItems[0]).substring(0, 1000));
        }
        const anomalies = normalizeAnomalies(data);
        return jsonResponse({ anomalies, source: "live", total: anomalies.length });
      }

      case "anomaly_details": {
        const anomalyId = url.searchParams.get("anomaly_id");
        if (!anomalyId) {
          return jsonResponse({ error: "anomaly_id required" }, 400);
        }
        const res = await wanguardFetch(`/anomalies/${anomalyId}`);
        const data = await parseJsonResponse(res);
        return jsonResponse({ anomaly: data, source: "live" });
      }

      case "anomaly_actions": {
        const anomalyId = url.searchParams.get("anomaly_id");
        if (!anomalyId) {
          return jsonResponse({ error: "anomaly_id required" }, 400);
        }
        const res = await wanguardFetch(`/anomalies/${anomalyId}/response_actions`);
        const data = await parseJsonResponse(res);
        const actions = Array.isArray(data) ? data : [];
        return jsonResponse({ actions, source: "live" });
      }

      case "bgp_announcements": {
        const res = await wanguardFetch("/bgp_announcements");
        const data = await parseJsonResponse(res);
        const announcements = Array.isArray(data) ? data : [];
        return jsonResponse({ announcements, source: "live" });
      }

      case "live_stats": {
        const res = await wanguardFetch("/sensors");
        const data = await parseJsonResponse(res);
        return jsonResponse({ sensors: data, source: "live" });
      }

      case "status": {
        try {
          const res = await wanguardFetch("/sensors");
          await res.text(); // consume body
          return jsonResponse({ online: true, checkedAt: new Date().toISOString() });
        } catch {
          return jsonResponse({ online: false, checkedAt: new Date().toISOString() });
        }
      }

      default:
        return jsonResponse({ error: `Unknown action: ${action}` }, 400);
    }
  } catch (error) {
    console.error("Wanguard proxy error:", error);
    return new Response(JSON.stringify({ error: "Wanguard API error", message: String(error) }), {
      status: 502,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});

// --- Normalization ---

// Wanguard API returns from/until as objects: { iso_8601: "...", unixtime: "..." }
// and decoder as object: { decoder_id, decoder_name, href }
function extractDateStr(v: unknown): string {
  if (!v) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object" && v !== null) {
    const obj = v as Record<string, unknown>;
    if (obj.iso_8601) return String(obj.iso_8601);
    if (obj.unixtime) return new Date(Number(obj.unixtime) * 1000).toISOString();
  }
  return "";
}

function extractDecoderName(v: unknown): string {
  if (!v) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object" && v !== null) {
    const obj = v as Record<string, unknown>;
    if (obj.decoder_name) return String(obj.decoder_name);
  }
  return "";
}

function normalizeAnomalies(raw: unknown): Array<Record<string, unknown>> {
  const items = Array.isArray(raw) ? raw : [];

  return items.map((item: Record<string, unknown>) => {
    const fromStr = extractDateStr(item.from);
    const untilStr = extractDateStr(item.until);
    const startDate = fromStr ? new Date(fromStr) : null;
    const endDate = untilStr ? new Date(untilStr) : null;

    const rawDuration = item.duration;
    const durationSec = typeof rawDuration === "number" ? rawDuration
      : typeof rawDuration === "string" ? parseInt(rawDuration, 10) || 0
      : (startDate && endDate ? (endDate.getTime() - startDate.getTime()) / 1000 : 0);

    const bps = toNumber(item["bits/s"]) || toNumber(item.latest_value) || 0;
    const pps = toNumber(item["pkts/s"]) || 0;
    const decoderName = extractDecoderName(item.decoder);
    const classif = String(item.classification || "");
    const attackType = (classif && classif !== "Unclassified") ? classif : (decoderName || classif || "Unknown");

    return {
      id: String(item.anomaly_id || Math.random().toString(36).slice(2)),
      start: fromStr,
      end: untilStr,
      durationMinutes: Math.max(1, Math.round(durationSec / 60)),
      prefix: String(item.prefix || item.ip_group || "N/A"),
      sizeBps: bps,
      sizePps: pps,
      attackType,
      status: normalizeStatus(item.status as string),
      severity: toNumber(item.severity),
      direction: String(item.direction || ""),
      comments: String(item.comments || ""),
      sensorName: String(item.sensor_name || ""),
      ipGroup: String(item.ip_group || ""),
      raw: item,
    };
  });
}

function toNumber(v: unknown): number {
  if (typeof v === "number") return v;
  if (typeof v === "string") return parseFloat(v) || 0;
  return 0;
}

function normalizeStatus(status?: string): string {
  if (!status) return "Encerrado";
  const s = status.toLowerCase();
  if (s.includes("active") || s.includes("ativo")) return "Ativo";
  if (s.includes("pending")) return "Ativo";
  if (s.includes("mitigat")) return "Mitigado";
  if (s.includes("finished")) return "Encerrado";
  return "Encerrado";
}
