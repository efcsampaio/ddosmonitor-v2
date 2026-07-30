import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";

const corsHeadersStatic = {
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// Mesmo esquema de CORS restrito usado nas outras functions.
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

const supabaseUrlEnv = Deno.env.get("SUPABASE_URL")!;
const supabaseServiceKeyEnv = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

// Job pesado (loop de chamadas externas ao Wanguard, geração de gráfico,
// envio ao Telegram) — inicialmente travado só pro service role, mas
// ComparativoK2.tsx (botão "Gerar dataset") chama essa function direto do
// frontend. Então agora aceita OU a service role key, OU um usuário
// logado cujo role tenha acesso à página (admin/moderator/master_admin —
// mesmo critério de page:comparativo-k2 no frontend, mas checado aqui no
// servidor, que é o que realmente importa).
function isServiceRoleRequest(req: Request): boolean {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return false;
  return authHeader.slice("Bearer ".length) === supabaseServiceKeyEnv;
}

function getUserIdFromRequest(req: Request): string | null {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;
  try {
    const token = authHeader.split(" ")[1];
    const payload = JSON.parse(atob(token.split(".")[1]));
    return payload.sub || null;
  } catch { return null; }
}

async function hasDatasetAccess(req: Request): Promise<boolean> {
  if (isServiceRoleRequest(req)) return true;
  const userId = getUserIdFromRequest(req);
  if (!userId) return false;
  const supabase = createClient(supabaseUrlEnv, supabaseServiceKeyEnv);
  const { data } = await supabase
    .from("user_roles")
    .select("role")
    .eq("user_id", userId)
    .maybeSingle();
  const role = data?.role;
  return role === "admin" || role === "moderator" || role === "master_admin";
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

async function fetchWanguardAnomalies(startDate: string, endDate: string) {
  const basicAuth = getBasicAuth();
  if (!basicAuth) throw new Error("WANGUARD_USER/WANGUARD_PASS not configured");
  const url = new URL(`${WANGUARD_BASE_URL}/wanguard-api/v1/anomalies`);
  url.searchParams.set("from", `>=${startDate}`);
  url.searchParams.set("until", `<=${endDate}T23:59:59`);
  url.searchParams.set("fields", "anomaly_id,status,prefix,from,until,duration,pkts/s,bits/s,severity,classification,sensor_name");
  const res = await fetch(url.toString(), {
    headers: { Authorization: `Basic ${basicAuth}`, Accept: "application/json" },
  });
  if (!res.ok) throw new Error(`Wanguard ${res.status}`);
  const data = await res.json();
  return Array.isArray(data) ? data : [];
}

function extractDate(v: unknown): string {
  if (!v) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object" && v !== null) {
    const o = v as Record<string, unknown>;
    if (o.iso_8601) return String(o.iso_8601);
    if (o.unixtime) return new Date(Number(o.unixtime) * 1000).toISOString();
  }
  return "";
}

function toNum(v: unknown): number {
  if (typeof v === "number") return v;
  if (typeof v === "string") return parseFloat(v) || 0;
  return 0;
}

interface NormalizedAnomaly { start: Date; bps: number; pps: number; }

function normalizeAnomalies(raw: unknown[]): NormalizedAnomaly[] {
  return raw.map((item: any) => {
    const fromStr = extractDate(item.from);
    return {
      start: fromStr ? new Date(fromStr) : new Date(),
      bps: toNum(item["bits/s"]) || toNum(item.latest_value) || 0,
      pps: toNum(item["pkts/s"]) || 0,
    };
  });
}

const qratorPatterns = ["qrator", "path_anomaly"];
const rpkiPatterns = ["rpki"];
const ripestatPatterns = ["ripestat [visibility_drop]", "ripestat [aspath_anomaly]"];
const bgpPatterns = ["perda de vizinhos bgp", "perda de prefixos anunciados"];
const allStrongPatterns = [...qratorPatterns, ...rpkiPatterns, ...ripestatPatterns, ...bgpPatterns];

function matchesAny(signal: string, patterns: string[]): boolean {
  const lower = signal.toLowerCase();
  return patterns.some((p) => lower.includes(p));
}

interface ExternalEvent { time: Date; signals: string[]; status: string; }

function isStrongEvent(e: ExternalEvent): boolean {
  if (e.status === "CRITICAL") return true;
  if (e.status === "WARNING") return e.signals.some((s) => matchesAny(s, allStrongPatterns));
  return false;
}

function countPerSource(events: ExternalEvent[]) {
  let qrator = 0, rpki = 0, ripestat = 0, bgp = 0;
  for (const e of events) {
    if (!isStrongEvent(e)) continue;
    if (e.signals.some((s) => matchesAny(s, qratorPatterns))) qrator++;
    if (e.signals.some((s) => matchesAny(s, rpkiPatterns))) rpki++;
    if (e.signals.some((s) => matchesAny(s, ripestatPatterns))) ripestat++;
    if (e.signals.some((s) => matchesAny(s, bgpPatterns))) bgp++;
  }
  return { qrator, rpki, ripestat, bgp };
}

// Antes: passava por um proxy do Lovable (connector-gateway.lovable.dev),
// que exigia LOVABLE_API_KEY além do token do bot. Chamando a API do
// Telegram direto, só o token do bot (TELEGRAM_API_KEY) é necessário.
const TELEGRAM_API_BASE = "https://api.telegram.org";

async function sendCoverageToTelegram(supabase: any, asn: string) {
  const TELEGRAM_API_KEY = Deno.env.get("TELEGRAM_API_KEY");
  if (!TELEGRAM_API_KEY) {
    console.log("Telegram key not configured, skipping coverage image");
    return;
  }
  const { data: rows, error } = await supabase
    .from("as_attack_samples")
    .select("wanguard_is_under_attack, wanguard_severity_class, external_anomalies_count_30m, external_strong_anomalies_count_30m")
    .eq("asn", asn);
  if (error || !rows || rows.length === 0) { console.log("No samples to build coverage image"); return; }

  const attackRows = rows.filter((r: any) => r.wanguard_is_under_attack === true);
  const noAttackRows = rows.filter((r: any) => r.wanguard_is_under_attack === false);
  const attackTotal = attackRows.length;
  const attackWithExt = attackRows.filter((r: any) => r.external_strong_anomalies_count_30m > 0).length;
  const attackCoverage = attackTotal > 0 ? ((attackWithExt / attackTotal) * 100).toFixed(1) : "0.0";
  const noAttackTotal = noAttackRows.length;
  const noAttackClean = noAttackRows.filter((r: any) => r.external_strong_anomalies_count_30m === 0).length;
  const cleanRatio = noAttackTotal > 0 ? ((noAttackClean / noAttackTotal) * 100).toFixed(1) : "0.0";

  const severities = ["NONE", "LOW", "MEDIUM", "HIGH"];
  const sevTotals: number[] = [];
  const sevWithExt: number[] = [];
  const sevWithoutExt: number[] = [];
  for (const sev of severities) {
    const sevRows = rows.filter((r: any) => (r.wanguard_severity_class || "NONE") === sev);
    const total = sevRows.length;
    const withExt = sevRows.filter((r: any) => r.external_strong_anomalies_count_30m > 0).length;
    sevTotals.push(total);
    sevWithExt.push(withExt);
    sevWithoutExt.push(total - withExt);
  }

  const chartConfig = {
    type: "bar",
    data: {
      labels: severities,
      datasets: [
        { label: "Com sinal externo", data: sevWithExt, backgroundColor: "#f97316" },
        { label: "Sem sinal externo", data: sevWithoutExt, backgroundColor: "#3b82f6" },
      ],
    },
    options: {
      plugins: {
        title: { display: true, text: `Cobertura Externa vs Wanguard — ${asn}`, font: { size: 16 } },
        subtitle: { display: true, text: `Cobertura ataque: ${attackCoverage}% | Confiab. s/ ataque: ${cleanRatio}% | ${rows.length} amostras`, font: { size: 12 } },
      },
      scales: { x: { stacked: true }, y: { stacked: true, title: { display: true, text: "Amostras" } } },
    },
  };
  const chartUrl = `https://quickchart.io/chart?c=${encodeURIComponent(JSON.stringify(chartConfig))}&w=600&h=400&bkg=white`;

  const { data: monitors } = await supabase.from("monitored_asns").select("user_id").eq("asn", asn);
  if (!monitors || monitors.length === 0) return;
  const userIds = [...new Set(monitors.map((m: any) => m.user_id))];
  const { data: configs } = await supabase.from("telegram_config").select("chat_id").in("user_id", userIds).eq("enabled", true);
  if (!configs || configs.length === 0) return;

  const highIdx = severities.indexOf("HIGH");
  const highTotal = sevTotals[highIdx];
  const highWithExt = sevWithExt[highIdx];
  const highCoverage = highTotal > 0 ? ((highWithExt / highTotal) * 100).toFixed(1) : "0.0";

  const interpretationText =
    `\n\n📖 <b>Interpretação</b>\n` +
    `• A cobertura de ~${attackCoverage}% mostra que uma parte dos ataques vistos pelo Wanguard já deixa "pegadas" claras em fontes externas.\n` +
    `• A confiabilidade de ~${cleanRatio}% indica que, na maior parte do tempo sem ataque, as fontes externas permanecem silenciosas.\n` +
    `• Esse equilíbrio entre cobertura e confiabilidade é intencional.`;

  for (const cfg of configs) {
    try {
      const resp = await fetch(`${TELEGRAM_API_BASE}/bot${TELEGRAM_API_KEY}/sendPhoto`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          chat_id: cfg.chat_id,
          photo: chartUrl,
          caption: `📊 <b>Cobertura Externa vs Wanguard — ${asn}</b>\n\n` +
            `<b>Métricas atuais:</b>\n` +
            `• Total de janelas analisadas: ${rows.length}\n` +
            `• Cobertura em ataques: <b>${attackCoverage}%</b> (${attackWithExt} de ${attackTotal} janelas)\n` +
            `• Confiabilidade s/ ataque: <b>${cleanRatio}%</b> (${noAttackClean} de ${noAttackTotal} janelas)\n` +
            `• Cobertura HIGH: <b>${highCoverage}%</b> (${highWithExt} de ${highTotal} janelas)\n\n` +
            severities.map((s, i) => `• ${s}: ${sevTotals[i]} (${sevWithExt[i]} com sinal ext.)`).join("\n") +
            interpretationText +
            `\n\n🕐 ${new Date().toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}`,
          parse_mode: "HTML",
        }),
      });
      if (!resp.ok) { console.error(`Telegram sendPhoto failed [${resp.status}]:`, await resp.text()); }
      else { console.log(`Coverage image sent to chat ${cfg.chat_id}`); }
    } catch (sendErr) { console.error(`Failed to send to chat ${cfg.chat_id}:`, sendErr); }
  }
}

Deno.serve(async (req) => {
  const corsHeaders = buildCorsHeaders(req.headers.get("origin"));

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (!(await hasDatasetAccess(req))) {
    return new Response(JSON.stringify({ error: "Não autorizado" }), {
      status: 401,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const body = await req.json();
    const { asn = "AS267458", startDate, endDate, stepMinutes = 5, windowMinutes = 30 } = body;

    if (!startDate || !endDate) {
      return new Response(JSON.stringify({ error: "startDate and endDate required" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const start = new Date(startDate);
    const end = new Date(endDate);
    const bufferStart = new Date(start.getTime() - windowMinutes * 60000);
    const wgStartStr = bufferStart.toISOString().split("T")[0];
    const wgEndStr = end.toISOString().split("T")[0];

    console.log(`Fetching Wanguard anomalies from ${wgStartStr} to ${wgEndStr}`);
    const rawAnomalies = await fetchWanguardAnomalies(wgStartStr, wgEndStr);
    const anomalies = normalizeAnomalies(rawAnomalies);
    console.log(`Got ${anomalies.length} Wanguard anomalies`);

    const supabaseUrl = supabaseUrlEnv;
    const supabaseKey = supabaseServiceKeyEnv;
    const supabase = createClient(supabaseUrl, supabaseKey);

    const { data: externalRows } = await supabase
      .from("asn_incidents")
      .select("*")
      .eq("asn", asn)
      .gte("created_at", bufferStart.toISOString())
      .lte("created_at", end.toISOString());

    const externalEvents: ExternalEvent[] = (externalRows || []).map((r: any) => ({
      time: new Date(r.created_at),
      signals: r.signals as string[],
      status: r.status as string,
    }));

    const samples: any[] = [];
    let cursor = new Date(start);

    while (cursor <= end) {
      const windowEnd = new Date(cursor);
      const windowStart = new Date(cursor.getTime() - windowMinutes * 60000);

      const wgInWindow = anomalies.filter((a) => a.start >= windowStart && a.start <= windowEnd);
      const extInWindow = externalEvents.filter((e) => e.time >= windowStart && e.time <= windowEnd);

      const wanguard_attack_count = wgInWindow.length;
      const wanguard_is_under_attack = wanguard_attack_count > 0;
      const wanguard_max_bps = wgInWindow.length ? Math.max(...wgInWindow.map((a) => a.bps)) : null;
      const wanguard_max_pps = wgInWindow.length ? Math.max(...wgInWindow.map((a) => a.pps)) : null;

      let severity_class = "NONE";
      if (wanguard_max_bps != null) {
        if (wanguard_max_bps > 5e9) severity_class = "HIGH";
        else if (wanguard_max_bps > 1e9) severity_class = "MEDIUM";
        else if (wanguard_max_bps > 1e8) severity_class = "LOW";
      }

      const ripeCount = extInWindow.filter((e) => e.signals.some((s) => s.toLowerCase().includes("ripe"))).length;
      const strongCount = extInWindow.filter((e) => isStrongEvent(e)).length;
      const perSource = countPerSource(extInWindow);

      let ti_ips_total = 0;
      let ti_abuse_avg_score = 0;
      let ti_abuse_high_ratio = 0;
      let gn_noise_ratio = 0;
      let gn_malicious_ratio = 0;
      let gn_riot_ratio = 0;

      const { data: tiRow } = await supabase
        .from("asn_ip_reputation_window")
        .select("ips_total, avg_score, high_score_ips, gn_noise_ratio, gn_malicious_ratio, gn_riot_ratio")
        .eq("asn", asn)
        .eq("source", "abuseipdb")
        .gte("window_start", windowStart.toISOString())
        .lte("window_end", windowEnd.toISOString())
        .limit(1)
        .maybeSingle();

      if (tiRow) {
        const ipsTotal = tiRow.ips_total ?? 0;
        const avgScore = Number(tiRow.avg_score ?? 0);
        const highScoreIps = tiRow.high_score_ips ?? 0;
        ti_ips_total = ipsTotal;
        ti_abuse_avg_score = ipsTotal > 0 ? avgScore / 100 : 0;
        ti_abuse_high_ratio = ipsTotal > 0 ? highScoreIps / ipsTotal : 0;
        gn_noise_ratio = Number(tiRow.gn_noise_ratio ?? 0);
        gn_malicious_ratio = Number(tiRow.gn_malicious_ratio ?? 0);
        gn_riot_ratio = Number(tiRow.gn_riot_ratio ?? 0);
      }

      const ti_combined_score = Math.max(0, Math.min(1,
        (ti_abuse_avg_score) * 0.5 + gn_malicious_ratio * 0.4 - gn_riot_ratio * 0.1
      ));

      samples.push({
        asn,
        timestamp: windowEnd.toISOString(),
        external_anomalies_count_30m: extInWindow.length,
        ripe_events_count_30m: ripeCount,
        qrator_events_count_30m: perSource.qrator,
        external_strong_anomalies_count_30m: strongCount,
        rpki_events_count_30m: perSource.rpki,
        ripestat_events_count_30m: perSource.ripestat,
        bgp_events_count_30m: perSource.bgp,
        wanguard_is_under_attack,
        wanguard_attack_count_30m: wanguard_attack_count,
        wanguard_max_bps_30m: wanguard_max_bps,
        wanguard_max_pps_30m: wanguard_max_pps,
        wanguard_severity_class: severity_class,
        ti_ips_total,
        ti_abuse_avg_score: Math.round(ti_abuse_avg_score * 1000) / 1000,
        ti_abuse_high_ratio: Math.round(ti_abuse_high_ratio * 1000) / 1000,
        gn_noise_ratio: Math.round(gn_noise_ratio * 1000) / 1000,
        gn_malicious_ratio: Math.round(gn_malicious_ratio * 1000) / 1000,
        gn_riot_ratio: Math.round(gn_riot_ratio * 1000) / 1000,
        ti_combined_score: Math.round(ti_combined_score * 1000) / 1000,
      });

      cursor = new Date(cursor.getTime() + stepMinutes * 60000);
    }

    let inserted = 0;
    for (let i = 0; i < samples.length; i += 500) {
      const chunk = samples.slice(i, i + 500);
      const { error } = await supabase.from("as_attack_samples").upsert(chunk, {
        onConflict: "asn,timestamp",
        ignoreDuplicates: false,
      });
      if (error) { console.error("Insert error:", error); throw new Error(`Insert failed: ${error.message}`); }
      inserted += chunk.length;
    }

    console.log(`Generated ${inserted} samples`);

    try { await sendCoverageToTelegram(supabase, asn); }
    catch (tgErr) { console.error("Telegram coverage image error (non-fatal):", tgErr); }

    return new Response(
      JSON.stringify({ samplesCreated: inserted, wanguardAnomaliesFound: anomalies.length }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("generate-dataset error:", error);
    return new Response(
      JSON.stringify({ error: String(error) }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
