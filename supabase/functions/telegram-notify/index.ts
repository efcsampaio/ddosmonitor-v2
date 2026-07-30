import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const corsHeadersStatic = {
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

// Mesmo esquema de CORS restrito usado em asn-monitor / wanguard-proxy.
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

// Antes: passava por um proxy do Lovable (connector-gateway.lovable.dev),
// que exigia LOVABLE_API_KEY além do token do bot. Chamando a API do
// Telegram direto, só o token do bot (TELEGRAM_API_KEY) é necessário.
const TELEGRAM_API_BASE = "https://api.telegram.org";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabase = createClient(supabaseUrl, supabaseKey);

// /notify, /risk-alert e /third-party-alert são chamadas só por outras
// Edge Functions (asn-monitor, estimate-attack-risk) usando a service role
// key — nunca pelo frontend. Antes não havia checagem nenhuma nessas rotas.
function isServiceRoleRequest(req: Request): boolean {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return false;
  return authHeader.slice("Bearer ".length) === supabaseKey;
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

interface TelegramNotifyPayload {
  asn: string;
  name: string;
  status: "UNDER_ATTACK" | "WARNING" | "HEALTHY";
  signals: string[];
  visibility_percent?: number;
  packet_loss_percent?: number;
}

function buildMessage(payload: TelegramNotifyPayload): string {
  const statusEmoji: Record<string, string> = {
    UNDER_ATTACK: "🚨",
    WARNING: "⚠️",
    HEALTHY: "✅",
  };
  const statusLabel: Record<string, string> = {
    UNDER_ATTACK: "SOB ATAQUE",
    WARNING: "ALERTA",
    HEALTHY: "RECUPERADO",
  };

  const emoji = statusEmoji[payload.status] || "ℹ️";
  const label = statusLabel[payload.status] || payload.status;
  const lines = [
    `${emoji} <b>DDoS Monitor — ${label}</b>`,
    ``,
    `<b>ASN:</b> ${payload.asn} (${payload.name})`,
  ];

  if (payload.visibility_percent !== undefined) {
    lines.push(`<b>Visibilidade BGP:</b> ${payload.visibility_percent}%`);
  }
  if (payload.packet_loss_percent !== undefined) {
    lines.push(`<b>Perda de pacotes:</b> ${payload.packet_loss_percent}%`);
  }

  if (payload.signals && payload.signals.length > 0) {
    lines.push(``, `<b>Sinais:</b>`);
    for (const s of payload.signals.slice(0, 8)) {
      lines.push(`• ${s}`);
    }
  }

  lines.push(``, `🕐 ${new Date().toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}`);
  return lines.join("\n");
}

async function sendTelegramMessage(chatId: string, text: string): Promise<boolean> {
  const TELEGRAM_API_KEY = Deno.env.get("TELEGRAM_API_KEY");
  if (!TELEGRAM_API_KEY) {
    console.error("TELEGRAM_API_KEY is not configured");
    return false;
  }

  try {
    const response = await fetch(`${TELEGRAM_API_BASE}/bot${TELEGRAM_API_KEY}/sendMessage`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: "HTML",
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      console.error(`Telegram API error [${response.status}]:`, data);
      return false;
    }
    return true;
  } catch (err) {
    console.error("Telegram send error:", err);
    return false;
  }
}

// Send notification to all users who monitor a given ASN
async function notifyAllUsersForAsn(payload: TelegramNotifyPayload) {
  // Find all users who monitor this ASN
  const { data: monitors, error: monErr } = await supabase
    .from("monitored_asns")
    .select("user_id")
    .eq("asn", payload.asn);

  if (monErr || !monitors || monitors.length === 0) return;

  const userIds = [...new Set(monitors.map((m: { user_id: string }) => m.user_id))];

  // Get telegram configs for these users
  const { data: configs, error: cfgErr } = await supabase
    .from("telegram_config")
    .select("*")
    .in("user_id", userIds)
    .eq("enabled", true);

  if (cfgErr || !configs || configs.length === 0) return;

  const message = buildMessage(payload);

  for (const cfg of configs) {
    // Never send recovery notifications
    if (payload.status === "HEALTHY") continue;
    // Check notification preferences
    if (payload.status === "UNDER_ATTACK" && !cfg.notify_attacks) continue;
    if (payload.status === "WARNING" && !cfg.notify_warnings) continue;

    await sendTelegramMessage(cfg.chat_id, message);
  }
}

// ============================================================
// IP reputation description heuristic
// ============================================================
function describeIpReputation(score: number, reports: number): string {
  if (score >= 80) return "IP frequentemente reportado em ataques DDoS e tentativas de login.";
  if (score >= 50) return "IP envolvido em varreduras de porta e tentativas de acesso indevido.";
  if (score >= 20) return "IP com histórico de atividade suspeita contra múltiplos alvos.";
  return "IP com poucos reports de atividade suspeita.";
}

// ============================================================
// Build TI-enriched risk alert message
// ============================================================
interface RiskAlertPayload {
  asn: string;
  risk_score: number;
  risk_label: string;
  sources: string[];
  window_start: string;
  window_end: string;
  ti: {
    ips_total: number;
    ips_with_score: number;
    high_score_ips: number;
    avg_score: number;
  } | null;
  top_ips: { ip: string; reputation_score: number; reports_count: number }[];
}

function buildRiskAlertMessage(payload: RiskAlertPayload): string {
  const pct = Math.round(payload.risk_score * 100);
  const lines: string[] = [
    `🚨 <b>ATAQUE DETECTADO (CRÍTICO)</b>`,
    ``,
    `<b>ASN:</b> ${payload.asn}`,
    `<b>Risco:</b> ${pct}% (${payload.risk_label})`,
    `<b>Fontes:</b> ${payload.sources.length > 0 ? payload.sources.join(" + ") : "Modelo preditivo"}`,
  ];

  // TI block
  lines.push(``, `<b>Threat Intelligence (AbuseIPDB):</b>`);
  if (payload.ti && payload.ti.ips_with_score > 0) {
    lines.push(`• ${payload.ti.high_score_ips} IPs maliciosos detectados nos últimos 30 minutos`);
    lines.push(`• Score médio de reputação: ${Math.round(payload.ti.avg_score)}/100`);
  } else {
    lines.push(`• Nenhum IP malicioso detectado pela AbuseIPDB nesta janela.`);
  }

  // IP details block
  if (payload.top_ips && payload.top_ips.length > 0) {
    lines.push(``, `<b>Detalhes dos IPs:</b>`);
    payload.top_ips.forEach((ip, i) => {
      lines.push(`${i + 1}) <code>${ip.ip}</code> — score ${ip.reputation_score}/100, ${ip.reports_count} reports`);
      lines.push(`   <i>${describeIpReputation(ip.reputation_score, ip.reports_count)}</i>`);
    });
  }

  // Window time
  const wStart = new Date(payload.window_start);
  const wEnd = new Date(payload.window_end);
  const fmt = (d: Date) => d.toLocaleTimeString("pt-BR", { timeZone: "America/Sao_Paulo", hour: "2-digit", minute: "2-digit" });
  lines.push(``, `🕐 <b>Janela:</b> ${fmt(wStart)}–${fmt(wEnd)} (Brasília)`);

  return lines.join("\n");
}

// Notify all users monitoring this ASN about risk alert
async function notifyRiskAlert(payload: RiskAlertPayload) {
  // Find users who monitor this ASN
  const { data: monitors } = await supabase
    .from("monitored_asns")
    .select("user_id")
    .eq("asn", payload.asn);

  if (!monitors || monitors.length === 0) return;

  const userIds = [...new Set(monitors.map((m: { user_id: string }) => m.user_id))];

  const { data: configs } = await supabase
    .from("telegram_config")
    .select("*")
    .in("user_id", userIds)
    .eq("enabled", true)
    .eq("notify_attacks", true);

  if (!configs || configs.length === 0) return;

  const message = buildRiskAlertMessage(payload);

  for (const cfg of configs) {
    await sendTelegramMessage(cfg.chat_id, message);
  }

  // Log alert to alerts_history
  const sourcesObj: Record<string, boolean> = {};
  for (const s of payload.sources) {
    sourcesObj[s.toLowerCase()] = true;
  }
  if (payload.ti && payload.ti.avg_score > 0) {
    sourcesObj["abuseipdb"] = true;
  }

  let tiSummary = "Nenhum IP malicioso detectado nesta janela";
  if (payload.ti && payload.ti.ips_with_score > 0) {
    tiSummary = `${payload.ti.high_score_ips} IPs maliciosos (score médio ${Math.round(payload.ti.avg_score)}/100)`;
  }

  await supabase.from("alerts_history").insert({
    asn: payload.asn,
    risk_score: payload.risk_score,
    risk_label: payload.risk_label,
    sources: sourcesObj,
    ti_summary: tiSummary,
  });
}

// ============================================================
// Third-party ASN attack detection
// ============================================================
const MY_ASNS = [267458, 266953];

// Dedup: asn -> last notified timestamp
const thirdPartyLastNotified = new Map<number, number>();
const DEDUP_WINDOW_MS = 3 * 60 * 60 * 1000; // 3 horas

interface ThirdPartyAlertPayload {
  asn: number;
  asName?: string;
  timestamp: string; // ISO string
  reasons: string[];
  externalAnomaly: boolean;
  externalSeverity?: string;
  peakGbps?: number;
  affectedPrefix?: string;
  anomalyDurationMin?: number;
}

function buildAttackReasons(payload: ThirdPartyAlertPayload): string[] {
  const reasons: string[] = [];
  if (payload.externalAnomaly) {
    reasons.push("Anomalia detectada por fonte externa");
  }
  if (payload.externalSeverity) {
    reasons.push(`Severidade externa: ${payload.externalSeverity.toUpperCase()}`);
  }
  if (payload.peakGbps !== undefined && payload.peakGbps > 0) {
    reasons.push(`Pico de tráfego: ${payload.peakGbps.toFixed(2)} Gbps`);
  }
  if (payload.affectedPrefix) {
    reasons.push(`Prefixo afetado: ${payload.affectedPrefix}`);
  }
  if (payload.anomalyDurationMin !== undefined && payload.anomalyDurationMin > 0) {
    reasons.push(`Duração da anomalia: ${payload.anomalyDurationMin} min`);
  }
  // Also include any extra reasons passed directly
  if (payload.reasons?.length > 0) {
    for (const r of payload.reasons) {
      if (!reasons.includes(r)) reasons.push(r);
    }
  }
  return reasons;
}

function buildThirdPartyMessage(payload: ThirdPartyAlertPayload, reasons: string[]): string {
  const ts = new Date(payload.timestamp);
  const formatted = ts.toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" });
  const lines = [
    `🚨 <b>POSSÍVEL ATAQUE — ASN DE TERCEIRO</b>`,
    ``,
    `<b>ASN:</b> ${payload.asn}`,
    `<b>Nome:</b> ${payload.asName || "Não identificado"}`,
    `<b>Hora:</b> ${formatted}`,
    ``,
    `📋 <b>Motivo:</b>`,
  ];
  for (const r of reasons) {
    lines.push(`• ${r}`);
  }
  lines.push(``, `⚠️ Nenhuma ação automática foi tomada.`);
  lines.push(`Verifique impacto no upstream ou rotas BGP.`);
  return lines.join("\n");
}

async function notifyThirdPartyAttack(payload: ThirdPartyAlertPayload) {
  // Check if it's a own ASN — skip
  if (MY_ASNS.includes(payload.asn)) return;

  // Dedup check
  const now = Date.now();
  const lastNotif = thirdPartyLastNotified.get(payload.asn);
  if (lastNotif && now - lastNotif < DEDUP_WINDOW_MS) {
    console.log(`Skipping notification for ASN ${payload.asn}: dedup window 3h not elapsed`);
    return;
  }

  const reasons = buildAttackReasons(payload);
  if (reasons.length === 0) return;

  const message = buildThirdPartyMessage(payload, reasons);

  // Send to all users with telegram enabled and notify_attacks = true
  const { data: configs } = await supabase
    .from("telegram_config")
    .select("*")
    .eq("enabled", true)
    .eq("notify_attacks", true);

  if (!configs || configs.length === 0) return;

  let sent = false;
  for (const cfg of configs) {
    const ok = await sendTelegramMessage(cfg.chat_id, message);
    if (ok) sent = true;
  }

  if (sent) {
    thirdPartyLastNotified.set(payload.asn, now);
  }
}

Deno.serve(async (req) => {
  const corsHeaders = buildCorsHeaders(req.headers.get("origin"));

  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/telegram-notify/, "");

  // POST /notify — called internally by asn-monitor
  if (req.method === "POST" && (path === "/notify" || path === "" || path === "/")) {
    if (!isServiceRoleRequest(req)) {
      return new Response(JSON.stringify({ error: "Não autorizado" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    try {
      const payload: TelegramNotifyPayload = await req.json();
      await notifyAllUsersForAsn(payload);
      return new Response(JSON.stringify({ ok: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    } catch (err) {
      console.error("Notify error:", err);
      return new Response(JSON.stringify({ error: "Invalid payload" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  }

  // POST /risk-alert — TI-enriched risk alert from estimate-attack-risk
  if (req.method === "POST" && path === "/risk-alert") {
    if (!isServiceRoleRequest(req)) {
      return new Response(JSON.stringify({ error: "Não autorizado" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    try {
      const payload: RiskAlertPayload = await req.json();
      await notifyRiskAlert(payload);
      return new Response(JSON.stringify({ ok: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    } catch (err) {
      console.error("Risk alert error:", err);
      return new Response(JSON.stringify({ error: "Invalid payload" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  }

  // POST /third-party-alert — alert for possible attack on third-party ASN
  if (req.method === "POST" && path === "/third-party-alert") {
    if (!isServiceRoleRequest(req)) {
      return new Response(JSON.stringify({ error: "Não autorizado" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    try {
      const payload: ThirdPartyAlertPayload = await req.json();
      await notifyThirdPartyAttack(payload);
      return new Response(JSON.stringify({ ok: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    } catch (err) {
      console.error("Third-party alert error:", err);
      return new Response(JSON.stringify({ error: "Invalid payload" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  }
  if (req.method === "POST" && path === "/test") {
    const userId = getUserIdFromRequest(req);
    if (!userId) {
      return new Response(JSON.stringify({ error: "Não autenticado" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    try {
      const { chat_id } = await req.json();
      if (!chat_id) {
        return new Response(JSON.stringify({ error: "chat_id required" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Antes: qualquer usuário autenticado podia mandar teste pra QUALQUER
      // chat_id. Agora: só é permitido testar um chat_id que já está
      // cadastrado como do próprio usuário.
      const { data: ownConfig } = await supabase
        .from("telegram_config")
        .select("chat_id")
        .eq("user_id", userId)
        .eq("chat_id", chat_id)
        .maybeSingle();

      if (!ownConfig) {
        return new Response(JSON.stringify({ error: "chat_id não pertence à sua configuração" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const testMessage = buildMessage({
        asn: "AS00000",
        name: "Teste",
        status: "WARNING",
        signals: ["⚠️ Mensagem de teste do DDoS Monitor"],
      });

      const ok = await sendTelegramMessage(chat_id, testMessage);
      return new Response(JSON.stringify({ ok }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    } catch {
      return new Response(JSON.stringify({ error: "Invalid request" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  }

  return new Response(JSON.stringify({ error: "Not found" }), {
    status: 404,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
});
