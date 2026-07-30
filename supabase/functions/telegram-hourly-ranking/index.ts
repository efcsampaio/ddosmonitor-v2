import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

// Antes: passava por um proxy do Lovable (connector-gateway.lovable.dev),
// que exigia LOVABLE_API_KEY além do token do bot. Chamando a API do
// Telegram direto, só o token do bot (TELEGRAM_API_KEY) é necessário.
const TELEGRAM_API_BASE = "https://api.telegram.org";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supabase = createClient(supabaseUrl, supabaseKey);

// Mesmo esquema de CORS restrito usado nas outras functions.
const corsHeadersStatic = {
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};
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

// Essa function só deveria ser chamada pelo agendador (cron/Scheduled
// Function), nunca pelo frontend — antes não havia checagem nenhuma na
// rota, então qualquer request externo conseguia disparar o envio.
function isServiceRoleRequest(req: Request): boolean {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return false;
  return authHeader.slice("Bearer ".length) === supabaseKey;
}

interface RankingEntry {
  asn: string;
  name: string;
  total: number;
  attacks: number;
  warnings: number;
  avg_packet_loss: number;
  avg_visibility: number;
}

async function getHourlyRanking(): Promise<RankingEntry[]> {
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();

  const { data: incidents, error } = await supabase
    .from("asn_incidents")
    .select("asn, name, status, packet_loss_percent, visibility_percent")
    .gte("created_at", oneHourAgo);

  if (error || !incidents || incidents.length === 0) return [];

  // Aggregate by ASN
  const map = new Map<string, {
    name: string;
    total: number;
    attacks: number;
    warnings: number;
    packetLossSum: number;
    visibilitySum: number;
    count: number;
  }>();

  for (const inc of incidents) {
    const entry = map.get(inc.asn) || {
      name: inc.name,
      total: 0,
      attacks: 0,
      warnings: 0,
      packetLossSum: 0,
      visibilitySum: 0,
      count: 0,
    };
    entry.total++;
    if (inc.status === "UNDER_ATTACK") entry.attacks++;
    if (inc.status === "WARNING") entry.warnings++;
    entry.packetLossSum += inc.packet_loss_percent ?? 0;
    entry.visibilitySum += inc.visibility_percent ?? 100;
    entry.count++;
    map.set(inc.asn, entry);
  }

  return Array.from(map.entries())
    .map(([asn, e]) => ({
      asn,
      name: e.name,
      total: e.total,
      attacks: e.attacks,
      warnings: e.warnings,
      avg_packet_loss: e.count > 0 ? Math.round((e.packetLossSum / e.count) * 100) / 100 : 0,
      avg_visibility: e.count > 0 ? Math.round((e.visibilitySum / e.count) * 100) / 100 : 100,
    }))
    .sort((a, b) => b.total - a.total);
}

function buildRankingMessage(ranking: RankingEntry[]): string {
  const now = new Date();
  const hora = now.toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo", hour: "2-digit", minute: "2-digit" });
  const data = now.toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo", day: "2-digit", month: "2-digit", year: "numeric" });

  if (ranking.length === 0) {
    return [
      `📊 <b>Ranking Horário — ${hora} (${data})</b>`,
      ``,
      `✅ Nenhum incidente registrado na última hora.`,
    ].join("\n");
  }

  const lines = [
    `📊 <b>Ranking de Instabilidade — Última Hora</b>`,
    `🕐 ${hora} — ${data}`,
    ``,
    `Total de incidentes: <b>${ranking.reduce((s, r) => s + r.total, 0)}</b>`,
    ``,
  ];

  const medals = ["🥇", "🥈", "🥉"];

  for (let i = 0; i < Math.min(ranking.length, 10); i++) {
    const r = ranking[i];
    const prefix = i < 3 ? medals[i] : `${i + 1}.`;
    lines.push(
      `${prefix} <b>${r.asn}</b> — ${r.name}`,
      `   📈 ${r.total} incidentes | 🚨 ${r.attacks} ataques | ⚠️ ${r.warnings} alertas`,
      `   📉 Perda média: ${r.avg_packet_loss}% | 👁 Visibilidade: ${r.avg_visibility}%`,
      ``
    );
  }

  if (ranking.length > 10) {
    lines.push(`<i>... e mais ${ranking.length - 10} ASNs com incidentes</i>`);
  }

  return lines.join("\n");
}

// Antes: buscava o destinatário via profiles.username === "edson" (hardcoded).
// Agora: qualquer usuário com a role 'master_admin' em user_roles recebe o
// ranking — não depende de um username fixo, e suporta mais de um admin.
async function getMasterAdminUserIds(): Promise<string[]> {
  const { data, error } = await supabase
    .from("user_roles")
    .select("user_id")
    .eq("role", "master_admin");

  if (error || !data) return [];
  return data.map((r: { user_id: string }) => r.user_id);
}

async function sendToAllEnabledUsers(message: string) {
  const TELEGRAM_API_KEY = Deno.env.get("TELEGRAM_API_KEY");
  if (!TELEGRAM_API_KEY) {
    console.error("TELEGRAM_API_KEY is not configured");
    return;
  }

  const masterAdminIds = await getMasterAdminUserIds();
  if (masterAdminIds.length === 0) {
    console.error("Nenhum master admin encontrado (role 'master_admin' em user_roles)");
    return;
  }

  const { data: configs, error } = await supabase
    .from("telegram_config")
    .select("chat_id")
    .in("user_id", masterAdminIds)
    .eq("enabled", true);

  if (error || !configs || configs.length === 0) {
    console.log("No enabled telegram config for master admin(s)");
    return;
  }

  for (const cfg of configs) {
    try {
      const response = await fetch(`${TELEGRAM_API_BASE}/bot${TELEGRAM_API_KEY}/sendMessage`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          chat_id: cfg.chat_id,
          text: message,
          parse_mode: "HTML",
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        console.error(`Telegram error [${response.status}]:`, data);
      } else {
        console.log(`Ranking sent to chat ${cfg.chat_id}`);
      }
    } catch (err) {
      console.error("Send error:", err);
    }
  }
}

Deno.serve(async (req) => {
  const corsHeaders = buildCorsHeaders(req.headers.get("origin"));

  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  if (!isServiceRoleRequest(req)) {
    return new Response(JSON.stringify({ error: "Não autorizado" }), {
      status: 401,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const ranking = await getHourlyRanking();
    const message = buildRankingMessage(ranking);
    await sendToAllEnabledUsers(message);

    return new Response(JSON.stringify({ ok: true, asnCount: ranking.length }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("Hourly ranking error:", err);
    return new Response(JSON.stringify({ error: "Internal error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
