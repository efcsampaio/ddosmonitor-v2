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

// Antes: sem checagem nenhuma na rota, aberta pra qualquer chamada com a
// anon key. Agora exige um JWT de sessão real de usuário — mesmo padrão
// aplicado em estimate-attack-risk e wanguard-proxy.
function getUserIdFromRequest(req: Request): string | null {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;
  try {
    const token = authHeader.split(" ")[1];
    const payload = JSON.parse(atob(token.split(".")[1]));
    return payload.sub || null;
  } catch { return null; }
}

Deno.serve(async (req) => {
  const corsHeaders = buildCorsHeaders(req.headers.get("origin"));

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const userId = getUserIdFromRequest(req);
  if (!userId) {
    return new Response(
      JSON.stringify({ error: "Não autenticado" }),
      { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  try {
    const url = new URL(req.url);
    const asn = url.searchParams.get("asn") || "AS267458";

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const { data: rows, error } = await supabase
      .from("as_attack_samples")
      .select("wanguard_is_under_attack, wanguard_severity_class, external_anomalies_count_30m, external_strong_anomalies_count_30m")
      .eq("asn", asn);

    if (error) throw new Error(error.message);
    if (!rows || rows.length === 0) {
      return new Response(JSON.stringify({
        asn,
        total_samples: 0,
        attack_windows_total: 0,
        attack_windows_with_external: 0,
        attack_windows_without_external: 0,
        attack_coverage_ratio: 0,
        no_attack_windows_total: 0,
        no_attack_windows_with_external: 0,
        no_attack_windows_without_external: 0,
        no_attack_clean_ratio: 0,
        by_severity: [],
      }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const total_samples = rows.length;

    const attackRows = rows.filter((r: any) => r.wanguard_is_under_attack === true);
    const noAttackRows = rows.filter((r: any) => r.wanguard_is_under_attack === false);

    const attack_windows_total = attackRows.length;
    // Use strong anomalies for coverage (easily switchable back to external_anomalies_count_30m)
    const externalField = "external_strong_anomalies_count_30m";
    const attack_windows_with_external = attackRows.filter((r: any) => r[externalField] > 0).length;
    const attack_windows_without_external = attack_windows_total - attack_windows_with_external;
    const attack_coverage_ratio = attack_windows_total > 0 ? attack_windows_with_external / attack_windows_total : 0;

    const no_attack_windows_total = noAttackRows.length;
    const no_attack_windows_with_external = noAttackRows.filter((r: any) => r[externalField] > 0).length;
    const no_attack_windows_without_external = no_attack_windows_total - no_attack_windows_with_external;
    const no_attack_clean_ratio = no_attack_windows_total > 0 ? no_attack_windows_without_external / no_attack_windows_total : 0;

    // By severity
    const severityOrder = ["NONE", "LOW", "MEDIUM", "HIGH"];
    const severityMap = new Map<string, { total: number; with_external: number }>();
    for (const sev of severityOrder) {
      severityMap.set(sev, { total: 0, with_external: 0 });
    }

    for (const r of rows as any[]) {
      const sev = r.wanguard_severity_class || "NONE";
      if (!severityMap.has(sev)) severityMap.set(sev, { total: 0, with_external: 0 });
      const entry = severityMap.get(sev)!;
      entry.total++;
      if (r[externalField] > 0) entry.with_external++;
    }

    const by_severity = severityOrder
      .filter((sev) => severityMap.has(sev))
      .map((sev) => {
        const e = severityMap.get(sev)!;
        return {
          severity: sev,
          total: e.total,
          with_external: e.with_external,
          without_external: e.total - e.with_external,
          coverage_ratio: e.total > 0 ? e.with_external / e.total : 0,
        };
      });

    return new Response(JSON.stringify({
      asn,
      total_samples,
      attack_windows_total,
      attack_windows_with_external,
      attack_windows_without_external,
      attack_coverage_ratio,
      no_attack_windows_total,
      no_attack_windows_with_external,
      no_attack_windows_without_external,
      no_attack_clean_ratio,
      by_severity,
    }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (err) {
    console.error("learning-metrics error:", err);
    return new Response(JSON.stringify({ success: false, error: String(err) }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
