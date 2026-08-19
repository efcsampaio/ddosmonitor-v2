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

// Antes: qualquer chamada com a anon key (pública, embutida no bundle do
// frontend) conseguia disparar o treino do modelo, mesmo sem usuário
// logado. Agora: exige um JWT de sessão real — a anon key não tem `sub`
// no payload, então é rejeitada automaticamente por este check.
//
// Descoberto ao migrar: o cron "estimate-attack-risk-cron" (a cada 15min)
// sempre chamava aqui com a service_role key, mas essa key também não tem
// `sub` no payload — então o cron falhava com 401 em toda execução desde
// sempre, silenciosamente (pg_cron só confirma que o net.http_post foi
// enfileirado, não o status HTTP da resposta). userId nunca é usado pra
// filtrar dados (só como gate de autenticação), então é seguro liberar
// também a service role, igual ao padrão já usado em wanguard-proxy.
function isServiceRoleRequest(req: Request): boolean {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return false;
  return authHeader.slice("Bearer ".length) === Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
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

interface FeatureVector {
  strong_count: number;
  qrator_count: number;
  rpki_count: number;
  ripestat_count: number;
  bgp_count: number;
  has_combo_strong: boolean;
  ti_ips_total: number;
  ti_abuse_avg_score: number;
  ti_abuse_high_ratio: number;
  gn_noise_ratio: number;
  gn_malicious_ratio: number;
  gn_riot_ratio: number;
  ti_combined_score: number;
}

interface ModelWeights {
  bias: number;
  w_strong_count: number;
  w_qrator_count: number;
  w_rpki_count: number;
  w_ripestat_count: number;
  w_bgp_count: number;
  w_combo_strong: number;
  w_ti_abuse_avg_score: number;
  w_ti_abuse_high_ratio: number;
  w_ti_combined_score: number;
}

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-Math.max(-500, Math.min(500, x))));
}

function predict(w: ModelWeights, f: FeatureVector): number {
  const z = w.bias
    + w.w_strong_count * f.strong_count
    + w.w_qrator_count * f.qrator_count
    + w.w_rpki_count * f.rpki_count
    + w.w_ripestat_count * f.ripestat_count
    + w.w_bgp_count * f.bgp_count
    + w.w_combo_strong * (f.has_combo_strong ? 1 : 0)
    + w.w_ti_abuse_avg_score * f.ti_abuse_avg_score
    + w.w_ti_abuse_high_ratio * f.ti_abuse_high_ratio
    + w.w_ti_combined_score * f.ti_combined_score;
  return sigmoid(z);
}

function extractFeatures(row: any): FeatureVector {
  const qc = Number(row.qrator_count ?? row.qrator_events_count_30m ?? 0);
  const rc = Number(row.rpki_count ?? row.rpki_events_count_30m ?? 0);
  const rs = Number(row.ripestat_count ?? row.ripestat_events_count_30m ?? 0);
  const bg = Number(row.bgp_count ?? row.bgp_events_count_30m ?? 0);
  const sources = [qc > 0, rc > 0, rs > 0, bg > 0].filter(Boolean).length;

  const gnNoiseRatio = Number(row.gn_noise_ratio ?? 0);
  const gnMaliciousRatio = Number(row.gn_malicious_ratio ?? 0);
  const gnRiotRatio = Number(row.gn_riot_ratio ?? 0);
  const tiAbuse = Number(row.ti_abuse_avg_score ?? 0);
  const tiCombined = Number(row.ti_combined_score ?? 
    Math.max(0, Math.min(1, tiAbuse * 0.5 + gnMaliciousRatio * 0.4 - gnRiotRatio * 0.1)));

  return {
    strong_count: Number(row.strong_count ?? row.external_strong_anomalies_count_30m ?? 0),
    qrator_count: qc,
    rpki_count: rc,
    ripestat_count: rs,
    bgp_count: bg,
    has_combo_strong: row.has_combo_strong ?? sources >= 2,
    ti_ips_total: Number(row.ti_ips_total ?? 0),
    ti_abuse_avg_score: tiAbuse,
    ti_abuse_high_ratio: Number(row.ti_abuse_high_ratio ?? 0),
    gn_noise_ratio: gnNoiseRatio,
    gn_malicious_ratio: gnMaliciousRatio,
    gn_riot_ratio: gnRiotRatio,
    ti_combined_score: tiCombined,
  };
}

function trainModel(rows: any[], lr = 0.01, epochs = 300): ModelWeights {
  const w: ModelWeights = {
    bias: 0, w_strong_count: 0, w_qrator_count: 0,
    w_rpki_count: 0, w_ripestat_count: 0, w_bgp_count: 0, w_combo_strong: 0,
    w_ti_abuse_avg_score: 0, w_ti_abuse_high_ratio: 0, w_ti_combined_score: 0,
  };

  for (let epoch = 0; epoch < epochs; epoch++) {
    let dB = 0, dS = 0, dQ = 0, dR = 0, dRS = 0, dBG = 0, dC = 0;
    let dTiAvg = 0, dTiHigh = 0, dTiCombined = 0;

    for (const row of rows) {
      const f = extractFeatures(row);
      const pred = predict(w, f);
      const y = row.is_attack ? 1 : 0;
      const err = pred - y;

      dB += err;
      dS += err * f.strong_count;
      dQ += err * f.qrator_count;
      dR += err * f.rpki_count;
      dRS += err * f.ripestat_count;
      dBG += err * f.bgp_count;
      dC += err * (f.has_combo_strong ? 1 : 0);
      dTiAvg += err * f.ti_abuse_avg_score;
      dTiHigh += err * f.ti_abuse_high_ratio;
      dTiCombined += err * f.ti_combined_score;
    }

    const n = rows.length || 1;
    w.bias -= lr * (dB / n);
    w.w_strong_count -= lr * (dS / n);
    w.w_qrator_count -= lr * (dQ / n);
    w.w_rpki_count -= lr * (dR / n);
    w.w_ripestat_count -= lr * (dRS / n);
    w.w_bgp_count -= lr * (dBG / n);
    w.w_combo_strong -= lr * (dC / n);
    w.w_ti_abuse_avg_score -= lr * (dTiAvg / n);
    w.w_ti_abuse_high_ratio -= lr * (dTiHigh / n);
    w.w_ti_combined_score -= lr * (dTiCombined / n);
  }

  return w;
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

function isStrongEvent(status: string, signals: string[]): boolean {
  if (status === "CRITICAL") return true;
  if (status === "WARNING") return signals.some((s) => matchesAny(s, allStrongPatterns));
  return false;
}

function computeWindowFeatures(incidents: any[]): FeatureVector {
  let strong = 0, qrator = 0, rpki = 0, ripestat = 0, bgp = 0;
  for (const inc of incidents) {
    const signals = inc.signals as string[];
    if (!isStrongEvent(inc.status, signals)) continue;
    strong++;
    if (signals.some((s: string) => matchesAny(s, qratorPatterns))) qrator++;
    if (signals.some((s: string) => matchesAny(s, rpkiPatterns))) rpki++;
    if (signals.some((s: string) => matchesAny(s, ripestatPatterns))) ripestat++;
    if (signals.some((s: string) => matchesAny(s, bgpPatterns))) bgp++;
  }
  const sources = [qrator > 0, rpki > 0, ripestat > 0, bgp > 0].filter(Boolean).length;
  return {
    strong_count: strong, qrator_count: qrator, rpki_count: rpki,
    ripestat_count: ripestat, bgp_count: bgp, has_combo_strong: sources >= 2,
    ti_ips_total: 0, ti_abuse_avg_score: 0, ti_abuse_high_ratio: 0,
    gn_noise_ratio: 0, gn_malicious_ratio: 0, gn_riot_ratio: 0, ti_combined_score: 0,
  };
}

function computeHeuristicScore(features: FeatureVector): number {
  let s = 0;
  const qratorContrib   = Math.min(features.qrator_count   / 3, 1) * 0.30;
  const rpkiContrib     = Math.min(features.rpki_count     / 2, 1) * 0.20;
  const bgpContrib      = Math.min(features.bgp_count      / 3, 1) * 0.20;
  const ripestatContrib = Math.min(features.ripestat_count / 2, 1) * 0.15;
  s = qratorContrib + rpkiContrib + bgpContrib + ripestatContrib;

  const strongSources = [
    features.qrator_count >= 2, features.rpki_count >= 2,
    features.bgp_count >= 2, features.ripestat_count >= 2,
  ].filter(Boolean).length;
  if (strongSources >= 2) s += 0.15;

  // ── Threat Intelligence (AbuseIPDB + GreyNoise combined) ──
  // Base TI bonus from AbuseIPDB high ratio
  if (features.ti_abuse_high_ratio > 0) {
    const abuseBonus = Math.min(features.ti_abuse_high_ratio, 0.5) * 0.10;
    s += abuseBonus;
  }

  // GreyNoise adjustments
  if (features.gn_riot_ratio > 0.5) {
    // Most IPs are legitimate (CDN/Google) → reduce TI contribution
    s -= 0.03;
  } else if (features.gn_malicious_ratio > 0.3) {
    // 30%+ confirmed malicious by GreyNoise → boost
    s += Math.min(features.gn_malicious_ratio, 0.6) * 0.08;
  } else if (features.gn_noise_ratio > 0.6 && features.gn_malicious_ratio < 0.1) {
    // Mostly generic scanners, not targeted → keep TI low (no additional bonus)
  }

  return Math.min(Math.max(s, 0), 1);
}

Deno.serve(async (req) => {
  const corsHeaders = buildCorsHeaders(req.headers.get("origin"));

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const userId = getUserIdFromRequest(req);
  if (!userId && !isServiceRoleRequest(req)) {
    return new Response(
      JSON.stringify({ error: "Não autenticado" }),
      { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  try {
    const url = new URL(req.url);
    const asn = url.searchParams.get("asn");
    const startDate = url.searchParams.get("start_date");
    const endDate = url.searchParams.get("end_date");
    const windowMinutes = parseInt(url.searchParams.get("window_minutes") || "30");

    if (!asn || !startDate || !endDate) {
      return new Response(
        JSON.stringify({ error: "Required params: asn, start_date, end_date" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    // Treina com o ground truth Wanguard dos ASNs PRÓPRIOS da K2 (únicos com
    // status real de ataque confirmado) — antes só AS267458; AS266953 (Argo)
    // passou a ter dados reais também depois que generate-dataset passou a
    // cobrir os dois.
    const OWN_ASNS = ["AS267458", "AS266953"];
    console.log(`Fetching training data from ${OWN_ASNS.join(", ")}...`);
    const { data: trainingData, error: trainError } = await supabase
      .from("v_training_dataset")
      .select("is_attack, strong_count, qrator_count, rpki_count, ripestat_count, bgp_count, has_combo_strong, ti_ips_total, ti_abuse_avg_score, ti_abuse_high_ratio, gn_noise_ratio, gn_malicious_ratio, gn_riot_ratio, ti_combined_score")
      .in("asn", OWN_ASNS)
      .limit(5000);

    if (trainError) throw new Error(`Training data error: ${trainError.message}`);
    if (!trainingData || trainingData.length === 0) {
      return new Response(
        JSON.stringify({ error: `No training data available for ${OWN_ASNS.join(", ")}` }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    console.log(`Training on ${trainingData.length} samples...`);
    const weights = trainModel(trainingData);
    console.log("Model weights:", JSON.stringify(weights));

    console.log(`Computing features for ${asn} from ${startDate} to ${endDate}...`);
    const { data: incidents, error: incError } = await supabase
      .from("asn_incidents")
      .select("created_at, signals, status")
      .eq("asn", asn)
      .gte("created_at", startDate)
      .lte("created_at", endDate)
      .order("created_at", { ascending: true });

    if (incError) throw new Error(`Incidents error: ${incError.message}`);

    const { data: tiWindows } = await supabase
      .from("asn_ip_reputation_window")
      .select("window_start, window_end, ips_total, avg_score, high_score_ips, gn_noise_ratio, gn_malicious_ratio, gn_riot_ratio")
      .eq("asn", asn)
      .eq("source", "abuseipdb")
      .gte("window_start", startDate)
      .lte("window_end", endDate);

    const start = new Date(startDate);
    const end = new Date(endDate);
    const windowMs = windowMinutes * 60000;
    const results: any[] = [];

    let cursor = new Date(start.getTime() + windowMs);
    while (cursor <= end) {
      const windowStart = new Date(cursor.getTime() - windowMs);
      const windowEnd = new Date(cursor);

      const inWindow = (incidents || []).filter((inc) => {
        const t = new Date(inc.created_at);
        return t >= windowStart && t <= windowEnd;
      });

      const features = computeWindowFeatures(inWindow);

      const tiMatch = (tiWindows || []).find((ti) => {
        const tiStart = new Date(ti.window_start);
        const tiEnd = new Date(ti.window_end);
        return tiStart <= windowEnd && tiEnd >= windowStart;
      });

      if (tiMatch) {
        const ipsTotal = tiMatch.ips_total ?? 0;
        features.ti_ips_total = ipsTotal;
        features.ti_abuse_avg_score = ipsTotal > 0 ? Number(tiMatch.avg_score ?? 0) / 100 : 0;
        features.ti_abuse_high_ratio = ipsTotal > 0 ? (tiMatch.high_score_ips ?? 0) / ipsTotal : 0;
        features.gn_noise_ratio = Number(tiMatch.gn_noise_ratio ?? 0);
        features.gn_malicious_ratio = Number(tiMatch.gn_malicious_ratio ?? 0);
        features.gn_riot_ratio = Number(tiMatch.gn_riot_ratio ?? 0);
        features.ti_combined_score = Math.max(0, Math.min(1,
          features.ti_abuse_avg_score * 0.5 + features.gn_malicious_ratio * 0.4 - features.gn_riot_ratio * 0.1
        ));
      }

      const model_score = predict(weights, features);
      const heuristic_score = computeHeuristicScore(features);
      const final_score = 0.6 * model_score + 0.4 * heuristic_score;

      results.push({
        timestamp: windowEnd.toISOString(),
        window_start: windowStart.toISOString(),
        window_end: windowEnd.toISOString(),
        features: {
          strong_count: features.strong_count,
          qrator_count: features.qrator_count,
          rpki_count: features.rpki_count,
          ripestat_count: features.ripestat_count,
          bgp_count: features.bgp_count,
          has_combo_strong: features.has_combo_strong,
          ti_ips_total: features.ti_ips_total,
          ti_abuse_avg_score: Math.round(features.ti_abuse_avg_score * 1000) / 1000,
          ti_abuse_high_ratio: Math.round(features.ti_abuse_high_ratio * 1000) / 1000,
          gn_noise_ratio: Math.round(features.gn_noise_ratio * 1000) / 1000,
          gn_malicious_ratio: Math.round(features.gn_malicious_ratio * 1000) / 1000,
          gn_riot_ratio: Math.round(features.gn_riot_ratio * 1000) / 1000,
          ti_combined_score: Math.round(features.ti_combined_score * 1000) / 1000,
          total_incidents_in_window: inWindow.length,
        },
        model_score_raw: Math.round(model_score * 1000) / 1000,
        heuristic_score: Math.round(heuristic_score * 1000) / 1000,
        risk_score: Math.round(final_score * 1000) / 1000,
        risk_label:
          final_score >= 0.80 ? "HIGH" :
          final_score >= 0.60 ? "MEDIUM" :
          final_score >= 0.30 ? "LOW" : "NONE",
      });

      cursor = new Date(cursor.getTime() + windowMs);
    }

    // ── Telegram alerts for HIGH risk ──
    const RISK_THRESHOLD = 0.80;
    const ALERT_COOLDOWN_MS = 60 * 60 * 1000;

    const lastWindow = results[results.length - 1];
    if (lastWindow && lastWindow.risk_score >= RISK_THRESHOLD) {
      const { data: alertState } = await supabase
        .from("asn_alert_state")
        .select("last_alert_at, last_risk_score")
        .eq("asn", asn)
        .single();

      const previousScore = alertState?.last_risk_score ?? 0;
      const lastAlertAt = alertState?.last_alert_at ? new Date(alertState.last_alert_at).getTime() : 0;
      const now = Date.now();
      const crossedThreshold = previousScore < RISK_THRESHOLD;
      const cooldownExpired = (now - lastAlertAt) > ALERT_COOLDOWN_MS;

      if (crossedThreshold || cooldownExpired) {
        console.log(`ALERT: ${asn} crossed risk threshold (${lastWindow.risk_score})`);

        const { data: tiWindow } = await supabase
          .from("asn_ip_reputation_window")
          .select("ips_total, ips_with_score, high_score_ips, avg_score, gn_noise_ratio, gn_malicious_ratio, gn_riot_ratio")
          .eq("asn", asn)
          .eq("source", "abuseipdb")
          .gte("window_start", lastWindow.window_start)
          .lte("window_end", lastWindow.window_end)
          .limit(1)
          .single();

        let topIps: { ip: string; reputation_score: number; reports_count: number }[] = [];
        if (tiWindow && (tiWindow.ips_with_score ?? 0) > 0) {
          const { data: ips } = await supabase
            .from("ip_reputation")
            .select("ip, reputation_score, reports_count")
            .eq("source", "abuseipdb")
            .gt("reputation_score", 0)
            .order("reputation_score", { ascending: false })
            .order("reports_count", { ascending: false })
            .limit(3);
          topIps = ips || [];
        }

        const sources: string[] = [];
        if (lastWindow.features.qrator_count > 0) sources.push("Qrator");
        if (lastWindow.features.rpki_count > 0) sources.push("RPKI");
        if (lastWindow.features.bgp_count > 0) sources.push("BGP");
        if (lastWindow.features.ripestat_count > 0) sources.push("RIPEstat");
        if (lastWindow.features.ti_ips_total > 0) sources.push("AbuseIPDB");
        if (lastWindow.features.gn_malicious_ratio > 0) sources.push("GreyNoise");

        try {
          const fnUrl = `${supabaseUrl}/functions/v1/telegram-notify/risk-alert`;
          await fetch(fnUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Authorization": `Bearer ${supabaseKey}` },
            body: JSON.stringify({
              asn,
              risk_score: lastWindow.risk_score,
              risk_label: lastWindow.risk_label,
              sources,
              window_start: lastWindow.window_start,
              window_end: lastWindow.window_end,
              ti: tiWindow ? {
                ips_total: tiWindow.ips_total ?? 0,
                ips_with_score: tiWindow.ips_with_score ?? 0,
                high_score_ips: tiWindow.high_score_ips ?? 0,
                avg_score: Number(tiWindow.avg_score ?? 0),
                gn_noise_ratio: Number(tiWindow.gn_noise_ratio ?? 0),
                gn_malicious_ratio: Number(tiWindow.gn_malicious_ratio ?? 0),
                gn_riot_ratio: Number(tiWindow.gn_riot_ratio ?? 0),
              } : null,
              top_ips: topIps,
            }),
          });
        } catch (err) { console.error("Failed to send risk alert:", err); }

        await supabase.from("asn_alert_state").upsert({
          asn, last_alert_at: new Date().toISOString(),
          last_risk_score: lastWindow.risk_score, last_risk_label: lastWindow.risk_label,
        }, { onConflict: "asn" });
      }
    } else if (lastWindow) {
      await supabase.from("asn_alert_state").upsert({
        asn, last_risk_score: lastWindow.risk_score, last_risk_label: lastWindow.risk_label,
      }, { onConflict: "asn" });
    }

    const highRiskWindows = results.filter((r) => r.risk_label === "HIGH" || r.risk_label === "MEDIUM").length;

    return new Response(
      JSON.stringify({
        asn,
        period: { start: startDate, end: endDate },
        window_minutes: windowMinutes,
        model: {
          trained_on: OWN_ASNS,
          training_samples: trainingData.length,
          weights,
          features_used: ["strong_count", "qrator_count", "rpki_count", "ripestat_count", "bgp_count", "has_combo_strong", "ti_abuse_avg_score", "ti_abuse_high_ratio", "ti_combined_score"],
          has_hybrid_score: true,
        },
        summary: {
          total_windows: results.length,
          high_risk_windows: highRiskWindows,
          max_score: results.length ? Math.max(...results.map((r) => r.risk_score)) : 0,
        },
        windows: results,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("estimate-attack-risk error:", error);
    return new Response(
      JSON.stringify({ error: String(error) }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
