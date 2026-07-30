import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeadersStatic = {
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
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

// Essa function chama APIs pagas/rate-limited (AbuseIPDB, GreyNoise) e itera
// todos os ASNs monitorados quando chamada sem `asn` no body — deveria só
// ser disparada pelo pipeline interno (cron / estimate-attack-risk), nunca
// por qualquer request externo com a anon key. Antes não havia checagem
// nenhuma na rota.
function isServiceRoleRequest(req: Request): boolean {
  const authHeader = req.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) return false;
  return authHeader.slice("Bearer ".length) === supabaseServiceKeyEnv;
}

const ABUSEIPDB_BASE_URL =
  Deno.env.get("ABUSEIPDB_BASE_URL") || "https://api.abuseipdb.com/api/v2";
const ABUSEIPDB_API_KEY = Deno.env.get("ABUSEIPDB_API_KEY") || "";
const GREYNOISE_API_KEY = Deno.env.get("GREYNOISE_API_KEY") || "";
const GREYNOISE_BASE_URL = "https://api.greynoise.io/v3/community";
const CACHE_TTL_HOURS = 24;
const GN_CACHE_TTL_HOURS = 7 * 24; // 7 days
const RIPESTAT_BASE = "https://stat.ripe.net";
const MAX_IPS_PER_ASN = 20;
const MAX_IPS_PRIORITY_ASN = 30;
const ABUSEIPDB_DELAY_MS = 200;
const GREYNOISE_DELAY_MS = 1500;
const MAX_GN_PER_ASN = 5;
const MAX_GN_PRIORITY_ASN = 10;

// ASNs concorrentes estratégicos — prioridade GreyNoise
const PRIORITY_ASNS = new Set(["AS268538", "AS267530", "AS268726", "268538", "267530", "268726"]);

/** Parse CIDR like "192.168.1.0/24" → { networkInt, prefixLen } */
function parseCidr(cidr: string): { networkInt: number; prefixLen: number } | null {
  const m = cidr.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (!m) return null;
  const prefixLen = parseInt(m[2], 10);
  if (prefixLen < 24 || prefixLen > 32) return null;
  const parts = m[1].split(".").map(Number);
  const networkInt = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  return { networkInt, prefixLen };
}

function intToIp(n: number): string {
  return `${(n >>> 24) & 0xff}.${(n >>> 16) & 0xff}.${(n >>> 8) & 0xff}.${n & 0xff}`;
}

/** Sample IPs from a /24–/32 prefix. For priority ASNs, sample more densely. */
function sampleIpsFromPrefix(cidr: string, dense = false): string[] {
  const parsed = parseCidr(cidr);
  if (!parsed) return [];
  const { networkInt, prefixLen } = parsed;
  const hostBits = 32 - prefixLen;
  const blockSize = 1 << hostBits;
  if (blockSize <= 2) return [intToIp(networkInt)];
  const first = networkInt + 1;
  const last = networkInt + blockSize - 2;
  const mid = networkInt + Math.floor(blockSize / 2);

  if (!dense) {
    const ips = [intToIp(first)];
    if (mid !== first && mid !== last) ips.push(intToIp(mid));
    ips.push(intToIp(last));
    return ips;
  }

  // Dense sampling: first, 1/4, 1/2, 3/4, last + common service IPs (.1, .2, .10, .100, .200, .253, .254)
  const targets = new Set<number>();
  targets.add(first);
  targets.add(last);
  targets.add(mid);
  targets.add(networkInt + Math.floor(blockSize / 4));
  targets.add(networkInt + Math.floor(3 * blockSize / 4));
  // Common service offsets
  for (const offset of [1, 2, 10, 100, 200, 253, 254]) {
    const ip = networkInt + offset;
    if (ip > networkInt && ip < networkInt + blockSize - 1) targets.add(ip);
  }
  return [...targets].sort((a, b) => a - b).map(intToIp);
}

async function fetchPrefixesForAsn(asn: string): Promise<string[]> {
  const resource = asn.startsWith("AS") ? asn : `AS${asn}`;
  const url = `${RIPESTAT_BASE}/data/announced-prefixes/data.json?resource=${resource}`;
  try {
    const resp = await fetch(url);
    if (!resp.ok) { console.warn(`RIPEstat error for ${resource}:`, resp.status); return []; }
    const json = await resp.json();
    const prefixes: { prefix: string }[] = json?.data?.prefixes ?? [];
    return prefixes.map((p) => p.prefix).filter((p) => !p.includes(":") && parseCidr(p) !== null);
  } catch (err) { console.error(`Failed to fetch prefixes for ${resource}:`, err); return []; }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function isCacheValid(checkedAt: string | null, now: Date): boolean {
  if (!checkedAt) return false;
  return now.getTime() - new Date(checkedAt).getTime() < CACHE_TTL_HOURS * 3600 * 1000;
}

// ── GreyNoise lookup ──
async function lookupGreyNoise(ip: string): Promise<{ noise: boolean; riot: boolean; classification: string } | null> {
  if (!GREYNOISE_API_KEY) { console.warn("GREYNOISE_API_KEY not set, skipping", ip); return null; }
  try {
    await sleep(GREYNOISE_DELAY_MS);
    const resp = await fetch(`${GREYNOISE_BASE_URL}/${encodeURIComponent(ip)}`, {
      headers: { key: GREYNOISE_API_KEY, Accept: "application/json" },
    });
    if (resp.status === 404) {
      await resp.text();
      return { noise: false, riot: false, classification: "unknown" };
    }
    if (resp.status === 429) {
      console.warn(`GreyNoise rate-limited for ${ip}, skipping remaining`);
      await resp.text();
      return { noise: false, riot: false, classification: "rate_limited" };
    }
    if (!resp.ok) { console.error(`GreyNoise error for ${ip}:`, resp.status, await resp.text()); return null; }
    const data = await resp.json();
    return {
      noise: data.noise ?? false,
      riot: data.riot ?? false,
      classification: data.classification ?? "unknown",
    };
  } catch (err) { console.error(`GreyNoise lookup failed for ${ip}:`, err); return null; }
}

// ── AbuseIPDB lookup ──
async function lookupAbuseIPDB(ip: string): Promise<{ score: number; reports: number; lastSeen: string | null } | null> {
  if (!ABUSEIPDB_API_KEY) { console.warn("ABUSEIPDB_API_KEY not set, skipping", ip); return null; }
  try {
    await sleep(ABUSEIPDB_DELAY_MS);
    const resp = await fetch(
      `${ABUSEIPDB_BASE_URL}/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=30`,
      { headers: { Key: ABUSEIPDB_API_KEY, Accept: "application/json" } }
    );
    if (!resp.ok) { console.error(`AbuseIPDB error for ${ip}:`, resp.status, await resp.text()); return null; }
    const json = await resp.json();
    const d = json.data;
    return { score: d.abuseConfidenceScore ?? 0, reports: d.totalReports ?? 0, lastSeen: d.lastReportedAt || null };
  } catch (err) { console.error(`AbuseIPDB lookup failed for ${ip}:`, err); return null; }
}

Deno.serve(async (req) => {
  const corsHeaders = buildCorsHeaders(req.headers.get("origin"));

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (!isServiceRoleRequest(req)) {
    return new Response(JSON.stringify({ error: "Não autorizado" }), {
      status: 401,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const supabaseUrl = supabaseUrlEnv;
    const serviceRoleKey = supabaseServiceKeyEnv;
    const supabase = createClient(supabaseUrl, serviceRoleKey);

    const body = await req.json().catch(() => ({}));
    const now = new Date();
    const windowEnd = body.window_end || now.toISOString();
    const windowStart = body.window_start || new Date(now.getTime() - 30 * 60 * 1000).toISOString();
    const asn = body.asn;

    // ── Build IP list per ASN ──
    const ipsByAsn: Record<string, string[]> = {};

    if (asn) {
      const isPriority = PRIORITY_ASNS.has(asn);
      const maxIps = isPriority ? MAX_IPS_PRIORITY_ASN : MAX_IPS_PER_ASN;
      const prefixes = await fetchPrefixesForAsn(asn);
      if (prefixes.length > 0) {
        const allIps: string[] = [];
        for (const prefix of prefixes) {
          allIps.push(...sampleIpsFromPrefix(prefix, isPriority));
          if (allIps.length >= maxIps) break;
        }
        ipsByAsn[asn] = [...new Set(allIps)].slice(0, maxIps);
      }
    } else {
      const { data: monitored } = await supabase.from("monitored_asns").select("asn");
      for (const { asn: currentAsn } of (monitored ?? [])) {
        const isPriority = PRIORITY_ASNS.has(currentAsn);
        const maxIps = isPriority ? MAX_IPS_PRIORITY_ASN : MAX_IPS_PER_ASN;
        const prefixes = await fetchPrefixesForAsn(currentAsn);
        if (prefixes.length === 0) continue;
        const allIps: string[] = [];
        for (const prefix of prefixes) {
          allIps.push(...sampleIpsFromPrefix(prefix, isPriority));
          if (allIps.length >= maxIps) break;
        }
        ipsByAsn[currentAsn] = [...new Set(allIps)].slice(0, maxIps);
        if (isPriority) console.log(`Priority ASN ${currentAsn}: sampled ${ipsByAsn[currentAsn].length} IPs (dense)`);
      }
    }

    console.log("enrich-ip-reputation: starting", {
      windowStart, windowEnd, asn: asn || "all", asnCount: Object.keys(ipsByAsn).length,
    });

    const results: Record<string, any> = {};

    for (const [currentAsn, ips] of Object.entries(ipsByAsn)) {
      const isPriority = PRIORITY_ASNS.has(currentAsn);
      const gnMaxCalls = isPriority ? MAX_GN_PRIORITY_ASN : MAX_GN_PER_ASN;
      const reputations: any[] = [];
      let gnCallsThisAsn = 0;
      let gnRateLimited = false;

      for (const ip of ips) {
        const { data: cached } = await supabase.from("ip_reputation").select("*").eq("ip", ip).maybeSingle();
        const now = new Date();

        // ── AbuseIPDB (cache independente via last_checked_at) ──
        const abuseCacheValid = isCacheValid(cached?.last_checked_at, now);
        let abuseScore = cached?.reputation_score ?? 0;
        let abuseReports = cached?.reports_count ?? 0;
        let abuseLastSeen = cached?.last_seen_at ?? null;

        if (!abuseCacheValid) {
          const abuseResult = await lookupAbuseIPDB(ip);
          if (abuseResult) {
            abuseScore = abuseResult.score;
            abuseReports = abuseResult.reports;
            abuseLastSeen = abuseResult.lastSeen;
          }
        }

        // ── GreyNoise (cache independente via gn_last_checked) ──
        const gnCacheValid = cached?.gn_last_checked ? now.getTime() - new Date(cached.gn_last_checked).getTime() < GN_CACHE_TTL_HOURS * 3600 * 1000 : false;
        let gnNoise = cached?.gn_noise ?? null;
        let gnRiot = cached?.gn_riot ?? null;
        let gnClassification = cached?.gn_classification ?? null;

        if (!gnCacheValid && !gnRateLimited && gnCallsThisAsn < gnMaxCalls) {
          const gnResult = await lookupGreyNoise(ip);
          if (gnResult) {
            gnNoise = gnResult.noise;
            gnRiot = gnResult.riot;
            gnClassification = gnResult.classification;
            if (gnResult.classification === "rate_limited") {
              gnRateLimited = true;
            } else {
              gnCallsThisAsn++;
            }
          }
        }

        // ── Upsert ip_reputation ──
        const record = {
          ip,
          source: "abuseipdb",
          reputation_score: abuseScore,
          reports_count: abuseReports,
          last_seen_at: abuseLastSeen,
          last_checked_at: abuseCacheValid ? cached!.last_checked_at : now.toISOString(),
          gn_noise: gnNoise,
          gn_riot: gnRiot,
          gn_classification: gnClassification,
          gn_last_checked: gnCacheValid ? cached!.gn_last_checked : now.toISOString(),
        };

        await supabase.from("ip_reputation").upsert(record, { onConflict: "ip" });
        reputations.push(record);
      }

      // ── Aggregate per ASN + window ──
      const ipsWithScore = reputations.filter((r) => r.reputation_score > 0);
      const highScoreIps = reputations.filter((r) => r.reputation_score >= 80);
      const avgScore = ipsWithScore.length > 0
        ? ipsWithScore.reduce((s, r) => s + r.reputation_score, 0) / ipsWithScore.length
        : null;

      const total = reputations.length || 1;
      const gnNoiseCount = reputations.filter((r) => r.gn_noise === true).length;
      const gnMaliciousCount = reputations.filter((r) => r.gn_classification === "malicious").length;
      const gnRiotCount = reputations.filter((r) => r.gn_riot === true).length;

      const windowRecord = {
        asn: currentAsn,
        window_start: windowStart,
        window_end: windowEnd,
        source: "abuseipdb",
        ips_total: ips.length,
        ips_with_score: ipsWithScore.length,
        high_score_ips: highScoreIps.length,
        avg_score: avgScore,
        gn_noise_ratio: Math.round((gnNoiseCount / total) * 1000) / 1000,
        gn_malicious_ratio: Math.round((gnMaliciousCount / total) * 1000) / 1000,
        gn_riot_ratio: Math.round((gnRiotCount / total) * 1000) / 1000,
      };

      await supabase.from("asn_ip_reputation_window").upsert(windowRecord, {
        onConflict: "asn,window_start,window_end,source",
      });

      results[currentAsn] = {
        ips_total: ips.length,
        ips_with_score: ipsWithScore.length,
        high_score_ips: highScoreIps.length,
        avg_score: avgScore,
        gn_noise_ratio: windowRecord.gn_noise_ratio,
        gn_malicious_ratio: windowRecord.gn_malicious_ratio,
        gn_riot_ratio: windowRecord.gn_riot_ratio,
      };
    }

    return new Response(
      JSON.stringify({ ok: true, window: { start: windowStart, end: windowEnd }, results }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (err) {
    console.error("enrich-ip-reputation error:", err);
    return new Response(
      JSON.stringify({ error: String(err) }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
