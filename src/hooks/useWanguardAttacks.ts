import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useWanguardAnomalies, type WanguardEvent } from "@/hooks/useWanguard";

export type PeriodOption = "24h" | "7d" | "30d";

function periodToDates(period: PeriodOption): { start: Date; end: Date } {
  const end = new Date();
  const start = new Date();
  switch (period) {
    case "24h":
      start.setHours(start.getHours() - 24);
      break;
    case "7d":
      start.setDate(start.getDate() - 7);
      break;
    case "30d":
      start.setDate(start.getDate() - 30);
      break;
  }
  return { start, end };
}

const WEEKDAY_NAMES = ["Domingo", "Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado"];

export interface TypeStats {
  type: string;
  count: number;
  totalBps: number;
  avgBps: number;
  peakHour: number;
}

export type PossibleAttackReason = "EXTERNAL" | "INTERNAL" | "BOTH";

export const MY_ASNS = [267458, 266953];

export interface HighVolumeAlert {
  id: string;
  timestamp: Date;
  prefix: string;
  attackType: string;
  sizeBps: number;
  sizeGbps: number;
  possibleAttack: boolean;
  possibleAttackReason: PossibleAttackReason | null;
  asn?: number;
  isThirdParty: boolean;
}

interface AttackSampleWindow {
  timestamp: string;
  wanguard_severity_class: string;
  external_anomalies_count_30m: number;
  external_strong_anomalies_count_30m: number;
  wanguard_max_bps_30m: number | null;
}

export interface WanguardAggregates {
  totalAttacks: number;
  totalBps: number;
  avgBps: number;
  maxBps: number;
  byLevel: Record<string, number>;
  byHour: Record<number, number>;
  byPrefix: { prefix: string; count: number; totalBps: number }[];
  byDayOfWeek: Record<number, number>;
  attacksByHour: { hour: number; count: number }[];
  attacksByWeekday: { weekday: string; count: number }[];
  attacksByTypeAndHour: { type: string; hour: number; count: number }[];
  typeStats: TypeStats[];
  firstHitByPrefix: { prefix: string; firstHitCount: number }[];
  attacksByDay: { date: string; count: number; totalBps: number }[];
  dailyStats: {
    avgDailyCount: number;
    stdDailyCount: number;
    peakDays: { date: string; count: number; totalBps: number }[];
  };
  highVolumeAlerts: HighVolumeAlert[];
}

/** Maps raw Wanguard attackType to a readable label */
const ATTACK_TYPE_LABELS: Record<string, string> = {
  "udp-atk": "UDP Flood",
  "tcp-atk": "TCP Flood",
  "syn-atk": "SYN Flood",
  "icmp-atk": "ICMP Flood",
  "dns-atk": "DNS Amplification",
  "ntp-atk": "NTP Amplification",
  "gre-atk": "GRE Flood",
  "frag-atk": "Fragmentação",
  "chargen-atk": "Chargen",
  "ssdp-atk": "SSDP Reflection",
  "memcached-atk": "Memcached",
  udp_flood: "UDP Flood",
  syn_flood: "SYN Flood",
  tcp_flood: "TCP Flood",
  icmp_flood: "ICMP Flood",
  amplification: "Amplificação",
  dns_amplification: "DNS Amplification",
  ntp_amplification: "NTP Amplification",
  scan: "Scan",
  http_flood: "HTTP Flood",
  slowloris: "Slowloris",
  ack_flood: "ACK Flood",
  rst_flood: "RST Flood",
  mixed: "Misto",
  unclassified: "Sem classificação",
  unknown: "Sem classificação",
  "—": "Sem classificação",
  "": "Sem classificação",
};

export function normalizeAttackType(raw: string | undefined | null): string {
  if (!raw || raw === "—" || raw.trim() === "") return "Sem classificação";
  const key = raw.toLowerCase().trim();
  return ATTACK_TYPE_LABELS[key] || ATTACK_TYPE_LABELS[key.replace(/[\s-]+/g, "_")] || raw;
}

function computeDailyStats(attacksByDay: { date: string; count: number; totalBps: number }[]) {
  if (attacksByDay.length === 0) return { avgDailyCount: 0, stdDailyCount: 0, peakDays: [] };
  const counts = attacksByDay.map((d) => d.count);
  const avg = counts.reduce((s, c) => s + c, 0) / counts.length;
  const variance = counts.reduce((s, c) => s + (c - avg) ** 2, 0) / counts.length;
  const std = Math.sqrt(variance);
  const threshold = avg + 2 * std;
  const peakDays = attacksByDay
    .filter((d) => d.count >= threshold)
    .sort((a, b) => b.count - a.count);
  return { avgDailyCount: avg, stdDailyCount: std, peakDays };
}

export function computeAggregates(events: WanguardEvent[], sampleWindows: AttackSampleWindow[] = []): WanguardAggregates {
  // Build a lookup of sample windows by rounded timestamp (5-min buckets)
  const windowLookup = new Map<number, AttackSampleWindow>();
  for (const w of sampleWindows) {
    const ts = new Date(w.timestamp).getTime();
    // Round to 5-min bucket
    const bucket = Math.floor(ts / 300000) * 300000;
    // Keep the window with most data per bucket
    if (!windowLookup.has(bucket) || (w.external_anomalies_count_30m > 0 || w.wanguard_severity_class !== "NONE")) {
      windowLookup.set(bucket, w);
    }
  }

  function findWindow(eventTs: Date): AttackSampleWindow | undefined {
    const bucket = Math.floor(eventTs.getTime() / 300000) * 300000;
    // Try exact bucket and neighbors (±5 min)
    return windowLookup.get(bucket) || windowLookup.get(bucket - 300000) || windowLookup.get(bucket + 300000);
  }
  const byLevel: Record<string, number> = {};
  const byHour: Record<number, number> = {};
  const byDayOfWeek: Record<number, number> = {};
  const prefixMap: Record<string, { count: number; totalBps: number }> = {};

  // For type+hour cross and type stats
  const typeHourMap: Record<string, Record<number, number>> = {};
  const typeStatsMap: Record<string, { count: number; totalBps: number; hourCounts: Record<number, number> }> = {};

  let totalBps = 0;
  let maxBps = 0;

  for (const e of events) {
    const level = normalizeAttackType(e.attackType);
    byLevel[level] = (byLevel[level] || 0) + 1;

    const hour = e.timestamp.getHours();
    byHour[hour] = (byHour[hour] || 0) + 1;

    const dow = e.timestamp.getDay();
    byDayOfWeek[dow] = (byDayOfWeek[dow] || 0) + 1;

    const pfx = e.prefix || "N/A";
    if (!prefixMap[pfx]) prefixMap[pfx] = { count: 0, totalBps: 0 };
    prefixMap[pfx].count++;
    prefixMap[pfx].totalBps += e.sizeBps;

    // type x hour cross
    if (!typeHourMap[level]) typeHourMap[level] = {};
    typeHourMap[level][hour] = (typeHourMap[level][hour] || 0) + 1;

    // type stats
    if (!typeStatsMap[level]) typeStatsMap[level] = { count: 0, totalBps: 0, hourCounts: {} };
    typeStatsMap[level].count++;
    typeStatsMap[level].totalBps += e.sizeBps;
    typeStatsMap[level].hourCounts[hour] = (typeStatsMap[level].hourCounts[hour] || 0) + 1;

    totalBps += e.sizeBps;
    if (e.sizeBps > maxBps) maxBps = e.sizeBps;
  }

  const byPrefix = Object.entries(prefixMap)
    .map(([prefix, v]) => ({ prefix, ...v }))
    .sort((a, b) => b.count - a.count);

  const attacksByHour = Array.from({ length: 24 }, (_, h) => ({
    hour: h,
    count: byHour[h] || 0,
  }));

  const attacksByWeekday = Array.from({ length: 7 }, (_, d) => ({
    weekday: WEEKDAY_NAMES[d],
    count: byDayOfWeek[d] || 0,
  }));

  // Flatten type x hour cross
  const attacksByTypeAndHour: WanguardAggregates["attacksByTypeAndHour"] = [];
  for (const [type, hours] of Object.entries(typeHourMap)) {
    for (const [h, count] of Object.entries(hours)) {
      attacksByTypeAndHour.push({ type, hour: Number(h), count });
    }
  }

  // Build typeStats sorted by count desc
  const typeStats: TypeStats[] = Object.entries(typeStatsMap)
    .map(([type, s]) => {
      const peakHour = Object.entries(s.hourCounts).sort((a, b) => b[1] - a[1])[0];
      return {
        type,
        count: s.count,
        totalBps: s.totalBps,
        avgBps: s.count > 0 ? s.totalBps / s.count : 0,
        peakHour: peakHour ? Number(peakHour[0]) : 0,
      };
    })
    .sort((a, b) => b.count - a.count);

  // Day buckets (shared for firstHit and attacksByDay)
  const dayBuckets: Record<string, WanguardEvent[]> = {};
  for (const e of events) {
    const dayKey = e.timestamp.toISOString().slice(0, 10);
    if (!dayBuckets[dayKey]) dayBuckets[dayKey] = [];
    dayBuckets[dayKey].push(e);
  }

  // Attacks by day aggregate
  const attacksByDay = Object.entries(dayBuckets)
    .map(([date, dayEvents]) => ({
      date,
      count: dayEvents.length,
      totalBps: dayEvents.reduce((sum, ev) => sum + ev.sizeBps, 0),
    }))
    .sort((a, b) => a.date.localeCompare(b.date));
  const firstHitCounts: Record<string, number> = {};
  for (const dayEvents of Object.values(dayBuckets)) {
    dayEvents.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    const firstPrefix = dayEvents[0]?.prefix;
    if (firstPrefix) {
      firstHitCounts[firstPrefix] = (firstHitCounts[firstPrefix] || 0) + 1;
    }
  }
  const firstHitByPrefix = Object.entries(firstHitCounts)
    .map(([prefix, firstHitCount]) => ({ prefix, firstHitCount }))
    .sort((a, b) => b.firstHitCount - a.firstHitCount);

  const HIGH_VOLUME_THRESHOLD = 10 * 1e9;
  const INTERNAL_BPS_THRESHOLD = 5 * 1e9;
  const highVolumeAlerts: HighVolumeAlert[] = events
    .filter((e) => e.sizeBps >= HIGH_VOLUME_THRESHOLD)
    .map((e) => {
      const window = findWindow(e.timestamp);
      const hasExternalAnomaly = window
        ? window.external_anomalies_count_30m > 0 || window.external_strong_anomalies_count_30m > 0
        : false;
      const possibleAttack = hasExternalAnomaly;
      const possibleAttackReason: PossibleAttackReason | null = hasExternalAnomaly ? "EXTERNAL" : null;

      // Extract ASN number from prefix or event if available
      const eventAsn = (e as any).asn ? Number((e as any).asn) : undefined;
      const isThirdParty = eventAsn ? !MY_ASNS.includes(eventAsn) : true;

      return {
        id: `${e.timestamp.toISOString()}_${e.prefix || "unknown"}`,
        timestamp: e.timestamp,
        prefix: e.prefix || "N/A",
        attackType: normalizeAttackType(e.attackType),
        sizeBps: e.sizeBps,
        sizeGbps: e.sizeBps / 1e9,
        possibleAttack,
        possibleAttackReason,
        asn: eventAsn,
        isThirdParty,
      };
    })
    .sort((a, b) => b.sizeBps - a.sizeBps);

  return {
    totalAttacks: events.length,
    totalBps,
    avgBps: events.length > 0 ? totalBps / events.length : 0,
    maxBps,
    byLevel,
    byHour,
    byPrefix,
    byDayOfWeek,
    attacksByHour,
    attacksByWeekday,
    attacksByTypeAndHour,
    typeStats,
    firstHitByPrefix,
    attacksByDay,
    dailyStats: computeDailyStats(attacksByDay),
    highVolumeAlerts,
  };
}

export function useWanguardAttacks(period: PeriodOption, refreshKey = 0) {
  const { start, end } = useMemo(() => periodToDates(period), [period]);

  const { data: events, isLoading, error, source, apiError, refetch } = useWanguardAnomalies(start, end, refreshKey);

  // Fetch as_attack_samples windows for possibleAttack correlation
  const { data: sampleWindows = [] } = useQuery({
    queryKey: ["attack-sample-windows", start.toISOString(), end.toISOString()],
    queryFn: async () => {
      const { data } = await supabase
        .from("as_attack_samples")
        .select("timestamp, wanguard_severity_class, external_anomalies_count_30m, external_strong_anomalies_count_30m, wanguard_max_bps_30m")
        .gte("timestamp", start.toISOString())
        .lte("timestamp", end.toISOString())
        .order("timestamp", { ascending: true })
        .limit(1000);
      return (data ?? []) as AttackSampleWindow[];
    },
  });

  const aggregates = useMemo(() => computeAggregates(events, sampleWindows), [events, sampleWindows]);

  return {
    events,
    aggregates,
    isLoading,
    error,
    source,
    apiError,
    refetch,
  };
}
