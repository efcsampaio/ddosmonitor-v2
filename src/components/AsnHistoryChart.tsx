import { useState, useEffect, useMemo, useRef } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Loader2, Activity, ShieldAlert } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { motion, useInView } from "motion/react";
import {
  CHART_TOOLTIP_STYLE,
  CHART_TOOLTIP_LABEL_STYLE,
  CHART_TOOLTIP_ITEM_STYLE,
  CHART_CURSOR,
  CHART_AXIS_TICK,
  CHART_GRID,
  CHART_LEGEND_STYLE,
  CHART_ANIM,
} from "@/lib/chartConfig";
import {
  ComposedChart,
  Line,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
  CartesianGrid,
} from "recharts";

interface SampleRow {
  timestamp: string;
  asn: string;
  wanguard_attack_count_30m: number;
  wanguard_severity_class: string;
  external_anomalies_count_30m: number;
  external_strong_anomalies_count_30m: number;
  qrator_events_count_30m: number;
  rpki_events_count_30m: number;
  ripestat_events_count_30m: number;
  bgp_events_count_30m: number;
  ti_ips_total: number;
  ti_abuse_avg_score: number;
  ti_abuse_high_ratio: number;
  gn_noise_ratio: number;
  gn_malicious_ratio: number;
  gn_riot_ratio: number;
  ti_combined_score: number;
}

interface ChartPoint {
  time: string;
  timestamp: string;
  qrator: number;
  rpki: number;
  ripestat: number;
  bgp: number;
  external: number;
  strong: number;
  wanguard: number;
  ti_score: number;
  ti_ips: number;
  ti_ratio: number;
  ti_marker: number | null;
  severity: string;
  gn_noise_ratio: number;
  gn_malicious_ratio: number;
  gn_riot_ratio: number;
  ti_combined_score: number;
}

function formatTime(iso: string) {
  const d = new Date(iso);
  return d.toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit" }) +
    " " +
    d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
}

function tiMarkerColor(score: number): string {
  if (score >= 50) return "hsl(0, 84%, 60%)";
  if (score > 0) return "hsl(30, 90%, 50%)";
  return "transparent";
}

interface Props {
  asns: string[];
}

const HOURS_OPTIONS = [
  { value: "6", label: "Últimas 6h" },
  { value: "12", label: "Últimas 12h" },
  { value: "24", label: "Últimas 24h" },
  { value: "72", label: "Últimos 3 dias" },
  { value: "168", label: "Últimos 7 dias" },
];

export function AsnHistoryChart({ asns }: Props) {
  const [hours, setHours] = useState("24");
  const [selectedAsn, setSelectedAsn] = useState<string>("all");
  const [data, setData] = useState<SampleRow[]>([]);
  const [loading, setLoading] = useState(true);
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: true, margin: "-100px" });

  useEffect(() => {
    if (asns.length === 0) return;
    let cancelled = false;

    async function load() {
      setLoading(true);
      const since = new Date(Date.now() - parseInt(hours) * 60 * 60 * 1000).toISOString();

      const { data: rows } = await supabase
        .from("as_attack_samples")
        .select(
          "timestamp, asn, wanguard_attack_count_30m, wanguard_severity_class, " +
          "external_anomalies_count_30m, external_strong_anomalies_count_30m, " +
          "qrator_events_count_30m, rpki_events_count_30m, ripestat_events_count_30m, " +
          "bgp_events_count_30m, ti_ips_total, ti_abuse_avg_score, ti_abuse_high_ratio, " +
          "gn_noise_ratio, gn_malicious_ratio, gn_riot_ratio, ti_combined_score"
        )
        .gte("timestamp", since)
        .in("asn", asns)
        .order("timestamp", { ascending: true })
        .limit(500);

      if (!cancelled) {
        setData((rows as unknown as SampleRow[]) ?? []);
        setLoading(false);
      }
    }

    load();
    return () => { cancelled = true; };
  }, [asns, hours]);

  const filtered = useMemo(() => {
    if (selectedAsn === "all") return data;
    return data.filter((r) => r.asn === selectedAsn);
  }, [data, selectedAsn]);

  const chartData: ChartPoint[] = useMemo(() => {
    return filtered.map((r) => ({
      time: formatTime(r.timestamp),
      timestamp: r.timestamp,
      qrator: r.qrator_events_count_30m,
      rpki: r.rpki_events_count_30m,
      ripestat: r.ripestat_events_count_30m,
      bgp: r.bgp_events_count_30m,
      external: r.external_anomalies_count_30m,
      strong: r.external_strong_anomalies_count_30m,
      wanguard: r.wanguard_attack_count_30m,
      ti_score: Number(r.ti_abuse_avg_score) || 0,
      ti_ips: r.ti_ips_total,
      ti_ratio: Number(r.ti_abuse_high_ratio) || 0,
      ti_marker: (Number(r.ti_abuse_avg_score) || 0) > 0 ? (Number(r.ti_abuse_avg_score) || 0) : null,
      severity: r.wanguard_severity_class,
      gn_noise_ratio: Number(r.gn_noise_ratio) || 0,
      gn_malicious_ratio: Number(r.gn_malicious_ratio) || 0,
      gn_riot_ratio: Number(r.gn_riot_ratio) || 0,
      ti_combined_score: Number(r.ti_combined_score) || 0,
    }));
  }, [filtered]);

  const uniqueAsns = useMemo(() => {
    const set = new Set(data.map((r) => r.asn));
    return Array.from(set).sort();
  }, [data]);

  if (asns.length === 0) return null;

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 30 }}
      animate={isInView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.5, ease: "easeOut" }}
    >
      <Card className="bg-card border-border p-3 md:p-5">
        <div className="flex flex-col sm:flex-row sm:items-center gap-2 mb-4">
          <motion.div
            initial={{ x: -20, opacity: 0 }}
            animate={isInView ? { x: 0, opacity: 1 } : {}}
            transition={{ duration: 0.4, delay: 0.1 }}
            className="flex items-center gap-2"
          >
            <Activity className="h-5 w-5 text-muted-foreground shrink-0" />
            <h3 className="text-base md:text-lg font-semibold text-foreground">
              Histórico de Amostras
            </h3>
          </motion.div>
          <div className="flex items-center gap-2 sm:ml-auto">
            <Select value={selectedAsn} onValueChange={setSelectedAsn}>
              <SelectTrigger className="w-[180px] h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Todos os ASNs</SelectItem>
                {uniqueAsns.map((a) => (
                  <SelectItem key={a} value={a}>{a}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={hours} onValueChange={setHours}>
              <SelectTrigger className="w-[140px] h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {HOURS_OPTIONS.map((o) => (
                  <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            <span className="ml-2 text-muted-foreground text-sm">Carregando histórico...</span>
          </div>
        ) : chartData.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">
            Nenhuma amostra encontrada no período selecionado.
          </p>
        ) : (
          <>
            <motion.div
              initial={{ scaleY: 0 }}
              animate={{ scaleY: 1 }}
              transition={{ duration: 0.5, delay: 0.2, ease: "easeOut" }}
              style={{ transformOrigin: "bottom" }}
              className="h-[280px] sm:h-[340px] mb-4"
            >
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={chartData} margin={{ left: 0, right: 10, top: 5, bottom: 5 }}>
                  <XAxis
                    dataKey="time"
                    tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                    interval="preserveStartEnd"
                  />
                  <YAxis
                    yAxisId="left"
                    tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                    label={{ value: "Eventos", angle: -90, position: "insideLeft", style: { fill: "hsl(var(--muted-foreground))", fontSize: 10 } }}
                  />
                  <YAxis
                    yAxisId="right"
                    orientation="right"
                    domain={[0, 100]}
                    tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                    label={{ value: "TI Score", angle: 90, position: "insideRight", style: { fill: "hsl(var(--muted-foreground))", fontSize: 10 } }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: 8,
                      fontSize: 11,
                      color: "hsl(var(--foreground))",
                    }}
                    content={({ active, payload, label }) => {
                      if (!active || !payload || payload.length === 0) return null;
                      const d = payload[0]?.payload as ChartPoint;
                      return (
                        <div className="bg-card border border-border rounded-lg p-3 text-xs space-y-1 shadow-lg">
                          <p className="font-semibold text-foreground">{label}</p>
                          <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
                            <span className="text-muted-foreground">Qrator:</span><span>{d.qrator}</span>
                            <span className="text-muted-foreground">RPKI:</span><span>{d.rpki}</span>
                            <span className="text-muted-foreground">RIPEstat:</span><span>{d.ripestat}</span>
                            <span className="text-muted-foreground">BGP:</span><span>{d.bgp}</span>
                            <span className="text-muted-foreground">Wanguard:</span><span>{d.wanguard}</span>
                            <span className="text-muted-foreground">Anomalias ext.:</span><span>{d.external}</span>
                          </div>
                          {d.ti_ips > 0 && (
                            <div className="border-t border-border pt-1 mt-1 space-y-0.5">
                              <p className="font-semibold text-orange-400 flex items-center gap-1">
                                <ShieldAlert className="h-3 w-3" /> AbuseIPDB
                              </p>
                              <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
                                <span className="text-muted-foreground">IPs amostrados:</span>
                                <span>{d.ti_ips}</span>
                                <span className="text-muted-foreground">Score médio:</span>
                                <span className={d.ti_score >= 50 ? "text-destructive font-semibold" : d.ti_score > 0 ? "text-orange-400" : ""}>
                                  {d.ti_score}/100
                                </span>
                                <span className="text-muted-foreground">Ratio maliciosos:</span>
                                <span>{(d.ti_ratio * 100).toFixed(1)}%</span>
                              </div>
                            </div>
                          )}
                          {(d.gn_malicious_ratio > 0 || d.gn_noise_ratio > 0 || d.gn_riot_ratio > 0) && (
                            <div className="border-t border-border pt-1 mt-1 space-y-0.5">
                              <p className="font-semibold text-purple-400 flex items-center gap-1">
                                <ShieldAlert className="h-3 w-3" /> GreyNoise
                              </p>
                              <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
                                <span className="text-muted-foreground">Scanners genéricos:</span>
                                <span>{(d.gn_noise_ratio * 100).toFixed(1)}%</span>
                                <span className="text-muted-foreground">Maliciosos confirmados:</span>
                                <span className={d.gn_malicious_ratio >= 0.3 ? "text-destructive font-semibold" : ""}>
                                  {(d.gn_malicious_ratio * 100).toFixed(1)}%
                                </span>
                                <span className="text-muted-foreground">IPs legítimos (riot):</span>
                                <span className={d.gn_riot_ratio >= 0.5 ? "text-emerald-400" : ""}>
                                  {(d.gn_riot_ratio * 100).toFixed(1)}%
                                </span>
                              </div>
                            </div>
                          )}
                          {d.ti_combined_score > 0 && (
                            <div className="border-t border-border pt-1 mt-1">
                              <div className="grid grid-cols-2 gap-x-4">
                                <span className="text-muted-foreground font-semibold">Score TI combinado:</span>
                                <span className={d.ti_combined_score >= 0.5 ? "text-destructive font-bold" : "text-orange-400 font-semibold"}>
                                  {(d.ti_combined_score * 100).toFixed(0)}/100
                                </span>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: 10 }} iconSize={10} />
                  <Bar yAxisId="left" dataKey="qrator" name="Qrator" fill="hsl(270, 70%, 60%)" barSize={6} stackId="events" opacity={0.7} animationDuration={600} animationBegin={0} />
                  <Bar yAxisId="left" dataKey="rpki" name="RPKI" fill="hsl(190, 90%, 50%)" barSize={6} stackId="events" opacity={0.7} animationDuration={600} animationBegin={0} />
                  <Bar yAxisId="left" dataKey="ripestat" name="RIPEstat" fill="hsl(210, 70%, 55%)" barSize={6} stackId="events" opacity={0.7} animationDuration={600} animationBegin={0} />
                  <Bar yAxisId="left" dataKey="bgp" name="BGP" fill="hsl(150, 60%, 45%)" barSize={6} stackId="events" opacity={0.7} animationDuration={600} animationBegin={0} />
                  <Line
                    yAxisId="right"
                    dataKey="ti_marker"
                    name="TI Score"
                    stroke="hsl(30, 90%, 50%)"
                    strokeWidth={0}
                    animationDuration={800}
                    animationBegin={200}
                    dot={(props: any) => {
                      const { cx, cy, payload } = props;
                      if (!payload.ti_marker) return <circle key={`empty-${cx}`} r={0} />;
                      const color = tiMarkerColor(payload.ti_score);
                      const size = payload.ti_score >= 50 ? 6 : 4;
                      return (
                        <g key={`ti-${cx}-${cy}`}>
                          {payload.ti_score >= 50 && (
                            <circle cx={cx} cy={cy} r={10} fill={color} opacity={0.15}>
                              <animate attributeName="r" values="6;12;6" dur="2s" repeatCount="indefinite" />
                              <animate attributeName="opacity" values="0.2;0.05;0.2" dur="2s" repeatCount="indefinite" />
                            </circle>
                          )}
                          <circle
                            cx={cx}
                            cy={cy}
                            r={size}
                            fill={color}
                            stroke="hsl(var(--background))"
                            strokeWidth={1.5}
                            opacity={0.9}
                          />
                        </g>
                      );
                    }}
                    connectNulls={false}
                  />
                </ComposedChart>
              </ResponsiveContainer>
            </motion.div>

            <div className="flex items-center gap-4 mb-4 text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1">
                <span className="inline-block w-3 h-3 rounded-full" style={{ background: "hsl(0, 84%, 60%)" }} />
                TI Score ≥ 50 (alto)
              </span>
              <span className="flex items-center gap-1">
                <span className="inline-block w-3 h-3 rounded-full" style={{ background: "hsl(30, 90%, 50%)" }} />
                TI Score 1–49 (moderado)
              </span>
            </div>

            <div className="overflow-x-auto -mx-3 md:mx-0">
              <table className="w-full text-[10px] sm:text-xs min-w-[850px]">
                <thead>
                  <tr className="border-b border-border text-muted-foreground">
                    <th className="text-left py-2 px-2">Janela</th>
                    <th className="text-center py-2 px-1">Qrator</th>
                    <th className="text-center py-2 px-1">RPKI</th>
                    <th className="text-center py-2 px-1">BGP</th>
                    <th className="text-center py-2 px-1">RIPEstat</th>
                    <th className="text-center py-2 px-1">Wanguard</th>
                    <th className="text-center py-2 px-1">IPs TI</th>
                    <th className="text-center py-2 px-1">Score TI</th>
                    <th className="text-center py-2 px-1">Score Combinado</th>
                  </tr>
                </thead>
                <tbody>
                  {chartData.slice(0, 50).map((d, i) => (
                    <motion.tr
                      key={i}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.25, delay: i * 0.02 }}
                      className="border-b border-border/50 hover:bg-secondary/30 transition-colors duration-200"
                    >
                      <td className="py-1.5 px-2 text-foreground whitespace-nowrap">{d.time}</td>
                      <td className="text-center py-1.5 px-1">{d.qrator || "—"}</td>
                      <td className="text-center py-1.5 px-1">{d.rpki || "—"}</td>
                      <td className="text-center py-1.5 px-1">{d.bgp || "—"}</td>
                      <td className="text-center py-1.5 px-1">{d.ripestat || "—"}</td>
                      <td className="text-center py-1.5 px-1">
                        {d.wanguard > 0 ? (
                          <Badge variant="destructive" className="text-[9px] px-1.5">{d.wanguard}</Badge>
                        ) : "—"}
                      </td>
                      <td className="text-center py-1.5 px-1">
                        {d.ti_ips > 0 ? d.ti_ips : "—"}
                      </td>
                      <td className="text-center py-1.5 px-1">
                        {d.ti_score > 0 ? (
                          <span className={d.ti_score >= 50 ? "text-destructive font-semibold" : "text-orange-400"}>
                            {d.ti_score}
                          </span>
                        ) : "—"}
                      </td>
                      <td className="text-center py-1.5 px-1">
                        {d.ti_combined_score > 0 ? (
                          <span className={d.ti_combined_score >= 0.5 ? "text-destructive font-semibold" : "text-orange-400"}>
                            {(d.ti_combined_score * 100).toFixed(0)}
                          </span>
                        ) : "—"}
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Card>
    </motion.div>
  );
}
