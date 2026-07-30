import { useState, useMemo, useRef } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from "recharts";
import { TrendingDown, ShieldAlert, AlertTriangle, Clock } from "lucide-react";
import { fetchIncidentRanking, type IncidentRanking } from "@/services/asnApi";
import type { ASNDataLocal } from "@/hooks/useNetworkMonitor";
import { motion, useInView } from "motion/react";
import { useEffect } from "react";
import {
  CHART_TOOLTIP_STYLE,
  CHART_TOOLTIP_LABEL_STYLE,
  CHART_TOOLTIP_ITEM_STYLE,
  CHART_CURSOR,
  CHART_AXIS_TICK,
  CHART_GRID,
  CHART_ANIM,
} from "@/lib/chartConfig";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

function getBarColor(score: number): string {
  if (score >= 30) return "hsl(0, 84%, 60%)";
  if (score >= 10) return "hsl(45, 93%, 58%)";
  return "hsl(142, 71%, 45%)";
}

function shortenName(name: string, maxLen = 20): string {
  if (!name || name.length <= maxLen) return name || "—";
  return name.slice(0, maxLen - 1) + "…";
}

interface Props {
  dados: ASNDataLocal[];
}

export function InstabilityRanking({ dados }: Props) {
  const [ranking, setRanking] = useState<IncidentRanking[]>([]);
  const [hours, setHours] = useState("24");
  const [loading, setLoading] = useState(true);
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: true, margin: "-100px" });

  const userAsns = useMemo(() => new Set(dados.map(d => d.metrics.asn)), [dados]);

  useEffect(() => {
    let cancelled = false;
    let first = true;
    async function load() {
      if (first) { setLoading(true); first = false; }
      try {
        const data = await fetchIncidentRanking(parseInt(hours));
        if (!cancelled) setRanking(data);
      } catch (err) {
        console.error("Erro ao buscar ranking:", err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    const interval = setInterval(load, 30000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [hours]);

  const filteredRanking = useMemo(() =>
    ranking.filter(r => userAsns.has(r.asn)),
  [ranking, userAsns]);

  const sortedRanking = useMemo(() =>
    [...filteredRanking].sort((a, b) => b.score - a.score),
  [filteredRanking]);

  const chartData = useMemo(() =>
    sortedRanking.map(r => ({
      ...r,
      shortName: shortenName(r.name),
    })),
  [sortedRanking]);

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
            <TrendingDown className="h-5 w-5 text-muted-foreground shrink-0" />
            <h3 className="text-base md:text-lg font-semibold text-foreground">Ranking de Instabilidade</h3>
          </motion.div>
          <span className="text-xs text-muted-foreground hidden md:inline">Baseado no histórico de incidentes</span>
          <div className="sm:ml-auto">
            <motion.div whileHover={{ scale: 1.05 }} transition={{ type: "spring", stiffness: 400, damping: 25 }}>
              <Select value={hours} onValueChange={setHours}>
                <SelectTrigger className="w-[160px] h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">Última 1 hora</SelectItem>
                  <SelectItem value="3">Últimas 3 horas</SelectItem>
                  <SelectItem value="6">Últimas 6 horas</SelectItem>
                  <SelectItem value="12">Últimas 12 horas</SelectItem>
                  <SelectItem value="24">Últimas 24 horas</SelectItem>
                  <SelectItem value="168">Últimos 7 dias</SelectItem>
                  <SelectItem value="720">Últimos 30 dias</SelectItem>
                  <SelectItem value="2160">Últimos 90 dias</SelectItem>
                </SelectContent>
              </Select>
            </motion.div>
          </div>
        </div>

        {loading && sortedRanking.length === 0 ? (
          <div className="py-8 space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-6 rounded bg-muted animate-pulse" style={{ width: `${80 - i * 15}%` }} />
            ))}
          </div>
        ) : sortedRanking.length === 0 ? (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-center py-8">
            <motion.div animate={{ scale: [1, 1.1, 1] }} transition={{ duration: 2, repeat: Infinity }}>
              <TrendingDown className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
            </motion.div>
            <p className="text-sm text-muted-foreground">
              Nenhum incidente registrado no período selecionado.
            </p>
          </motion.div>
        ) : (
          <>
            <div className="h-[200px] sm:h-[280px] mb-4">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} layout="vertical" margin={{ left: 5, right: 20, top: 5, bottom: 5 }}>
                  <CartesianGrid {...CHART_GRID} horizontal={false} />
                  <XAxis
                    type="number"
                    domain={[0, "auto"]}
                    tick={CHART_AXIS_TICK}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    type="category"
                    dataKey="shortName"
                    width={100}
                    tick={{ fill: "hsl(var(--foreground))", fontSize: 10 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={CHART_TOOLTIP_STYLE}
                    labelStyle={CHART_TOOLTIP_LABEL_STYLE}
                    itemStyle={CHART_TOOLTIP_ITEM_STYLE}
                    cursor={CHART_CURSOR}
                    animationDuration={200}
                    formatter={(value: number, _name: string, props: any) => [
                      `${value} pts`,
                      props.payload.name,
                    ]}
                  />
                  <Bar
                    dataKey="score"
                    radius={[0, 6, 6, 0]}
                    barSize={24}
                    isAnimationActive={true}
                    animationDuration={CHART_ANIM.barDuration}
                    animationEasing={CHART_ANIM.barEasing}
                  >
                    {chartData.map((entry, idx) => (
                      <Cell key={idx} fill={getBarColor(entry.score)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="overflow-x-auto -mx-3 md:-mx-0">
              <table className="w-full text-[10px] sm:text-xs min-w-[600px]">
                <thead>
                  <tr className="border-b border-border text-muted-foreground">
                    <th className="text-left py-2 px-2">Provedor</th>
                    <th className="text-center py-2 px-1">Score</th>
                    <th className="text-center py-2 px-1">Inc.</th>
                    <th className="text-center py-2 px-1">Ataques</th>
                    <th className="text-center py-2 px-1">Alertas</th>
                    <th className="text-center py-2 px-1">Wdr</th>
                    <th className="text-center py-2 px-1">Perda</th>
                    <th className="text-right py-2 px-2">Último</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedRanking.map((r, i) => (
                    <motion.tr
                      key={r.asn}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.3, delay: i * 0.04 }}
                      className="border-b border-border/50 hover:bg-secondary/30 transition-colors duration-200"
                    >
                      <td className="py-2 px-2 text-foreground font-medium">
                        <div>{shortenName(r.name, 25)}</div>
                        <div className="text-muted-foreground text-[10px]">{r.asn}</div>
                      </td>
                      <td className="text-center py-2 px-1">
                        <Badge
                          variant="outline"
                          className={`text-[10px] ${
                            r.score >= 30
                              ? "bg-destructive/20 text-destructive border-destructive/30"
                              : r.score >= 10
                              ? "bg-yellow-500/20 text-yellow-500 border-yellow-500/30"
                              : "bg-green-500/20 text-green-500 border-green-500/30"
                          }`}
                        >
                          {r.score}
                        </Badge>
                      </td>
                      <td className="text-center py-2 px-1 text-foreground">{r.totalIncidents}</td>
                      <td className="text-center py-2 px-1">
                        {r.attacks > 0 ? (
                          <span className="flex items-center justify-center gap-0.5 text-destructive">
                            <ShieldAlert className="h-3 w-3" /> {r.attacks}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">0</span>
                        )}
                      </td>
                      <td className="text-center py-2 px-1">
                        {r.warnings > 0 ? (
                          <span className="flex items-center justify-center gap-0.5 text-yellow-500">
                            <AlertTriangle className="h-3 w-3" /> {r.warnings}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">0</span>
                        )}
                      </td>
                      <td className="text-center py-2 px-1 text-foreground">{r.totalWithdrawals}</td>
                      <td className="text-center py-2 px-1 text-foreground">{r.avgPacketLoss}%</td>
                      <td className="text-right py-2 px-2 text-muted-foreground">
                        <span className="flex items-center justify-end gap-0.5">
                          <Clock className="h-3 w-3" />
                          <span>
                            {new Date(r.lastIncident).toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit" })}
                            {" "}
                            {new Date(r.lastIncident).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" })}
                          </span>
                        </span>
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
