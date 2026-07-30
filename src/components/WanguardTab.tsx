import { useState, useMemo } from "react";
import { useWanguardAttacks, computeAggregates, normalizeAttackType, type PeriodOption, type WanguardAggregates } from "@/hooks/useWanguardAttacks";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { RefreshCw, ShieldAlert, BarChart3, Clock, Target, TrendingUp, Grid3X3, List, Crosshair, CalendarDays, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import { motion, useInView } from "motion/react";
import { useRef } from "react";
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
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  CartesianGrid,
  Area,
  AreaChart,
  Legend,
} from "recharts";

const PERIOD_OPTIONS: { value: PeriodOption; label: string }[] = [
  { value: "24h", label: "Últimas 24h" },
  { value: "7d", label: "Últimos 7 dias" },
  { value: "30d", label: "Últimos 30 dias" },
];

const PIE_COLORS = [
  "hsl(var(--primary))",
  "hsl(var(--destructive))",
  "hsl(210, 70%, 55%)",
  "hsl(45, 90%, 55%)",
  "hsl(160, 60%, 45%)",
  "hsl(280, 60%, 55%)",
  "hsl(20, 80%, 55%)",
  "hsl(330, 60%, 50%)",
];

const UNCLASSIFIED_COLOR = "hsl(var(--muted-foreground))";

const TIME_SLOTS = [
  { label: "00h–06h", min: 0, max: 5 },
  { label: "06h–12h", min: 6, max: 11 },
  { label: "12h–18h", min: 12, max: 17 },
  { label: "18h–24h", min: 18, max: 23 },
];

function formatBps(bps: number): string {
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} Gbps`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(2)} Mbps`;
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(1)} Kbps`;
  return `${bps} bps`;
}

export function WanguardTab() {
  const [period, setPeriod] = useState<PeriodOption>("7d");
  const [refreshKey, setRefreshKey] = useState(0);
  const [typeFilter, setTypeFilter] = useState("all");
  const { events, aggregates, isLoading, refetch } = useWanguardAttacks(period, refreshKey);

  const handleRefresh = () => {
    setRefreshKey((k) => k + 1);
    refetch();
  };

  const attackTypes = useMemo(
    () => aggregates.typeStats.filter((s) => s.count > 0).map((s) => s.type),
    [aggregates.typeStats]
  );

  const filteredAggregates = useMemo(() => {
    if (typeFilter === "all") return aggregates;
    const filtered = events.filter((e) => normalizeAttackType(e.attackType) === typeFilter);
    return computeAggregates(filtered);
  }, [typeFilter, events, aggregates]);

  const levelData = Object.entries(filteredAggregates.byLevel).map(([name, value]) => ({ name, value }));

  const hourData = Array.from({ length: 24 }, (_, h) => ({
    hour: `${String(h).padStart(2, "0")}:00`,
    ataques: filteredAggregates.byHour[h] || 0,
  }));

  const prefixData = filteredAggregates.byPrefix.slice(0, 10);
  const dailyData = filteredAggregates.attacksByDay.map((d) => ({
    ...d,
    dateLabel: d.date.slice(5),
    totalGbps: +(d.totalBps / 1e9).toFixed(2),
  }));

  return (
    <div className="space-y-4 md:space-y-6">
      {/* Period filter + refresh */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          {PERIOD_OPTIONS.map((p) => (
            <Button
              key={p.value}
              size="sm"
              variant={period === p.value ? "default" : "outline"}
              onClick={() => setPeriod(p.value)}
            >
              {p.label}
            </Button>
          ))}
          {attackTypes.length > 1 && (
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="h-8 rounded-md border border-border bg-background px-2 text-sm text-foreground"
            >
              <option value="all">Todos os tipos</option>
              {attackTypes.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          )}
        </div>
        <Button size="sm" variant="outline" className="gap-1.5" onClick={handleRefresh} disabled={isLoading}>
          <RefreshCw className={cn("h-4 w-4", isLoading && "animate-spin")} /> Atualizar
        </Button>
      </div>

      {isLoading ? (
        <div className="text-center py-12 text-muted-foreground animate-pulse">Carregando dados do Wanguard...</div>
      ) : events.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground">
          <p>Nenhum ataque encontrado no período selecionado.</p>
        </div>
      ) : (
        <>
          {/* Resumo Recente */}
          <Card className="p-4 md:p-6">
            <div className="flex items-center gap-2 mb-4">
              <ShieldAlert className="h-5 w-5 text-primary" />
              <h3 className="font-semibold text-foreground">Resumo Recente</h3>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <Stat label="Total de ataques" value={String(filteredAggregates.totalAttacks)} />
              <Stat label="Volume total" value={formatBps(filteredAggregates.totalBps)} />
              <Stat label="Volume médio" value={formatBps(filteredAggregates.avgBps)} />
              <Stat label="Pico máximo" value={formatBps(filteredAggregates.maxBps)} />
            </div>
          </Card>

          {/* Donut + Linha side by side */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <AnimatedChartCard>
              <div className="flex items-center gap-2 mb-4">
                <BarChart3 className="h-5 w-5 text-primary" />
                <h3 className="font-semibold text-foreground">Ataques por Tipo/Nível</h3>
              </div>
              {levelData.length > 0 ? (
                <ResponsiveContainer width="100%" height={260}>
                  <PieChart>
                    <Pie
                      data={levelData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={90}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      animationDuration={CHART_ANIM.pieDuration}
                      animationEasing={CHART_ANIM.pieEasing}
                    >
                      {levelData.map((entry, i) => (
                        <Cell
                          key={i}
                          fill={entry.name === "Sem classificação" ? UNCLASSIFIED_COLOR : PIE_COLORS[i % PIE_COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={CHART_TOOLTIP_STYLE}
                      labelStyle={CHART_TOOLTIP_LABEL_STYLE}
                      itemStyle={CHART_TOOLTIP_ITEM_STYLE}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <p className="text-sm text-muted-foreground">Sem dados</p>
              )}
            </AnimatedChartCard>

            <AnimatedChartCard>
              <div className="flex items-center gap-2 mb-4">
                <Clock className="h-5 w-5 text-primary" />
                <h3 className="font-semibold text-foreground">Ataques por Horário do Dia</h3>
              </div>
              <ResponsiveContainer width="100%" height={260}>
                <LineChart data={hourData}>
                  <CartesianGrid {...CHART_GRID} />
                  <XAxis dataKey="hour" tick={CHART_AXIS_TICK} interval={2} stroke="hsl(var(--muted-foreground))" axisLine={false} tickLine={false} />
                  <YAxis allowDecimals={false} tick={CHART_AXIS_TICK} stroke="hsl(var(--muted-foreground))" axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={CHART_TOOLTIP_STYLE}
                    labelStyle={CHART_TOOLTIP_LABEL_STYLE}
                    itemStyle={CHART_TOOLTIP_ITEM_STYLE}
                    cursor={CHART_CURSOR}
                    animationDuration={200}
                  />
                  <defs>
                    <linearGradient id="hourLineGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Line
                    type="monotone"
                    dataKey="ataques"
                    stroke="hsl(var(--primary))"
                    strokeWidth={2.5}
                    dot={{ r: 3, fill: "hsl(var(--primary))", stroke: "hsl(var(--background))", strokeWidth: 2 }}
                    activeDot={{ r: 6, fill: "hsl(var(--primary))", stroke: "hsl(var(--background))", strokeWidth: 2 }}
                    animationDuration={CHART_ANIM.lineDuration}
                    animationEasing={CHART_ANIM.lineEasing}
                  />
                </LineChart>
              </ResponsiveContainer>
            </AnimatedChartCard>
          </div>

          {/* Alertas de picos anormais */}
          <PeakAlertsCard dailyStats={filteredAggregates.dailyStats} />

          {/* Tendência Diária */}
          {dailyData.length > 1 && (
            <AnimatedChartCard>
              <div className="flex items-center gap-2 mb-4">
                <CalendarDays className="h-5 w-5 text-primary" />
                <h3 className="font-semibold text-foreground">Tendência Diária de Ataques</h3>
              </div>
              <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={dailyData}>
                  <defs>
                    <linearGradient id="dailyAreaGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid {...CHART_GRID} />
                  <XAxis dataKey="dateLabel" tick={CHART_AXIS_TICK} stroke="hsl(var(--muted-foreground))" axisLine={false} tickLine={false} />
                  <YAxis yAxisId="left" allowDecimals={false} tick={CHART_AXIS_TICK} stroke="hsl(var(--muted-foreground))" axisLine={false} tickLine={false} />
                  <YAxis yAxisId="right" orientation="right" tick={CHART_AXIS_TICK} stroke="hsl(var(--muted-foreground))" axisLine={false} tickLine={false} tickFormatter={(v: number) => `${v} Gbps`} />
                  <Tooltip
                    contentStyle={CHART_TOOLTIP_STYLE}
                    labelStyle={CHART_TOOLTIP_LABEL_STYLE}
                    itemStyle={CHART_TOOLTIP_ITEM_STYLE}
                    cursor={CHART_CURSOR}
                    animationDuration={200}
                    formatter={(value: number, name: string) =>
                      name === "totalGbps" ? [`${value} Gbps`, "Volume"] : [value, "Ataques"]
                    }
                    labelFormatter={(label) => `Data: ${label}`}
                  />
                  <Legend wrapperStyle={CHART_LEGEND_STYLE} />
                  <Area
                    yAxisId="left"
                    type="monotone"
                    dataKey="count"
                    name="Ataques"
                    stroke="hsl(var(--primary))"
                    fill="url(#dailyAreaGrad)"
                    strokeWidth={2.5}
                    animationDuration={CHART_ANIM.lineDuration}
                    animationEasing={CHART_ANIM.lineEasing}
                    dot={(props: any) => {
                      const isPeak = filteredAggregates.dailyStats.peakDays.some((p) => p.date === dailyData[props.index]?.date);
                      if (!isPeak) return <circle key={props.index} cx={0} cy={0} r={0} fill="none" />;
                      return (
                        <g key={props.index}>
                          <circle cx={props.cx} cy={props.cy} r={10} fill="hsl(var(--destructive))" opacity={0.15}>
                            <animate attributeName="r" values="6;12;6" dur="2s" repeatCount="indefinite" />
                            <animate attributeName="opacity" values="0.2;0.05;0.2" dur="2s" repeatCount="indefinite" />
                          </circle>
                          <circle cx={props.cx} cy={props.cy} r={6} fill="hsl(var(--destructive))" stroke="hsl(var(--background))" strokeWidth={2} />
                        </g>
                      );
                    }}
                    activeDot={{ r: 6, fill: "hsl(var(--primary))", stroke: "hsl(var(--background))", strokeWidth: 2 }}
                  />
                  <Line
                    yAxisId="right"
                    type="monotone"
                    dataKey="totalGbps"
                    name="Volume (Gbps)"
                    stroke="hsl(var(--destructive))"
                    strokeWidth={2}
                    dot={false}
                    activeDot={{ r: 5, fill: "hsl(var(--destructive))", stroke: "hsl(var(--background))", strokeWidth: 2 }}
                    animationDuration={CHART_ANIM.lineDuration}
                    animationBegin={200}
                    animationEasing={CHART_ANIM.lineEasing}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </AnimatedChartCard>
          )}

          {/* Padrão por tipo de ataque (tabela) */}
          <TypeStatsTable aggregates={filteredAggregates} />

          {/* Correlação tipo x horário (heatmap) */}
          <TypeHourHeatmap aggregates={filteredAggregates} />

          {/* Padrões de periodicidade */}
          <PeriodicityInsights aggregates={filteredAggregates} />

          {/* Blocos mais atacados */}
          <AnimatedChartCard>
            <div className="flex items-center gap-2 mb-4">
              <Target className="h-5 w-5 text-primary" />
              <h3 className="font-semibold text-foreground">Blocos/Prefixos Mais Atacados</h3>
            </div>
            {prefixData.length > 0 ? (
              <ResponsiveContainer width="100%" height={Math.max(200, prefixData.length * 36)}>
                <BarChart data={prefixData} layout="vertical" margin={{ left: 20 }}>
                  <CartesianGrid {...CHART_GRID} />
                  <XAxis type="number" allowDecimals={false} tick={CHART_AXIS_TICK} stroke="hsl(var(--muted-foreground))" axisLine={false} tickLine={false} />
                  <YAxis
                    dataKey="prefix"
                    type="category"
                    width={160}
                    tick={CHART_AXIS_TICK}
                    stroke="hsl(var(--muted-foreground))"
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={CHART_TOOLTIP_STYLE}
                    labelStyle={CHART_TOOLTIP_LABEL_STYLE}
                    itemStyle={CHART_TOOLTIP_ITEM_STYLE}
                    cursor={CHART_CURSOR}
                    animationDuration={200}
                    formatter={(value: number, name: string) =>
                      name === "totalBps" ? formatBps(value) : value
                    }
                  />
                  <Bar
                    dataKey="count"
                    name="Ataques"
                    fill="hsl(var(--primary))"
                    radius={[0, 4, 4, 0]}
                    animationDuration={CHART_ANIM.barDuration}
                    animationEasing={CHART_ANIM.barEasing}
                  />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-sm text-muted-foreground">Sem dados</p>
            )}
          </AnimatedChartCard>

          {/* Blocos atacados primeiro */}
          <FirstHitCard aggregates={filteredAggregates} />
        </>
      )}
    </div>
  );
}

/* ── Animated chart card wrapper ── */

function AnimatedChartCard({ children }: { children: React.ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: true, margin: "-80px" });

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 25 }}
      animate={isInView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.5, ease: "easeOut" }}
    >
      <Card className="p-4 md:p-6">{children}</Card>
    </motion.div>
  );
}

/* ── Small components ──  */

function FirstHitCard({ aggregates }: { aggregates: WanguardAggregates }) {
  const top3 = aggregates.firstHitByPrefix.slice(0, 3);

  return (
    <Card className="p-4 md:p-6">
      <div className="flex items-center gap-2 mb-3">
        <Crosshair className="h-5 w-5 text-primary" />
        <h3 className="font-semibold text-foreground">Blocos Atacados Primeiro</h3>
      </div>
      {top3.length > 0 ? (
        <div className="space-y-1.5 text-sm text-muted-foreground">
          {top3.map((item) => (
            <p key={item.prefix}>
              <span className="text-foreground font-medium">{item.prefix}</span>{" "}
              foi o primeiro alvo em{" "}
              <span className="text-foreground font-medium">{item.firstHitCount} {item.firstHitCount === 1 ? "dia" : "dias"}</span>{" "}
              do período.
            </p>
          ))}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">
          Dados insuficientes para identificar blocos atacados primeiro neste período.
        </p>
      )}
    </Card>
  );
}


function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-lg font-semibold text-foreground">{value}</p>
    </div>
  );
}

/* ── Tabela: Padrão por tipo de ataque ── */

function TypeStatsTable({ aggregates }: { aggregates: WanguardAggregates }) {
  if (aggregates.typeStats.length === 0) return null;

  return (
    <Card className="p-4 md:p-6">
      <div className="flex items-center gap-2 mb-4">
        <List className="h-5 w-5 text-primary" />
        <h3 className="font-semibold text-foreground">Padrão por Tipo de Ataque</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-muted-foreground">
              <th className="py-2 pr-4 font-medium">Tipo</th>
              <th className="py-2 pr-4 font-medium text-right">Qtd</th>
              <th className="py-2 pr-4 font-medium text-right">Volume Total</th>
              <th className="py-2 pr-4 font-medium text-right">Vol. Médio</th>
              <th className="py-2 font-medium text-right">Horário de Pico</th>
            </tr>
          </thead>
          <tbody>
            {aggregates.typeStats.map((s) => (
              <tr key={s.type} className="border-b border-border/50 hover:bg-secondary/30 transition-colors">
                <td className="py-2 pr-4 font-medium text-foreground">{s.type}</td>
                <td className="py-2 pr-4 text-right text-foreground">{s.count}</td>
                <td className="py-2 pr-4 text-right text-muted-foreground">{formatBps(s.totalBps)}</td>
                <td className="py-2 pr-4 text-right text-muted-foreground">{formatBps(s.avgBps)}</td>
                <td className="py-2 text-right text-muted-foreground">
                  {String(s.peakHour).padStart(2, "0")}:00–{String(s.peakHour + 1).padStart(2, "0")}:00
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

/* ── Heatmap: Correlação tipo x horário ── */

function TypeHourHeatmap({ aggregates }: { aggregates: WanguardAggregates }) {
  const { attacksByTypeAndHour, typeStats } = aggregates;
  const types = typeStats.map((s) => s.type);

  const matrix = useMemo(() => {
    const map: Record<string, Record<string, number>> = {};
    for (const t of types) {
      map[t] = {};
      for (const slot of TIME_SLOTS) map[t][slot.label] = 0;
    }
    for (const item of attacksByTypeAndHour) {
      const slot = TIME_SLOTS.find((s) => item.hour >= s.min && item.hour <= s.max);
      if (slot && map[item.type]) {
        map[item.type][slot.label] += item.count;
      }
    }
    return map;
  }, [attacksByTypeAndHour, types]);

  const maxVal = useMemo(() => {
    let m = 0;
    for (const row of Object.values(matrix)) {
      for (const v of Object.values(row)) if (v > m) m = v;
    }
    return m || 1;
  }, [matrix]);

  if (types.length === 0) return null;

  return (
    <Card className="p-4 md:p-6">
      <div className="flex items-center gap-2 mb-4">
        <Grid3X3 className="h-5 w-5 text-primary" />
        <h3 className="font-semibold text-foreground">Correlação Tipo × Horário</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th className="py-2 pr-4 text-left font-medium">Tipo</th>
              {TIME_SLOTS.map((s) => (
                <th key={s.label} className="py-2 px-3 text-center font-medium">{s.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {types.map((type) => (
              <tr key={type} className="border-b border-border/50">
                <td className="py-2 pr-4 font-medium text-foreground whitespace-nowrap">{type}</td>
                {TIME_SLOTS.map((slot) => {
                  const val = matrix[type]?.[slot.label] || 0;
                  const intensity = val / maxVal;
                  return (
                    <td key={slot.label} className="py-2 px-3 text-center">
                      <div
                        className="rounded-md px-2 py-1 text-xs font-medium mx-auto w-fit min-w-[3rem] transition-all duration-300"
                        style={{
                          backgroundColor: val > 0
                            ? `hsl(var(--primary) / ${0.15 + intensity * 0.7})`
                            : "transparent",
                          color: intensity > 0.5 ? "hsl(var(--primary-foreground))" : "hsl(var(--foreground))",
                        }}
                      >
                        {val > 0 ? val : "—"}
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

/* ── Padrões de Periodicidade ── */

function PeriodicityInsights({ aggregates }: { aggregates: WanguardAggregates }) {
  if (aggregates.totalAttacks < 10) {
    return (
      <Card className="p-4 md:p-6">
        <div className="flex items-center gap-2 mb-2">
          <TrendingUp className="h-5 w-5 text-primary" />
          <h3 className="font-semibold text-foreground">Padrões de Periodicidade</h3>
        </div>
        <p className="text-sm text-muted-foreground">
          Dados insuficientes para identificar padrões de periodicidade neste período.
        </p>
      </Card>
    );
  }

  const sortedDays = [...aggregates.attacksByWeekday].sort((a, b) => b.count - a.count);
  const top2Days = sortedDays.slice(0, 2).filter((d) => d.count > 0);

  const peakHour = [...aggregates.attacksByHour].sort((a, b) => b.count - a.count)[0];
  const peakHourLabel = `${String(peakHour.hour).padStart(2, "0")}:00 e ${String(peakHour.hour + 1).padStart(2, "0")}:00`;

  const topType = aggregates.typeStats[0];
  const topTypePercent = topType
    ? Math.round((topType.count / aggregates.totalAttacks) * 100)
    : 0;
  const topTypePeakLabel = topType
    ? `${String(topType.peakHour).padStart(2, "0")}:00 e ${String(topType.peakHour + 1).padStart(2, "0")}:00`
    : "";

  return (
    <Card className="p-4 md:p-6">
      <div className="flex items-center gap-2 mb-3">
        <TrendingUp className="h-5 w-5 text-primary" />
        <h3 className="font-semibold text-foreground">Padrões de Periodicidade</h3>
      </div>
      <div className="space-y-1.5 text-sm text-muted-foreground">
        {top2Days.length >= 2 ? (
          <p>
            <span className="text-foreground font-medium">Dias mais críticos neste período:</span>{" "}
            {top2Days[0].weekday} ({top2Days[0].count} ataques) e {top2Days[1].weekday} ({top2Days[1].count} ataques).
          </p>
        ) : top2Days.length === 1 ? (
          <p>
            <span className="text-foreground font-medium">Dia mais crítico:</span>{" "}
            {top2Days[0].weekday} ({top2Days[0].count} ataques).
          </p>
        ) : null}
        {peakHour && peakHour.count > 0 && (
          <p>
            <span className="text-foreground font-medium">Horário de pico recorrente:</span>{" "}
            entre {peakHourLabel} ({peakHour.count} ataques).
          </p>
        )}
        {topType && topTypePercent > 0 && (
          <p>
            <span className="text-foreground font-medium">Nos dias mais críticos,</span>{" "}
            o tipo predominante foi {topType.type} ({topTypePercent}% dos ataques), com pico entre {topTypePeakLabel}.
          </p>
        )}
      </div>
    </Card>
  );
}

/* ── Alertas de Picos Anormais ── */

function PeakAlertsCard({ dailyStats }: { dailyStats: WanguardAggregates["dailyStats"] }) {
  const { peakDays } = dailyStats;

  const formatDate = (d: string) => {
    const [, m, day] = d.split("-");
    return `${day}/${m}`;
  };

  return (
    <Card className="p-4 md:p-6">
      <div className="flex items-center gap-2 mb-3">
        <AlertTriangle className={cn("h-5 w-5", peakDays.length > 0 ? "text-destructive" : "text-muted-foreground")} />
        <h3 className="font-semibold text-foreground">Alertas de Picos Anormais</h3>
      </div>
      {peakDays.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          Nenhum pico anormal de ataques foi identificado no período selecionado.
        </p>
      ) : (
        <div className="text-sm text-muted-foreground space-y-1">
          <p>
            <span className="text-foreground font-medium">Picos anormais detectados em:</span>{" "}
            {peakDays.slice(0, 3).map((p, i) => (
              <span key={p.date}>
                {i > 0 && (i === Math.min(peakDays.length, 3) - 1 ? " e " : ", ")}
                <span className="text-destructive font-medium">{formatDate(p.date)}</span>{" "}
                ({p.count} ataques, {formatBps(p.totalBps)})
              </span>
            ))}
            {peakDays.length > 3 && (
              <span> …e outros {peakDays.length - 3} dias com picos menores.</span>
            )}
            .
          </p>
        </div>
      )}
    </Card>
  );
}
