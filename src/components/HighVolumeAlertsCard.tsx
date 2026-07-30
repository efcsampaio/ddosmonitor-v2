import { useState, useMemo, useEffect, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import {
  AlertTriangle,
  Zap,
  ChevronLeft,
  ChevronRight,
  Shield,
  Activity,
  Radio,
  Clock,
  TrendingUp,
  ShieldAlert,
} from "lucide-react";
import { motion, AnimatePresence, useMotionValue, useTransform, animate } from "motion/react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import {
  CHART_TOOLTIP_STYLE,
  CHART_TOOLTIP_LABEL_STYLE,
  CHART_TOOLTIP_ITEM_STYLE,
  CHART_ANIM,
} from "@/lib/chartConfig";
import type { HighVolumeAlert, PossibleAttackReason, MY_ASNS } from "@/hooks/useWanguardAttacks";

const PAGE_SIZE = 20;

const SEVERITY_COLORS = {
  critical: "hsl(0, 84%, 60%)",
  warning: "hsl(45, 93%, 58%)",
  info: "hsl(199, 89%, 48%)",
  ok: "hsl(142, 71%, 45%)",
};

const REASON_CONFIG: Record<PossibleAttackReason, { label: string; color: string; bg: string; border: string }> = {
  BOTH: { label: "Sinal Externo", color: "hsl(45, 93%, 58%)", bg: "hsl(45, 93%, 58% / 0.2)", border: "hsl(45, 93%, 58% / 0.3)" },
  EXTERNAL: { label: "Sinal Externo", color: "hsl(45, 93%, 58%)", bg: "hsl(45, 93%, 58% / 0.2)", border: "hsl(45, 93%, 58% / 0.3)" },
  INTERNAL: { label: "Sinal Interno", color: "hsl(199, 89%, 48%)", bg: "hsl(199, 89%, 48% / 0.2)", border: "hsl(199, 89%, 48% / 0.3)" },
};

function severityOf(gbps: number) {
  if (gbps >= 100) return "critical";
  if (gbps >= 50) return "warning";
  return "info";
}

function AnimatedCounter({ value }: { value: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const mv = useMotionValue(0);
  const rounded = useTransform(mv, (v) => Math.round(v));

  useEffect(() => {
    const c = animate(mv, value, { duration: 0.8, ease: "easeOut" });
    return c.stop;
  }, [value, mv]);

  useEffect(() => {
    return rounded.on("change", (v) => {
      if (ref.current) ref.current.textContent = String(v);
    });
  }, [rounded]);

  return <span ref={ref}>0</span>;
}

function StatCard({
  label, value, icon: Icon, color, glowColor, delay,
}: {
  label: string; value: number; icon: React.ElementType; color: string; glowColor: string; delay: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay }}
      whileHover={{ y: -4, scale: 1.02, boxShadow: `0 0 20px ${glowColor}`, transition: { type: "spring", stiffness: 400, damping: 25 } }}
    >
      <Card className="bg-card border-border p-3 md:p-4 transition-all duration-300">
        <div className="flex items-center gap-3">
          <motion.div whileHover={{ scale: 1.15, rotate: 5 }} transition={{ type: "spring", stiffness: 400, damping: 20 }}>
            <Icon className="h-6 w-6 md:h-8 md:w-8 shrink-0" style={{ color }} />
          </motion.div>
          <div className="min-w-0">
            <p className="text-lg md:text-2xl font-bold text-foreground"><AnimatedCounter value={value} /></p>
            <p className="text-[10px] md:text-xs text-muted-foreground truncate">{label}</p>
          </div>
        </div>
      </Card>
    </motion.div>
  );
}

function SeverityDistribution({ alerts }: { alerts: HighVolumeAlert[] }) {
  const data = useMemo(() => {
    let critical = 0, warning = 0, info = 0;
    for (const a of alerts) {
      const s = severityOf(a.sizeGbps);
      if (s === "critical") critical++;
      else if (s === "warning") warning++;
      else info++;
    }
    return [
      { name: "Crítico (≥100 Gbps)", value: critical, color: SEVERITY_COLORS.critical },
      { name: "Alto (≥50 Gbps)", value: warning, color: SEVERITY_COLORS.warning },
      { name: "Elevado (≥10 Gbps)", value: info, color: SEVERITY_COLORS.info },
    ].filter((d) => d.value > 0);
  }, [alerts]);

  if (data.length === 0) return null;

  return (
    <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.5, delay: 0.3 }}>
      <Card className="bg-card border-border p-4">
        <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
          <TrendingUp className="h-4 w-4 text-muted-foreground" />
          Distribuição por Severidade
        </h3>
        <div className="flex items-center gap-4">
          <div className="h-[120px] w-[120px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  dataKey="value"
                  cx="50%"
                  cy="50%"
                  innerRadius={30}
                  outerRadius={55}
                  strokeWidth={0}
                  animationDuration={CHART_ANIM.pieDuration}
                  animationEasing={CHART_ANIM.pieEasing}
                >
                  {data.map((d, i) => (
                    <Cell key={i} fill={d.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={CHART_TOOLTIP_STYLE}
                  labelStyle={CHART_TOOLTIP_LABEL_STYLE}
                  itemStyle={CHART_TOOLTIP_ITEM_STYLE}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex flex-col gap-1.5 text-xs">
            {data.map((d) => (
              <div key={d.name} className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: d.color }} />
                <span className="text-muted-foreground">{d.name}:</span>
                <span className="font-semibold text-foreground">{d.value}</span>
              </div>
            ))}
          </div>
        </div>
      </Card>
    </motion.div>
  );
}

function TimelineDot({ alert, isLast }: { alert: HighVolumeAlert; isLast: boolean }) {
  const sev = severityOf(alert.sizeGbps);
  const color = SEVERITY_COLORS[sev];

  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center">
        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ type: "spring", stiffness: 500, damping: 30 }}
          className="w-3 h-3 rounded-full shrink-0 mt-1"
          style={{ background: color, boxShadow: `0 0 8px ${color}` }}
        />
        {!isLast && <div className="w-px flex-1 bg-border mt-1" />}
      </div>
      <div className="pb-4 min-w-0">
        <p className="text-xs font-mono text-muted-foreground">
          {alert.timestamp.toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}
        </p>
        <p className="text-sm text-foreground">
          <span className="font-semibold" style={{ color }}>{alert.sizeGbps.toFixed(1)} Gbps</span>
          {" — "}
          <span className="font-mono text-xs">{alert.prefix}</span>
          {" "}
          <Badge variant="outline" className="text-[10px] ml-1">{alert.attackType}</Badge>
        </p>
      </div>
    </div>
  );
}

interface Props {
  alerts: HighVolumeAlert[];
}

export function HighVolumeAlertsCard({ alerts }: Props) {
  const [page, setPage] = useState(1);
  const [view, setView] = useState<"table" | "timeline">("table");
  const [onlyPossibleAttacks, setOnlyPossibleAttacks] = useState(false);
  const [onlyThirdParty, setOnlyThirdParty] = useState(false);

  useEffect(() => { setPage(1); }, [alerts, onlyPossibleAttacks, onlyThirdParty]);

  const externalCount = useMemo(() => alerts.filter((a) => a.possibleAttackReason === "EXTERNAL" || a.possibleAttackReason === "BOTH").length, [alerts]);
  const thirdPartyCount = useMemo(() => alerts.filter((a) => a.isThirdParty).length, [alerts]);

  const sortedAlerts = useMemo(() => {
    return [...alerts].sort((a, b) => {
      const aExt = a.possibleAttackReason === "EXTERNAL" || a.possibleAttackReason === "BOTH" ? 1 : 0;
      const bExt = b.possibleAttackReason === "EXTERNAL" || b.possibleAttackReason === "BOTH" ? 1 : 0;
      if (bExt !== aExt) return bExt - aExt;
      // Third-party second priority
      if (a.isThirdParty !== b.isThirdParty) return a.isThirdParty ? -1 : 1;
      return b.timestamp.getTime() - a.timestamp.getTime();
    });
  }, [alerts]);

  const displayAlerts = useMemo(() => {
    let filtered = sortedAlerts;
    if (onlyPossibleAttacks) filtered = filtered.filter((a) => a.possibleAttackReason === "EXTERNAL" || a.possibleAttackReason === "BOTH");
    if (onlyThirdParty) filtered = filtered.filter((a) => a.isThirdParty);
    return filtered;
  }, [sortedAlerts, onlyPossibleAttacks, onlyThirdParty]);

  const totalPages = Math.max(1, Math.ceil(displayAlerts.length / PAGE_SIZE));
  const paged = useMemo(
    () => displayAlerts.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE),
    [displayAlerts, page]
  );

  const stats = useMemo(() => {
    let critical = 0, warning = 0, info = 0, maxGbps = 0;
    for (const a of alerts) {
      if (a.sizeGbps > maxGbps) maxGbps = a.sizeGbps;
      const s = severityOf(a.sizeGbps);
      if (s === "critical") critical++;
      else if (s === "warning") warning++;
      else info++;
    }
    return { total: alerts.length, critical, warning, info, maxGbps };
  }, [alerts]);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 md:gap-3">
        <StatCard label="Total de alertas" value={stats.total} icon={Activity} color={SEVERITY_COLORS.info} glowColor="hsl(199 89% 48% / 0.2)" delay={0} />
        <StatCard label="Críticos (≥100G)" value={stats.critical} icon={AlertTriangle} color={SEVERITY_COLORS.critical} glowColor="hsl(0 84% 60% / 0.2)" delay={0.1} />
        <StatCard label="Altos (≥50G)" value={stats.warning} icon={Radio} color={SEVERITY_COLORS.warning} glowColor="hsl(45 93% 58% / 0.2)" delay={0.2} />
        <StatCard label="Pico máximo" value={Math.round(stats.maxGbps)} icon={Zap} color={SEVERITY_COLORS.critical} glowColor="hsl(0 84% 60% / 0.15)" delay={0.3} />
      </div>

      {alerts.length > 0 && <SeverityDistribution alerts={alerts} />}

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 0.2 }}>
        <Card className="bg-card border-border overflow-hidden">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <CardTitle className="text-base flex items-center gap-2">
                <motion.div animate={{ rotate: [0, 5, -5, 0] }} transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}>
                  <Zap className="h-5 w-5 text-destructive" />
                </motion.div>
                Ataques acima de 10 Gbps
                {alerts.length > 0 && (
                  <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", stiffness: 500, damping: 30 }}>
                    <Badge variant="destructive" className="ml-1 text-xs">{alerts.length}</Badge>
                  </motion.div>
                )}
              </CardTitle>
              {alerts.length > 0 && (
                <div className="flex items-center gap-3 flex-wrap">
                  <div className="flex items-center gap-2">
                    <Switch
                      id="only-attacks"
                      checked={onlyPossibleAttacks}
                      onCheckedChange={setOnlyPossibleAttacks}
                      className="scale-90"
                    />
                    <Label htmlFor="only-attacks" className="text-xs text-muted-foreground cursor-pointer flex items-center gap-1">
                      <ShieldAlert className="h-3.5 w-3.5" />
                      Somente sinais externos ({externalCount})
                    </Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch
                      id="only-third-party"
                      checked={onlyThirdParty}
                      onCheckedChange={setOnlyThirdParty}
                      className="scale-90"
                    />
                    <Label htmlFor="only-third-party" className="text-xs text-muted-foreground cursor-pointer flex items-center gap-1">
                      <Shield className="h-3.5 w-3.5" style={{ color: "hsl(270, 70%, 60%)" }} />
                      Somente ASNs de terceiros ({thirdPartyCount})
                    </Label>
                  </div>
                  <div className="flex gap-1">
                    <Button size="sm" variant={view === "table" ? "default" : "outline"} className="text-xs h-7 px-2" onClick={() => setView("table")}>Tabela</Button>
                    <Button size="sm" variant={view === "timeline" ? "default" : "outline"} className="text-xs h-7 px-2" onClick={() => setView("timeline")}>Timeline</Button>
                  </div>
                </div>
              )}
            </div>
          </CardHeader>
          <CardContent>
            {alerts.length === 0 ? (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col items-center gap-3 py-8">
                <motion.div animate={{ y: [0, -8, 0] }} transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}>
                  <Shield className="h-10 w-10 text-muted-foreground" />
                </motion.div>
                <p className="text-sm text-muted-foreground text-center">Nenhum ataque de alto volume registrado no período selecionado.</p>
              </motion.div>
            ) : (
              <AnimatePresence mode="wait">
                {view === "table" ? (
                  <motion.div key="table" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.25 }}>
                     <p className="text-sm text-muted-foreground mb-3">
                       {displayAlerts.length} ataque{displayAlerts.length > 1 ? "s" : ""} de alto volume identificado{displayAlerts.length > 1 ? "s" : ""}
                       {onlyPossibleAttacks && ` (filtrado de ${alerts.length})`}.
                     </p>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs min-w-[750px]">
                        <thead>
                          <tr className="border-b border-border text-muted-foreground">
                            <th className="text-left py-2 px-2">Data/Hora</th>
                            <th className="text-left py-2 px-2">Prefixo</th>
                            <th className="text-left py-2 px-2">Tipo</th>
                            <th className="text-right py-2 px-2">Volume (Gbps)</th>
                            <th className="text-center py-2 px-2">Possível ataque</th>
                          </tr>
                        </thead>
                        <tbody>
                          {paged.map((a, idx) => {
                            const color = SEVERITY_COLORS[severityOf(a.sizeGbps)];
                            const reasonCfg = a.possibleAttackReason ? REASON_CONFIG[a.possibleAttackReason] : null;
                            return (
                              <motion.tr
                                key={`${a.id}_${idx}`}
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ duration: 0.25, delay: idx * 0.03 }}
                                className="border-b border-border/50 hover:bg-secondary/30 transition-colors duration-200"
                                style={{ borderLeft: `3px solid ${color}` }}
                              >
                                <td className="py-2 px-2 font-mono text-muted-foreground">
                                  <span className="flex items-center gap-1">
                                    <Clock className="h-3 w-3" />
                                    {a.timestamp.toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}
                                  </span>
                                </td>
                                <td className="py-2 px-2 font-mono text-foreground">{a.prefix}</td>
                                <td className="py-2 px-2"><Badge variant="outline" className="text-[10px]">{a.attackType}</Badge></td>
                                <td className="py-2 px-2 text-right font-semibold" style={{ color }}>{a.sizeGbps.toFixed(1)}</td>
                                <td className="py-2 px-2 text-center">
                                  <div className="flex flex-wrap gap-1 justify-center">
                                    {(a.possibleAttackReason === "EXTERNAL" || a.possibleAttackReason === "BOTH") && (
                                      <Badge
                                        variant="outline"
                                        className="text-[10px] px-1.5 py-0.5 font-medium"
                                        style={{ backgroundColor: "hsl(45, 93%, 58% / 0.2)", color: "hsl(45, 93%, 58%)", borderColor: "hsl(45, 93%, 58% / 0.3)" }}
                                      >
                                        <ShieldAlert className="h-3 w-3 mr-0.5" />
                                        Sinal Externo
                                      </Badge>
                                    )}
                                    {a.isThirdParty && (
                                      <Badge
                                        variant="outline"
                                        className="text-[10px] px-1.5 py-0.5 font-medium"
                                        style={{ backgroundColor: "hsl(270, 70%, 60% / 0.2)", color: "hsl(270, 70%, 60%)", borderColor: "hsl(270, 70%, 60% / 0.3)" }}
                                      >
                                        <Shield className="h-3 w-3 mr-0.5" />
                                        ASN Terceiro
                                      </Badge>
                                    )}
                                  </div>
                                </td>
                              </motion.tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                    {totalPages > 1 && (
                      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }} className="flex items-center justify-between mt-4 pt-3 border-t border-border">
                        <motion.div whileHover={{ x: -3 }} whileTap={{ scale: 0.95 }}>
                          <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => p - 1)} className="gap-1">
                            <ChevronLeft className="h-4 w-4" /> Anterior
                          </Button>
                        </motion.div>
                        <span className="text-sm text-muted-foreground">Página <span className="font-semibold text-foreground">{page}</span> de {totalPages}</span>
                        <motion.div whileHover={{ x: 3 }} whileTap={{ scale: 0.95 }}>
                          <Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="gap-1">
                            Próxima <ChevronRight className="h-4 w-4" />
                          </Button>
                        </motion.div>
                      </motion.div>
                    )}
                  </motion.div>
                ) : (
                  <motion.div key="timeline" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} transition={{ duration: 0.25 }} className="max-h-[500px] overflow-y-auto pr-2">
                    {paged.map((a, i) => (
                      <motion.div key={`${a.id}_${i}`} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}>
                        <TimelineDot alert={a} isLast={i === paged.length - 1} />
                      </motion.div>
                    ))}
                    {totalPages > 1 && (
                      <div className="flex items-center justify-between mt-4 pt-3 border-t border-border">
                        <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => p - 1)} className="gap-1"><ChevronLeft className="h-4 w-4" /> Anterior</Button>
                        <span className="text-sm text-muted-foreground">Página <span className="font-semibold text-foreground">{page}</span> de {totalPages}</span>
                        <Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="gap-1">Próxima <ChevronRight className="h-4 w-4" /></Button>
                      </div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            )}
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
