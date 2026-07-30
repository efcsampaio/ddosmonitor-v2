import { useState, useEffect, useCallback, useMemo } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { LineChart, Line, ResponsiveContainer, YAxis, Area, AreaChart, XAxis } from "recharts";
import { Zap, Wifi, Globe, Eye, Network, Server, ChevronDown, ChevronUp, Trash2, Activity, ShieldCheck, ShieldAlert, Radio, Loader2, AlertTriangle, TrendingUp, TrendingDown, Minus } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { motion, AnimatePresence } from "motion/react";
import type { ASNDataLocal } from "@/hooks/useNetworkMonitor";

interface PingNodeResult {
  node: string;
  location: string;
  country: string;
  pings: Array<{ status: string; rttMs: number }>;
  avgMs: number;
  minMs: number;
  maxMs: number;
  packetLoss: number;
}

interface PingResponse {
  ip: string;
  prefix: string;
  method: string;
  source: string;
  reportUrl: string;
  nodes: PingNodeResult[];
}

interface Props {
  dados: ASNDataLocal;
  onRemoverAsn: (asn: string) => void;
  externalRiskData?: RiskData | null;
  highlightHigh?: boolean;
  index?: number;
}

const statusConfig = {
  HEALTHY: {
    label: "Saudável",
    badgeClass: "bg-neon-green/20 text-neon-green border-neon-green/30",
    chartColor: "hsl(142, 71%, 45%)",
    color: "hsl(142 71% 45%)",
    bgColor: "hsl(142 71% 45% / 0.1)",
    borderColor: "hsl(142 71% 45% / 0.3)",
    glowShadow: "0 0 15px hsl(142 71% 45% / 0.2)",
    gradientStop: "hsla(142, 71%, 45%, 0.05)",
  },
  WARNING: {
    label: "Em Alerta",
    badgeClass: "bg-neon-yellow/20 text-neon-yellow border-neon-yellow/30",
    chartColor: "hsl(45, 93%, 58%)",
    color: "hsl(45 93% 58%)",
    bgColor: "hsl(45 93% 58% / 0.1)",
    borderColor: "hsl(45 93% 58% / 0.5)",
    glowShadow: "0 0 20px hsl(45 93% 58% / 0.3)",
    gradientStop: "hsla(45, 93%, 58%, 0.05)",
  },
  UNDER_ATTACK: {
    label: "Sob Ataque",
    badgeClass: "bg-neon-red/20 text-neon-red border-neon-red/30",
    chartColor: "hsl(0, 84%, 60%)",
    color: "hsl(0 84% 60%)",
    bgColor: "hsl(0 84% 60% / 0.1)",
    borderColor: "hsl(0 84% 60% / 0.5)",
    glowShadow: "0 0 30px hsl(0 84% 60% / 0.4), 0 0 60px hsl(0 84% 60% / 0.2)",
    gradientStop: "hsla(0, 84%, 60%, 0.05)",
  },
};

const bgpLabel: Record<string, string> = { STABLE: "Estável", FLAPPING: "Oscilando", WITHDRAWN: "Retirada" };
const bgpColor: Record<string, string> = { STABLE: "text-neon-green", FLAPPING: "text-neon-yellow", WITHDRAWN: "text-neon-red" };

function visibilityColor(percent: number): string {
  if (percent >= 90) return "text-neon-green";
  if (percent >= 70) return "text-neon-yellow";
  return "text-neon-red";
}

const RISK_BADGE_CONFIG: Record<string, { label: string; className: string }> = {
  NONE: { label: "Sem risco", className: "bg-muted text-muted-foreground border-border" },
  LOW: { label: "Risco baixo", className: "bg-neon-yellow/10 text-neon-yellow border-neon-yellow/30" },
  MEDIUM: { label: "Risco médio", className: "bg-orange-500/10 text-orange-400 border-orange-500/30" },
  HIGH: { label: "Risco alto", className: "bg-neon-red/10 text-neon-red border-neon-red/30" },
};

const SCOPE_BADGE_CONFIG: Record<string, { label: string; className: string }> = {
  LOCALIZADO: { label: "Localizado", className: "bg-neon-yellow/10 text-neon-yellow border-neon-yellow/30" },
  MULTI_PROVEDOR: { label: "Multi-provedor", className: "bg-orange-500/10 text-orange-400 border-orange-500/30" },
  AMPLO: { label: "Amplo / Regional", className: "bg-neon-red/10 text-neon-red border-neon-red/30" },
};

export interface RiskData {
  risk_score: number;
  risk_label: string;
}

export async function fetchRiskForAsn(asn: string): Promise<RiskData | null> {
  try {
    const projectId = import.meta.env.VITE_SUPABASE_PROJECT_ID;
    const anonKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
    // Antes: usava a anon key também como Authorization bearer — o backend
    // agora exige um JWT de sessão real, então buscamos o token do usuário
    // logado. O header apikey continua sendo a anon key (é o identificador
    // do projeto, não credencial de usuário).
    const { data: { session } } = await supabase.auth.getSession();
    if (!session?.access_token) return null;
    const now = new Date();
    const twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000);
    const params = new URLSearchParams({
      asn,
      start_date: twoHoursAgo.toISOString(),
      end_date: now.toISOString(),
      window_minutes: "30",
    });
    const res = await fetch(
      `https://${projectId}.supabase.co/functions/v1/estimate-attack-risk?${params}`,
      { headers: { Authorization: `Bearer ${session.access_token}`, apikey: anonKey } }
    );
    if (!res.ok) return null;
    const data = await res.json();
    if (!data.windows || data.windows.length === 0) return null;
    const last = data.windows[data.windows.length - 1];
    return { risk_score: last.risk_score, risk_label: last.risk_label };
  } catch {
    return null;
  }
}

// Metric trend icon helper
function TrendIcon({ value, threshold, invertColor }: { value: number; threshold: number; invertColor?: boolean }) {
  if (value > threshold) {
    return invertColor
      ? <TrendingUp className="h-3 w-3 text-neon-green" />
      : <TrendingUp className="h-3 w-3 text-neon-red" />;
  }
  if (value < threshold * 0.5) {
    return invertColor
      ? <TrendingDown className="h-3 w-3 text-neon-red" />
      : <TrendingDown className="h-3 w-3 text-neon-green" />;
  }
  return <Minus className="h-3 w-3 text-muted-foreground" />;
}

export function ASNCard({ dados, onRemoverAsn, externalRiskData, highlightHigh, index = 0 }: Props) {
  const { metrics, historicoLatencia } = dados;
  const cfg = statusConfig[metrics.status];
  const isAtaque = metrics.status === "UNDER_ATTACK";
  const isWarning = metrics.status === "WARNING";
  const vis = metrics.bgpVisibility;
  const neigh = metrics.neighbours;
  const prefixes = metrics.prefixes || [];
  const bgpUpdates = metrics.bgpUpdates;
  const signals = metrics.detectionSignals || [];
  const securityAlerts = metrics.securityAlerts || [];
  const attackScope = metrics.attackScope;
  const [showPrefixes, setShowPrefixes] = useState(false);
  const [showNeighbours, setShowNeighbours] = useState(false);
  const [showSignals, setShowSignals] = useState(false);
  const [showSecurity, setShowSecurity] = useState(false);
  const [showScope, setShowScope] = useState(false);
  const [pinging, setPinging] = useState(false);
  const [pingData, setPingData] = useState<PingResponse | null>(null);
  const [showPing, setShowPing] = useState(false);
  const [riskData, setRiskData] = useState<RiskData | null>(externalRiskData ?? null);
  const [riskLoading, setRiskLoading] = useState(!externalRiskData);
  const [riskError, setRiskError] = useState(false);
  const [isHovered, setIsHovered] = useState(false);

  const gradientId = useMemo(() => `chart-gradient-${metrics.asn.replace(/\D/g, "")}`, [metrics.asn]);

  const loadRisk = useCallback(async () => {
    setRiskLoading(true);
    setRiskError(false);
    const result = await fetchRiskForAsn(metrics.asn);
    if (result) {
      setRiskData(result);
    } else {
      setRiskError(true);
    }
    setRiskLoading(false);
  }, [metrics.asn]);

  useEffect(() => {
    if (externalRiskData) {
      setRiskData(externalRiskData);
      setRiskLoading(false);
      setRiskError(false);
    } else {
      loadRisk();
    }
  }, [externalRiskData, loadRisk]);

  const handlePing = async () => {
    if (prefixes.length === 0) return;
    setPinging(true);
    setPingData(null);
    setShowPing(true);
    try {
      const { data, error } = await supabase.functions.invoke("asn-monitor/ping", {
        body: { prefixes },
      });
      if (error) throw error;
      setPingData(data);
    } catch (err) {
      console.error("Ping error:", err);
      setPingData(null);
    } finally {
      setPinging(false);
    }
  };

  const riskBarGradient =
    riskData?.risk_label === "HIGH"
      ? "linear-gradient(90deg, hsl(0 84% 40%), hsl(0 84% 60%))"
      : riskData?.risk_label === "MEDIUM"
      ? "linear-gradient(90deg, hsl(30 90% 45%), hsl(25 95% 55%))"
      : riskData?.risk_label === "LOW"
      ? "linear-gradient(90deg, hsl(45 80% 40%), hsl(45 93% 58%))"
      : "linear-gradient(90deg, hsl(217 33% 30%), hsl(217 33% 40%))";

  // Expandable section data
  const expandSections = [
    { key: "signals", show: showSignals },
    { key: "security", show: showSecurity },
    { key: "scope", show: showScope },
    { key: "prefixes", show: showPrefixes },
    { key: "neighbours", show: showNeighbours },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: index * 0.05, ease: "easeOut" }}
      whileHover={{ y: -4 }}
      onHoverStart={() => setIsHovered(true)}
      onHoverEnd={() => setIsHovered(false)}
    >
      <Card
        className={`bg-card border-border p-5 transition-all duration-300 relative overflow-hidden ${
          highlightHigh && riskData?.risk_label === "HIGH"
            ? "border-neon-red/60"
            : ""
        }`}
        style={{
          borderColor: isAtaque ? cfg.borderColor : isWarning ? cfg.borderColor : undefined,
          borderWidth: isAtaque ? 2 : undefined,
          boxShadow: isHovered ? cfg.glowShadow : (isAtaque ? cfg.glowShadow : undefined),
          background: `radial-gradient(circle at top right, ${cfg.gradientStop}, transparent 70%)`,
        }}
      >
        {/* Attack pulse overlay */}
        {isAtaque && (
          <motion.div
            className="absolute inset-0 rounded-lg pointer-events-none"
            style={{ border: `2px solid ${cfg.color}` }}
            animate={{ scale: [1, 1.02, 1], opacity: [0.5, 0.8, 0.5] }}
            transition={{ duration: 1.5, repeat: Infinity, ease: "easeInOut" }}
          />
        )}

        {/* === HEADER === */}
        <div className="flex items-start justify-between mb-4 relative z-10">
          <div className="flex items-center gap-3">
            {/* Icon with shockwave for attack */}
            <div className="relative">
              <motion.div
                animate={isAtaque ? { rotate: [0, 5, -5, 0] } : {}}
                transition={isAtaque ? { duration: 0.6, repeat: Infinity, repeatDelay: 1 } : {}}
              >
                <Activity className={`h-5 w-5 ${isAtaque ? "text-neon-red" : isWarning ? "text-neon-yellow" : "text-neon-green"}`} />
              </motion.div>
              {isAtaque && (
                <motion.div
                  className="absolute inset-0 rounded-full"
                  style={{ border: `2px solid ${cfg.color}` }}
                  animate={{ scale: [1, 1.3], opacity: [0.6, 0] }}
                  transition={{ duration: 1.2, repeat: Infinity, ease: "easeOut" }}
                />
              )}
            </div>
            <div>
              <h3 className="text-lg font-bold text-foreground font-mono">{metrics.asn}</h3>
              <p className="text-sm text-muted-foreground">{metrics.name || "—"}</p>
            </div>
          </div>
          <div className="flex flex-col items-end gap-1">
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: "spring", stiffness: 500, damping: 30, delay: 0.2 }}
            >
              <Badge variant="outline" className={cfg.badgeClass}>{cfg.label}</Badge>
            </motion.div>
            {!riskLoading && riskData && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.4 }}
                className="text-[11px] font-mono text-muted-foreground"
              >
                Risco:{" "}
                <span
                  className={
                    riskData.risk_label === "HIGH" ? "text-neon-red" :
                    riskData.risk_label === "MEDIUM" ? "text-orange-400" :
                    riskData.risk_label === "LOW" ? "text-neon-yellow" :
                    "text-muted-foreground"
                  }
                >
                  {Math.round(riskData.risk_score * 100)}%
                </span>
              </motion.span>
            )}
          </div>
        </div>

        {/* === MINI CHART === */}
        <motion.div
          className="h-16 mb-4 relative z-10"
          initial={{ scaleY: 0 }}
          animate={{ scaleY: 1 }}
          transition={{ duration: 0.4, delay: 0.2, ease: "easeOut" }}
          style={{ transformOrigin: "bottom" }}
        >
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={historicoLatencia}>
              <defs>
                <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={cfg.chartColor} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={cfg.chartColor} stopOpacity={0} />
                </linearGradient>
              </defs>
              <YAxis domain={[0, "auto"]} hide />
              <Area
                type="monotone"
                dataKey="valor"
                stroke={cfg.chartColor}
                strokeWidth={2}
                fill={`url(#${gradientId})`}
                animationDuration={1000}
                animationEasing="ease-out"
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>

        {/* === GRID DE MÉTRICAS === */}
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm relative z-10">
          {/* Latência */}
          <motion.div
            className="flex items-center justify-between"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ type: "spring", stiffness: 300, damping: 20, delay: 0.1 }}
            whileHover={{ scale: 1.05 }}
          >
            <span className="flex items-center gap-2 text-muted-foreground">
              <Zap className="h-4 w-4" /> Latência
            </span>
            <span className="flex items-center gap-1 font-mono text-foreground">
              {metrics.latency.avgMs}ms
              <TrendIcon value={metrics.latency.avgMs} threshold={100} />
            </span>
          </motion.div>

          {/* Perda */}
          <motion.div
            className="flex items-center justify-between"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ type: "spring", stiffness: 300, damping: 20, delay: 0.15 }}
            whileHover={{ scale: 1.05 }}
          >
            <span className="flex items-center gap-2 text-muted-foreground">
              <Wifi className="h-4 w-4" /> Perda
            </span>
            <span className={`flex items-center gap-1 font-mono ${metrics.packetLossPercent > 5 ? "text-neon-red" : "text-foreground"}`}>
              {metrics.packetLossPercent}%
              <TrendIcon value={metrics.packetLossPercent} threshold={5} />
            </span>
          </motion.div>

          {/* Rota BGP */}
          <motion.div
            className="flex items-center justify-between"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ type: "spring", stiffness: 300, damping: 20, delay: 0.2 }}
            whileHover={{ scale: 1.05 }}
          >
            <span className="flex items-center gap-2 text-muted-foreground">
              <Globe className="h-4 w-4" /> Rota BGP
            </span>
            <span className={`font-mono ${bgpColor[metrics.bgp.state]}`}>
              {bgpLabel[metrics.bgp.state] || metrics.bgp.state}
            </span>
          </motion.div>

          {/* Visibilidade */}
          {vis && (
            <motion.div
              className="flex items-center justify-between"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ type: "spring", stiffness: 300, damping: 20, delay: 0.25 }}
              whileHover={{ scale: 1.05 }}
            >
              <span className="flex items-center gap-2 text-muted-foreground">
                <Eye className="h-4 w-4" /> Visibilidade
              </span>
              <span className={`flex items-center gap-1 font-mono ${visibilityColor(vis.totalPercent)}`}>
                {vis.totalPercent}%
                <TrendIcon value={vis.totalPercent} threshold={90} invertColor />
              </span>
            </motion.div>
          )}

          {/* BGP Updates */}
          {bgpUpdates && (
            <motion.div
              className="flex items-center justify-between col-span-2"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ type: "spring", stiffness: 300, damping: 20, delay: 0.3 }}
              whileHover={{ scale: 1.05 }}
            >
              <span className="flex items-center gap-2 text-muted-foreground">
                <Activity className="h-4 w-4" /> BGP Updates
              </span>
              <span className="font-mono text-xs">
                <span className={bgpUpdates.withdrawals > 20 ? "text-neon-red" : "text-neon-green"}>
                  ↑{bgpUpdates.announcements} ↓{bgpUpdates.withdrawals}
                </span>
                <span className="text-muted-foreground/60 ml-1">({bgpUpdates.period})</span>
              </span>
            </motion.div>
          )}
        </div>

        {/* === EXPANDABLE SECTIONS === */}
        <div className="space-y-2 text-sm mt-3 relative z-10">
          {/* Detection Signals */}
          {signals.length > 0 && (
            <div>
              <button onClick={() => setShowSignals(!showSignals)} className="flex items-center justify-between w-full hover:bg-muted/30 rounded px-0 py-0.5 transition-colors">
                <span className="flex items-center gap-2 text-muted-foreground">
                  <ShieldCheck className="h-4 w-4" /> Detecção
                </span>
                <span className="flex items-center gap-1 text-xs">
                  <span className={metrics.status === "HEALTHY" ? "text-neon-green" : metrics.status === "WARNING" ? "text-neon-yellow" : "text-neon-red"}>
                    {signals.length} sinal(is)
                  </span>
                  {showSignals ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                </span>
              </button>
              <AnimatePresence>
                {showSignals && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.3 }}
                    className="overflow-hidden"
                  >
                    <div className="mt-1.5 ml-6 space-y-0.5 border-l-2 border-border pl-3">
                      {signals.map((s, i) => (
                        <motion.div
                          key={i}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.05 }}
                          className="text-xs text-muted-foreground"
                        >
                          {s}
                        </motion.div>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}

          {/* Security Alerts */}
          <div>
            <button onClick={() => setShowSecurity(!showSecurity)} className="flex items-center justify-between w-full hover:bg-muted/30 rounded px-0 py-0.5 transition-colors">
              <span className="flex items-center gap-2 text-muted-foreground">
                {securityAlerts.some(a => a.severity === "critical") ? (
                  <ShieldAlert className="h-4 w-4 text-neon-red" />
                ) : securityAlerts.some(a => a.severity === "warning") ? (
                  <ShieldAlert className="h-4 w-4 text-neon-yellow" />
                ) : (
                  <ShieldCheck className="h-4 w-4 text-neon-green" />
                )}
                Segurança BGP
              </span>
              <span className="flex items-center gap-1 text-xs">
                {securityAlerts.some(a => a.severity === "critical") ? (
                  <span className="text-neon-red">{securityAlerts.filter(a => a.severity === "critical").length} crítico(s)</span>
                ) : securityAlerts.some(a => a.severity === "warning") ? (
                  <span className="text-neon-yellow">{securityAlerts.filter(a => a.severity === "warning").length} alerta(s)</span>
                ) : securityAlerts.length > 0 ? (
                  <span className="text-neon-green">OK ✓</span>
                ) : (
                  <span className="text-muted-foreground">Verificando...</span>
                )}
                {showSecurity ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
              </span>
            </button>
            <AnimatePresence>
              {showSecurity && securityAlerts.length > 0 && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.3 }}
                  className="overflow-hidden"
                >
                  <div className="mt-1.5 ml-6 space-y-1 border-l-2 border-border pl-3">
                    {securityAlerts.map((a, i) => {
                      const typeLabel = a.type === "hijack" ? "🔴 HIJACK" : a.type === "route_leak" ? "🟡 ROUTE LEAK" : a.severity === "info" ? "✅" : "🔵 PATH";
                      return (
                        <motion.div
                          key={i}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.05 }}
                          className="text-xs"
                        >
                          <span className="font-semibold text-foreground/80">{typeLabel}</span>
                          <span className="text-muted-foreground ml-1">{a.description}</span>
                          {a.details && <div className="text-[10px] text-muted-foreground/60 font-mono mt-0.5 break-all">{a.details}</div>}
                        </motion.div>
                      );
                    })}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Attack Scope ("Contexto do Ataque") */}
          {attackScope && (
            <div>
              <button onClick={() => setShowScope(!showScope)} className="flex items-center justify-between w-full hover:bg-muted/30 rounded px-0 py-0.5 transition-colors">
                <span className="flex items-center gap-2 text-muted-foreground">
                  <Globe className="h-4 w-4" /> Contexto do Ataque
                </span>
                <span className="flex items-center gap-1.5 text-xs">
                  <Badge variant="outline" className={`text-[10px] ${SCOPE_BADGE_CONFIG[attackScope.level]?.className || ""}`}>
                    {SCOPE_BADGE_CONFIG[attackScope.level]?.label || attackScope.level}
                  </Badge>
                  {showScope ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                </span>
              </button>
              <AnimatePresence>
                {showScope && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.3 }}
                    className="overflow-hidden"
                  >
                    <div className="mt-1.5 ml-6 space-y-1.5 border-l-2 border-border pl-3">
                      <p className="text-[10px] text-muted-foreground">
                        {attackScope.affectedAsns.length} de {attackScope.totalMonitored} ASNs monitorados afetados nos últimos {attackScope.windowMinutes} min ({Math.round(attackScope.affectedRatio * 100)}%)
                      </p>
                      {attackScope.affectedAsns.length > 0 && (
                        <div className="space-y-0.5">
                          {attackScope.affectedAsns.map((a) => (
                            <div key={a.asn} className="text-xs font-mono text-muted-foreground">
                              {a.asn} — <span className="text-foreground/70">{a.name}</span>{" "}
                              <span className={a.status === "UNDER_ATTACK" ? "text-neon-red" : "text-neon-yellow"}>
                                ({a.status === "UNDER_ATTACK" ? "sob ataque" : "em alerta"})
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                      {attackScope.sharedUpstream && attackScope.sharedUpstream.length > 0 && (
                        <p className="text-[10px] text-orange-400">
                          Upstream em comum: {attackScope.sharedUpstream.map((u) => `AS${u.asn} (${u.name})`).join(", ")}
                        </p>
                      )}
                      {attackScope.ownBlocksUnderAttack.length > 0 && (
                        <div className="space-y-0.5">
                          <span className="text-[10px] font-semibold uppercase text-neon-red">Blocos próprios sob ataque (Wanguard)</span>
                          {attackScope.ownBlocksUnderAttack.map((b) => (
                            <div key={b.prefix} className="text-xs font-mono text-muted-foreground pl-2">
                              {b.prefix}
                              {typeof b.bps === "number" ? ` — ${(b.bps / 1e9).toFixed(2)} Gbps` : ""}
                              {typeof b.pps === "number" ? ` / ${(b.pps / 1e3).toFixed(0)}k pps` : ""}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}

          {/* Prefixes */}
          {prefixes.length > 0 && (
            <div>
              <button onClick={() => setShowPrefixes(!showPrefixes)} className="flex items-center justify-between w-full hover:bg-muted/30 rounded px-0 py-0.5 transition-colors">
                <span className="flex items-center gap-2 text-muted-foreground"><Server className="h-4 w-4" /> Prefixos IPv4</span>
                <span className="flex items-center gap-1 font-mono text-foreground">{prefixes.length}{showPrefixes ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}</span>
              </button>
              <AnimatePresence>
                {showPrefixes && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.3 }}
                    className="overflow-hidden"
                  >
                    <div className="mt-1.5 ml-6 max-h-32 overflow-y-auto space-y-0.5 border-l-2 border-border pl-3">
                      {prefixes.map((p, i) => (
                        <motion.div
                          key={p}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.02 }}
                          className="text-xs font-mono text-muted-foreground"
                        >
                          {p}
                        </motion.div>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}

          {/* Neighbours */}
          {neigh && neigh.total > 0 && (
            <div>
              <button onClick={() => setShowNeighbours(!showNeighbours)} className="flex items-center justify-between w-full hover:bg-muted/30 rounded px-0 py-0.5 transition-colors">
                <span className="flex items-center gap-2 text-muted-foreground"><Network className="h-4 w-4" /> Vizinhos BGP</span>
                <span className="flex items-center gap-1 font-mono text-foreground text-xs">↑{neigh.upstreams} ↔{neigh.peers} ↓{neigh.downstreams}{showNeighbours ? <ChevronUp className="h-3 w-3 ml-1" /> : <ChevronDown className="h-3 w-3 ml-1" />}</span>
              </button>
              <AnimatePresence>
                {showNeighbours && neigh.list && neigh.list.length > 0 && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.3 }}
                    className="overflow-hidden"
                  >
                    <div className="mt-1.5 ml-6 max-h-40 overflow-y-auto space-y-1 border-l-2 border-border pl-3">
                      {["upstream", "peer", "downstream"].map((type, tIdx) => {
                        const items = neigh.list.filter((n) => n.type === type);
                        if (items.length === 0) return null;
                        const label = type === "upstream" ? "↑ Upstreams" : type === "peer" ? "↔ Peers" : "↓ Downstreams";
                        const color = type === "upstream" ? "text-neon-green" : type === "peer" ? "text-neon-yellow" : "text-muted-foreground";
                        return (
                          <motion.div
                            key={type}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: tIdx * 0.1 }}
                          >
                            <span className={`text-[10px] font-semibold uppercase ${color}`}>{label}</span>
                            {items.map((n) => <div key={n.asn} className="text-xs font-mono text-muted-foreground pl-2">AS{n.asn} — <span className="text-foreground/70">{n.name}</span></div>)}
                          </motion.div>
                        );
                      })}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}
        </div>

        {/* === CAIXA DE RISCO ESTIMADO === */}
        <motion.div
          className="mt-3 border border-border rounded-lg p-3 space-y-2 bg-muted/5 relative z-10"
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ type: "spring", stiffness: 300, damping: 20, delay: 0.35 }}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5" /> Risco Estimado de Ataque
            </span>
            {!riskLoading && (
              <motion.button
                onClick={loadRisk}
                className="text-[10px] text-muted-foreground hover:text-foreground"
                whileTap={{ scale: 0.9 }}
              >
                ↻
              </motion.button>
            )}
          </div>
          {riskLoading ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" /> Estimando risco...
            </div>
          ) : riskError || !riskData ? (
            <p className="text-[10px] text-muted-foreground">Sem dados suficientes para estimar risco.</p>
          ) : (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <motion.div
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    transition={{ type: "spring", stiffness: 500, damping: 30 }}
                  >
                    <Badge variant="outline" className={`text-[10px] ${RISK_BADGE_CONFIG[riskData.risk_label]?.className || ""}`}>
                      {RISK_BADGE_CONFIG[riskData.risk_label]?.label || riskData.risk_label}
                    </Badge>
                  </motion.div>
                  <span className="text-sm font-mono font-bold text-foreground">
                    {Math.round(riskData.risk_score * 100)}%
                  </span>
                </div>
                <span className="text-[10px] text-muted-foreground">
                  últimas 2h · janela 30min
                </span>
              </div>

              {/* Progress Bar with shimmer */}
              <div className="w-full h-2 rounded-full bg-muted/40 overflow-hidden relative">
                <motion.div
                  className="h-full rounded-full relative"
                  initial={{ width: 0 }}
                  animate={{ width: `${Math.round(riskData.risk_score * 100)}%` }}
                  transition={{ duration: 0.8, delay: 0.5, ease: "easeOut" }}
                  style={{ background: riskBarGradient }}
                >
                  {/* Shimmer effect */}
                  <motion.div
                    className="absolute inset-0"
                    style={{
                      background: `linear-gradient(90deg, transparent, ${cfg.color.replace(")", " / 0.5)")}, transparent)`,
                    }}
                    animate={{ x: ["-100%", "400%"] }}
                    transition={{ duration: 2, repeat: Infinity, repeatDelay: 1, ease: "linear" }}
                  />
                </motion.div>
              </div>

              {(riskData.risk_label === "MEDIUM" || riskData.risk_label === "HIGH") && (
                <p className="text-[10px] text-muted-foreground leading-relaxed">
                  Com base nos sinais externos recentes, este ASN apresenta risco{" "}
                  {riskData.risk_label === "HIGH" ? "elevado" : "relevante"} de estar
                  sob ataque agora.
                </p>
              )}
            </div>
          )}
        </motion.div>

        {/* === FOOTER === */}
        <motion.div
          className="mt-4 space-y-2 relative z-10"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6 }}
        >
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs text-muted-foreground">Atualizado: {new Date(metrics.lastUpdated).toLocaleTimeString("pt-BR")}</span>
            <div className="flex items-center gap-1.5">
              <motion.div whileTap={{ scale: 0.98 }}>
                <Button
                  size="sm"
                  variant="ghost"
                  className="text-xs text-muted-foreground hover:text-neon-cyan hover:bg-neon-cyan/10 hover:border-neon-cyan/30 h-7 px-2 gap-1 transition-all duration-300"
                  title="Ping ASN"
                  onClick={handlePing}
                  disabled={pinging || prefixes.length === 0}
                >
                  {pinging ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Radio className="h-3.5 w-3.5" />}
                  <span className="text-[10px]">Ping</span>
                </Button>
              </motion.div>
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <motion.div whileTap={{ scale: 0.98 }}>
                    <Button size="sm" variant="ghost" className="text-xs text-muted-foreground hover:text-destructive h-7 w-7 p-0 transition-all duration-300" title="Remover ASN"><Trash2 className="h-3.5 w-3.5" /></Button>
                  </motion.div>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>Remover {metrics.asn}?</AlertDialogTitle>
                    <AlertDialogDescription>Tem certeza que deseja remover {metrics.asn} ({metrics.name || "sem nome"}) do monitoramento?</AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Cancelar</AlertDialogCancel>
                    <AlertDialogAction onClick={() => onRemoverAsn(metrics.asn)} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">Remover</AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            </div>
          </div>

          {/* Ping Results */}
          <AnimatePresence>
            {showPing && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.3 }}
                className="overflow-hidden"
              >
                <div className="border border-border rounded p-2 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-semibold text-muted-foreground uppercase flex items-center gap-1">
                      <Radio className="h-3 w-3 text-neon-cyan" /> Resultado do Ping
                    </span>
                    <button onClick={() => setShowPing(false)} className="text-[10px] text-muted-foreground hover:text-foreground">✕</button>
                  </div>
                  {pinging && (
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <Loader2 className="h-3 w-3 animate-spin" /> Ping ICMP via check-host.net...
                    </div>
                  )}
                  {!pinging && !pingData && (
                    <div className="text-xs text-neon-red">Falha ao pingar — sem resposta</div>
                  )}
                  {pingData && (
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-[10px]">
                        <span className="text-muted-foreground font-mono">{pingData.ip} ({pingData.prefix})</span>
                        <span className="text-neon-cyan">{pingData.method}</span>
                      </div>
                      {pingData.nodes.map((node, i) => (
                        <motion.div
                          key={i}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: i * 0.05 }}
                          className="text-xs font-mono border-l-2 border-border pl-2 space-y-0.5"
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-muted-foreground text-[10px]">
                              <span className="uppercase">{node.country}</span> {node.location}
                            </span>
                            <span className={node.packetLoss === 0 ? "text-neon-green text-[10px]" : node.packetLoss < 50 ? "text-neon-yellow text-[10px]" : "text-neon-red text-[10px]"}>
                              {node.packetLoss === 0 ? "✓ 0% loss" : `${node.packetLoss}% loss`}
                            </span>
                          </div>
                          {node.avgMs > 0 && (
                            <div className="flex gap-3 text-[10px] text-muted-foreground">
                              <span>avg: <span className="text-foreground">{node.avgMs}ms</span></span>
                              <span>min: <span className="text-foreground">{node.minMs}ms</span></span>
                              <span>max: <span className="text-foreground">{node.maxMs}ms</span></span>
                            </div>
                          )}
                          <div className="flex gap-1 text-[10px] text-muted-foreground/60">
                            {node.pings.map((p, j) => (
                              <span key={j} className={p.status === "OK" ? "" : "text-neon-red/60"}>
                                #{j + 1}: {p.status === "OK" ? `${p.rttMs}ms` : p.status}
                              </span>
                            ))}
                          </div>
                        </motion.div>
                      ))}
                      <a href={pingData.reportUrl} target="_blank" rel="noopener noreferrer" className="text-[10px] text-neon-cyan/70 hover:text-neon-cyan underline">
                        Ver relatório completo ↗
                      </a>
                    </div>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Data Sources */}
          <div className="flex items-center gap-3 flex-wrap">
            {[
              { active: metrics.dataSource === "ripestat", color: "bg-neon-green", label: metrics.dataSource === "ripestat" ? "RIPEstat BGP" : "Simulado" },
              { active: true, color: "bg-neon-purple", label: "Qrator Radar" },
              { active: true, color: "bg-neon-cyan", label: "RPKI" },
              { active: true, color: "bg-orange-400", label: "AbuseIPDB" },
              { active: true, color: "bg-emerald-400", label: "GreyNoise" },
            ].map((src, i) => (
              <motion.div
                key={src.label}
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring", stiffness: 500, damping: 30, delay: 0.5 + i * 0.05 }}
                className={`flex items-center gap-1.5 ${!src.active ? "opacity-40" : ""}`}
              >
                <span className={`inline-block w-2 h-2 rounded-full ${src.active ? src.color : "bg-muted-foreground"}`} />
                <span className="text-[10px] text-muted-foreground">{src.label}</span>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </Card>
    </motion.div>
  );
}
