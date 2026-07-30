import { useState, useEffect, useRef } from "react";
import { Card } from "@/components/ui/card";
import { Activity, ShieldCheck, AlertTriangle, ShieldAlert, Flame, Shield } from "lucide-react";
import { motion, useInView, useMotionValue, useTransform, animate } from "motion/react";
import type { ASNDataLocal } from "@/hooks/useNetworkMonitor";
import { fetchIncidentCount } from "@/services/asnApi";

interface Props {
  dados: ASNDataLocal[];
  loading?: boolean;
}

function AnimatedNumber({ value }: { value: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const motionVal = useMotionValue(0);
  const rounded = useTransform(motionVal, (v) => Math.round(v));

  useEffect(() => {
    const controls = animate(motionVal, value, { duration: 0.8, ease: "easeOut" });
    return controls.stop;
  }, [value, motionVal]);

  useEffect(() => {
    return rounded.on("change", (v) => {
      if (ref.current) ref.current.textContent = String(v);
    });
  }, [rounded]);

  return <span ref={ref}>0</span>;
}

function SkeletonCard() {
  return (
    <Card className="bg-card border-border p-3 md:p-4 overflow-hidden relative">
      <div className="flex items-center gap-2 md:gap-3">
        <div className="h-6 w-6 md:h-8 md:w-8 rounded bg-muted animate-pulse" />
        <div className="min-w-0 space-y-1.5">
          <div className="h-5 w-12 rounded bg-muted animate-pulse" />
          <div className="h-3 w-20 rounded bg-muted animate-pulse" />
        </div>
      </div>
      <div className="absolute inset-0 -translate-x-full animate-[shimmer_2s_infinite]" style={{
        background: "linear-gradient(90deg, transparent, hsl(var(--muted) / 0.3), transparent)",
      }} />
    </Card>
  );
}

export function SummaryCards({ dados, loading }: Props) {
  const [totalIncidents, setTotalIncidents] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const isInView = useInView(containerRef, { once: true, margin: "-50px" });

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const count = await fetchIncidentCount(365);
        if (!cancelled) setTotalIncidents(count);
      } catch { /* ignore */ }
    }
    load();
    const interval = setInterval(load, 30000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  if (loading) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 md:gap-4">
        {Array.from({ length: 6 }).map((_, i) => <SkeletonCard key={i} />)}
      </div>
    );
  }

  const total = dados.length;
  const saudaveis = dados.filter((d) => d.metrics.status === "HEALTHY").length;
  const alertas = dados.filter((d) => d.metrics.status === "WARNING").length;
  const ataques = dados.filter((d) => d.metrics.status === "UNDER_ATTACK").length;
  const totalBgpAlerts = dados.reduce((sum, d) => sum + (d.metrics.securityAlerts?.length || 0), 0);

  const cards = [
    { label: "ASNs Monitorados", valor: total, icon: Activity, cor: "text-neon-cyan" },
    { label: "Incidentes Registrados", valor: totalIncidents, icon: Flame, cor: "text-neon-red" },
    { label: "Alertas BGP", valor: totalBgpAlerts, icon: Shield, cor: "text-neon-purple" },
    { label: "Saudáveis", valor: saudaveis, icon: ShieldCheck, cor: "text-neon-green" },
    { label: "Em Alerta", valor: alertas, icon: AlertTriangle, cor: "text-neon-yellow" },
    { label: "Sob Ataque", valor: ataques, icon: ShieldAlert, cor: "text-neon-red" },
  ];

  return (
    <div ref={containerRef} className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 md:gap-4">
      {cards.map((c, i) => (
        <motion.div
          key={c.label}
          initial={{ opacity: 0, y: 20 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.4, delay: i * 0.05, ease: "easeOut" }}
          whileHover={{ y: -4, scale: 1.02, transition: { type: "spring", stiffness: 400, damping: 25 } }}
        >
          <Card className="bg-card border-border p-3 md:p-4 transition-shadow duration-300 hover:shadow-lg hover:shadow-primary/5">
            <div className="flex items-center gap-2 md:gap-3 group">
              <motion.div whileHover={{ scale: 1.15 }} transition={{ type: "spring", stiffness: 400, damping: 20 }}>
                <c.icon className={`h-6 w-6 md:h-8 md:w-8 shrink-0 ${c.cor} transition-transform duration-300`} />
              </motion.div>
              <div className="min-w-0">
                <p className="text-lg md:text-2xl font-bold text-foreground">
                  <AnimatedNumber value={c.valor} />
                </p>
                <p className="text-[10px] md:text-xs text-muted-foreground truncate">{c.label}</p>
              </div>
            </div>
          </Card>
        </motion.div>
      ))}
    </div>
  );
}
