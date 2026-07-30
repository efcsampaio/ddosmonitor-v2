import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ShieldAlert, Clock, AlertTriangle } from "lucide-react";
import { motion, AnimatePresence } from "motion/react";

interface AlertRecord {
  id: string;
  asn: string;
  risk_score: number;
  risk_label: string;
  sources: Record<string, boolean>;
  ti_summary: string | null;
  alerted_at: string;
}

const sourceLabels: Record<string, string> = {
  qrator: "Qrator",
  rpki: "RPKI",
  bgp: "BGP",
  ripestat: "RIPEstat",
  abuseipdb: "AbuseIPDB",
};

const riskColor: Record<string, string> = {
  HIGH: "bg-destructive/20 text-destructive border-destructive/30",
  MEDIUM: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  LOW: "bg-neon-yellow/20 text-neon-yellow border-neon-yellow/30",
};

const riskBorderColor: Record<string, string> = {
  HIGH: "hsl(0, 84%, 60%)",
  MEDIUM: "hsl(30, 90%, 50%)",
  LOW: "hsl(45, 93%, 58%)",
};

export function AlertsHistory() {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<AlertRecord | null>(null);

  useEffect(() => {
    const load = async () => {
      const { data } = await supabase
        .from("alerts_history")
        .select("*")
        .order("alerted_at", { ascending: false })
        .limit(50);
      setAlerts((data as AlertRecord[]) ?? []);
      setLoading(false);
    };
    load();
  }, []);

  const activeSources = (sources: Record<string, boolean>) =>
    Object.entries(sources)
      .filter(([, v]) => v)
      .map(([k]) => sourceLabels[k] || k);

  if (loading) {
    return (
      <div className="space-y-2 py-4">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="h-16 rounded-lg bg-muted animate-pulse relative overflow-hidden">
            <div
              className="absolute inset-0 -translate-x-full animate-[shimmer_2s_infinite]"
              style={{ background: "linear-gradient(90deg, transparent, hsl(var(--muted) / 0.3), transparent)" }}
            />
          </div>
        ))}
      </div>
    );
  }

  if (alerts.length === 0) {
    return (
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <Card className="bg-card border-border p-8 text-center">
          <motion.div
            animate={{ y: [0, -8, 0] }}
            transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
          >
            <AlertTriangle className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
          </motion.div>
          <p className="text-muted-foreground">Nenhum alerta registrado ainda.</p>
        </Card>
      </motion.div>
    );
  }

  return (
    <>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <Card className="bg-card border-border overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center gap-2">
            <motion.div
              animate={{ rotate: [0, 5, -5, 0] }}
              transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
            >
              <ShieldAlert className="h-5 w-5 text-destructive" />
            </motion.div>
            <h2 className="font-semibold text-foreground">Histórico de Alertas</h2>
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: "spring", stiffness: 500, damping: 30, delay: 0.2 }}
              className="ml-auto"
            >
              <Badge variant="outline" className="text-xs">
                {alerts.length} registros
              </Badge>
            </motion.div>
          </div>

          <ScrollArea className="max-h-[520px]">
            <div className="divide-y divide-border">
              {alerts.map((a, i) => {
                const pct = Math.round(a.risk_score * 100);
                const sources = activeSources(a.sources);
                const borderClr = riskBorderColor[a.risk_label] ?? "hsl(var(--border))";

                return (
                  <motion.button
                    key={a.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.25, delay: i * 0.03 }}
                    whileHover={{
                      y: -2,
                      backgroundColor: "hsl(var(--secondary) / 0.5)",
                      transition: { duration: 0.15 },
                    }}
                    whileTap={{ scale: 0.995 }}
                    className="w-full text-left px-4 py-3 flex items-center gap-3 transition-colors"
                    style={{ borderLeft: `4px solid ${borderClr}` }}
                    onClick={() => setSelected(a)}
                  >
                    <div className="shrink-0 w-14 text-center">
                      <span className="text-lg font-bold text-foreground">{pct}%</span>
                    </div>

                    <div className="flex-1 min-w-0 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-sm text-foreground">{a.asn}</span>
                        <motion.div
                          initial={{ scale: 0 }}
                          animate={{ scale: 1 }}
                          transition={{ type: "spring", stiffness: 500, damping: 30, delay: 0.1 + i * 0.02 }}
                        >
                          <Badge variant="outline" className={`text-[10px] ${riskColor[a.risk_label] ?? ""}`}>
                            {a.risk_label}
                          </Badge>
                        </motion.div>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {sources.map((s) => (
                          <Badge key={s} variant="secondary" className="text-[10px] py-0">
                            {s}
                          </Badge>
                        ))}
                      </div>
                      {a.ti_summary && (
                        <p className="text-xs text-muted-foreground truncate">{a.ti_summary}</p>
                      )}
                    </div>

                    <div className="shrink-0 text-right">
                      <div className="flex items-center gap-1 text-xs font-mono text-muted-foreground">
                        <Clock className="h-3 w-3" />
                        {new Date(a.alerted_at).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}
                      </div>
                    </div>
                  </motion.button>
                );
              })}
            </div>
          </ScrollArea>
        </Card>
      </motion.div>

      <AnimatePresence>
        {selected && (
          <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
            <DialogContent className="sm:max-w-lg">
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <ShieldAlert className="h-5 w-5 text-destructive" />
                  Detalhes do Alerta
                </DialogTitle>
              </DialogHeader>
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3 }}
                className="space-y-4"
              >
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <p className="text-muted-foreground text-xs">ASN</p>
                    <p className="font-mono font-semibold">{selected.asn}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground text-xs">Risco</p>
                    <p className="font-semibold">
                      {Math.round(selected.risk_score * 100)}%{" "}
                      <Badge variant="outline" className={`text-[10px] ${riskColor[selected.risk_label] ?? ""}`}>
                        {selected.risk_label}
                      </Badge>
                    </p>
                  </div>
                  <div className="col-span-2">
                    <p className="text-muted-foreground text-xs mb-1">Fontes ativas</p>
                    <div className="flex flex-wrap gap-1">
                      {activeSources(selected.sources).map((s) => (
                        <Badge key={s} variant="secondary" className="text-xs">
                          {s}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div className="col-span-2">
                    <p className="text-muted-foreground text-xs">Threat Intelligence</p>
                    <p className="text-sm">{selected.ti_summary || "Sem dados de TI"}</p>
                  </div>
                  <div className="col-span-2">
                    <p className="text-muted-foreground text-xs">Data/Hora</p>
                    <p className="text-sm font-mono">
                      {new Date(selected.alerted_at).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}
                    </p>
                  </div>
                </div>
              </motion.div>
            </DialogContent>
          </Dialog>
        )}
      </AnimatePresence>
    </>
  );
}
