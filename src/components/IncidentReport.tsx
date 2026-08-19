import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";

interface Episode {
  asn: string;
  start_time: string;
  end_time: string;
  peak_bps: number | null;
  peak_pps: number | null;
  sample_count: number;
  correlated: boolean;
  correlated_with: string[];
}

const ASN_NAMES: Record<string, string> = {
  AS267458: "K2 Network",
  AS266953: "Argo Telecom",
};

interface SampleRow {
  timestamp: string;
  wanguard_max_bps_30m: number | null;
  wanguard_is_under_attack: boolean;
}

interface SignalRow {
  created_at: string;
  status: string;
  signals: string[];
}

function formatMbps(bps: number | null): string {
  if (bps == null) return "—";
  const mbps = bps / 1e6;
  if (mbps >= 1000) return `${(mbps / 1000).toFixed(1)} Gbps`;
  return `${Math.round(mbps)} Mbps`;
}

function formatDuration(startIso: string, endIso: string): string {
  const mins = Math.round((new Date(endIso).getTime() - new Date(startIso).getTime()) / 60000) + 5;
  if (mins < 60) return `${mins} min`;
  return `${Math.floor(mins / 60)}h${mins % 60 ? (mins % 60) + "min" : ""}`;
}

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function IncidentReport({ episode, onClose }: { episode: Episode | null; onClose: () => void }) {
  const [samples, setSamples] = useState<SampleRow[]>([]);
  const [signals, setSignals] = useState<SignalRow[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!episode) return;
    let cancelled = false;
    async function load() {
      setLoading(true);
      const start = new Date(new Date(episode!.start_time).getTime() - 15 * 60000).toISOString();
      const end = new Date(new Date(episode!.end_time).getTime() + 15 * 60000).toISOString();

      const [samplesRes, signalsRes] = await Promise.all([
        supabase
          .from("as_attack_samples")
          .select("timestamp,wanguard_max_bps_30m,wanguard_is_under_attack")
          .eq("asn", episode!.asn)
          .gte("timestamp", start)
          .lte("timestamp", end)
          .order("timestamp", { ascending: true }),
        supabase
          .from("asn_incidents")
          .select("created_at,status,signals")
          .eq("asn", episode!.asn)
          .gte("created_at", start)
          .lte("created_at", end)
          .order("created_at", { ascending: false })
          .limit(10),
      ]);

      if (cancelled) return;
      if (!samplesRes.error) setSamples((samplesRes.data as SampleRow[]) || []);
      if (!signalsRes.error) setSignals((signalsRes.data as SignalRow[]) || []);
      setLoading(false);
    }
    load();
    return () => { cancelled = true; };
  }, [episode]);

  const open = episode != null;
  const maxBps = Math.max(1, ...samples.map((s) => s.wanguard_max_bps_30m || 0));

  return (
    <Sheet open={open} onOpenChange={(v) => !v && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-xl overflow-y-auto">
        {episode && (
          <>
            <SheetHeader className="text-left">
              <p className="text-xs font-mono text-muted-foreground">{episode.asn} · {ASN_NAMES[episode.asn]}</p>
              <SheetTitle>Ataque — {formatDateTime(episode.start_time)}</SheetTitle>
              <div className="flex flex-wrap gap-2 pt-1">
                <span
                  className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                    episode.correlated
                      ? "bg-neon-yellow/10 text-neon-yellow border-neon-yellow/30"
                      : "bg-neon-red/10 text-neon-red border-neon-red/30"
                  }`}
                >
                  {episode.correlated ? "Correlacionado" : "Isolado"}
                </span>
                <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-muted text-muted-foreground">
                  Pico {formatMbps(episode.peak_bps)}
                </span>
                <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-muted text-muted-foreground">
                  {formatDuration(episode.start_time, episode.end_time)}
                </span>
              </div>
            </SheetHeader>

            <div className="mt-6 space-y-6">
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-muted/40 rounded-lg p-3">
                  <p className="text-[10px] text-muted-foreground uppercase">Pico de banda</p>
                  <p className="text-sm font-mono font-semibold">{formatMbps(episode.peak_bps)}</p>
                </div>
                <div className="bg-muted/40 rounded-lg p-3">
                  <p className="text-[10px] text-muted-foreground uppercase">Pico de pacotes</p>
                  <p className="text-sm font-mono font-semibold">
                    {episode.peak_pps ? `${Math.round(episode.peak_pps / 1000)} Kpps` : "—"}
                  </p>
                </div>
                <div className="bg-muted/40 rounded-lg p-3">
                  <p className="text-[10px] text-muted-foreground uppercase">Amostras</p>
                  <p className="text-sm font-mono font-semibold">{episode.sample_count}</p>
                </div>
              </div>

              <div>
                <h4 className="text-xs font-semibold text-foreground mb-2">Volume de tráfego</h4>
                {loading ? (
                  <p className="text-xs text-muted-foreground animate-pulse">Carregando...</p>
                ) : (
                  <div className="relative h-32 bg-muted/30 rounded-lg flex items-end gap-[1px] p-2">
                    {samples.map((s, i) => {
                      const h = Math.max(2, ((s.wanguard_max_bps_30m || 0) / maxBps) * 100);
                      return (
                        <div
                          key={i}
                          title={`${formatDateTime(s.timestamp)}: ${formatMbps(s.wanguard_max_bps_30m)}`}
                          className={`flex-1 rounded-t-sm ${s.wanguard_is_under_attack ? "bg-neon-red" : "bg-muted-foreground/30"}`}
                          style={{ height: `${h}%` }}
                        />
                      );
                    })}
                  </div>
                )}
              </div>

              <div>
                <h4 className="text-xs font-semibold text-foreground mb-2">Correlação com concorrentes</h4>
                {episode.correlated ? (
                  <div className="bg-neon-yellow/10 border border-neon-yellow/30 rounded-lg p-3 text-xs text-muted-foreground">
                    <b className="text-neon-yellow">Correlacionado.</b> {episode.correlated_with.join(", ")} também apresentaram
                    instabilidade na mesma janela — padrão consistente com evento regional, não direcionado.
                  </div>
                ) : (
                  <div className="bg-neon-red/10 border border-neon-red/30 rounded-lg p-3 text-xs text-muted-foreground">
                    <b className="text-neon-red">Isolado.</b> Nenhum concorrente apresentou instabilidade nesse horário —
                    consistente com um ataque direcionado a {episode.asn}.
                  </div>
                )}
              </div>

              <div>
                <h4 className="text-xs font-semibold text-foreground mb-2">Sinais BGP no período</h4>
                {signals.length === 0 ? (
                  <p className="text-xs text-muted-foreground">Nenhum sinal BGP registrado nessa janela.</p>
                ) : (
                  <div className="space-y-2">
                    {signals.map((s, i) => (
                      <div key={i} className="text-xs bg-muted/30 rounded-lg p-2.5">
                        <p className="font-mono text-muted-foreground text-[10px] mb-1">{formatDateTime(s.created_at)} · {s.status}</p>
                        <ul className="space-y-0.5">
                          {s.signals.slice(0, 4).map((sig, j) => (
                            <li key={j} className="text-muted-foreground">{sig}</li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
