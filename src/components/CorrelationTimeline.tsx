import { useEffect, useMemo, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card } from "@/components/ui/card";
import { ShieldAlert, Radio } from "lucide-react";
import { IncidentReport } from "@/components/IncidentReport";

const OWN_ASNS = [
  { asn: "AS267458", name: "K2 Network" },
  { asn: "AS266953", name: "Argo Telecom" },
];

const COMPETITOR_ASN_LIST = [
  { asn: "AS268538", name: "Conecta Network" },
  { asn: "AS267530", name: "TJ Telecom" },
  { asn: "AS268726", name: "TOPNET" },
];

const WINDOW_HOURS = 7 * 24;

interface OwnEpisode {
  asn: string;
  start_time: string;
  end_time: string;
  peak_bps: number | null;
  peak_pps: number | null;
  sample_count: number;
  correlated: boolean;
  correlated_with: string[];
}

interface CompetitorIncident {
  asn: string;
  created_at: string;
  status: string;
}

function pct(date: Date, domainStart: Date, domainEnd: Date): number {
  const total = domainEnd.getTime() - domainStart.getTime();
  const offset = date.getTime() - domainStart.getTime();
  return Math.min(100, Math.max(0, (offset / total) * 100));
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
  return `${Math.round(mins / 60)}h${mins % 60 ? (mins % 60) + "min" : ""}`;
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function CorrelationTimeline() {
  const [episodes, setEpisodes] = useState<OwnEpisode[]>([]);
  const [competitorIncidents, setCompetitorIncidents] = useState<CompetitorIncident[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEpisode, setSelectedEpisode] = useState<OwnEpisode | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      const since = new Date(Date.now() - WINDOW_HOURS * 60 * 60 * 1000).toISOString();

      const [episodesRes, competitorsRes] = await Promise.all([
        supabase
          .from("v_incident_correlation")
          .select("asn,start_time,end_time,peak_bps,peak_pps,sample_count,correlated,correlated_with")
          .gte("start_time", since)
          .order("start_time", { ascending: false }),
        supabase
          .from("asn_incidents")
          .select("asn,created_at,status")
          .in("asn", COMPETITOR_ASN_LIST.map((c) => c.asn))
          .gte("created_at", since)
          .order("created_at", { ascending: false }),
      ]);

      if (cancelled) return;
      if (!episodesRes.error) setEpisodes((episodesRes.data as OwnEpisode[]) || []);
      if (!competitorsRes.error) setCompetitorIncidents((competitorsRes.data as CompetitorIncident[]) || []);
      setLoading(false);
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const domainEnd = useMemo(() => new Date(), []);
  const domainStart = useMemo(() => new Date(domainEnd.getTime() - WINDOW_HOURS * 60 * 60 * 1000), [domainEnd]);

  const isolatedCount = episodes.filter((e) => !e.correlated).length;
  const correlatedCount = episodes.filter((e) => e.correlated).length;

  const lastCompetitorSignal = useMemo(() => {
    const map: Record<string, string | null> = {};
    for (const c of COMPETITOR_ASN_LIST) map[c.asn] = null;
    for (const inc of competitorIncidents) {
      if (!map[inc.asn]) map[inc.asn] = inc.created_at;
    }
    return map;
  }, [competitorIncidents]);

  if (loading) {
    return (
      <Card className="p-6">
        <p className="text-sm text-muted-foreground animate-pulse">Carregando linha do tempo de correlação...</p>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <Card className="p-4 space-y-1">
          <p className="text-[11px] uppercase tracking-wider text-muted-foreground">Ataques isolados (7d)</p>
          <p className="text-2xl font-bold text-neon-red font-mono">{isolatedCount}</p>
          <p className="text-xs text-muted-foreground">só K2/Argo — possível alvo direto</p>
        </Card>
        <Card className="p-4 space-y-1">
          <p className="text-[11px] uppercase tracking-wider text-muted-foreground">Eventos correlacionados (7d)</p>
          <p className="text-2xl font-bold text-neon-yellow font-mono">{correlatedCount}</p>
          <p className="text-xs text-muted-foreground">2+ concorrentes também afetados</p>
        </Card>
        <Card className="p-4 space-y-1">
          <p className="text-[11px] uppercase tracking-wider text-muted-foreground">Concorrentes monitorados</p>
          <p className="text-2xl font-bold font-mono">{COMPETITOR_ASN_LIST.length}</p>
          <p className="text-xs text-muted-foreground">só sinal externo (BGP)</p>
        </Card>
      </div>

      <Card className="p-5 space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-foreground">Linha do tempo de correlação</h3>
          <p className="text-xs text-muted-foreground mt-1">
            Cada barra é um episódio confirmado pelo Wanguard (ASNs próprios) ou incidente BGP (concorrentes).
            A cor vermelha marca ataque isolado; amarela, correlacionado com 2+ concorrentes na mesma janela.
          </p>
        </div>

        <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5"><span className="w-3 h-2 rounded-sm bg-neon-red inline-block" />Isolado</span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-2 rounded-sm bg-neon-yellow inline-block" />Correlacionado</span>
          <span className="flex items-center gap-1.5"><span className="w-3 h-2 rounded-sm bg-neon-cyan/70 inline-block" />Concorrente afetado</span>
        </div>

        <div className="space-y-1">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground border-b border-border pb-1">ASNs próprios — ground truth Wanguard</p>
          {OWN_ASNS.map((own) => {
            const rowEpisodes = episodes.filter((e) => e.asn === own.asn);
            return (
              <div key={own.asn} className="grid grid-cols-[130px_1fr] items-center gap-3 min-h-[30px] border-t border-border/50 first:border-t-0 py-1">
                <div className="text-xs">
                  <div className="font-mono font-semibold">{own.asn}</div>
                  <div className="text-muted-foreground text-[10px]">{own.name}</div>
                </div>
                <div className="relative h-5 bg-muted/40 rounded">
                  {rowEpisodes.map((e, i) => {
                    const left = pct(new Date(e.start_time), domainStart, domainEnd);
                    const right = pct(new Date(e.end_time), domainStart, domainEnd);
                    const width = Math.max(right - left, 0.3);
                    return (
                      <button
                        key={i}
                        type="button"
                        onClick={() => setSelectedEpisode(e)}
                        title={`${formatTime(e.start_time)} · ${formatMbps(e.peak_bps)} · ${e.correlated ? "correlacionado" : "isolado"}`}
                        className={`absolute top-0 h-full rounded-sm cursor-pointer hover:brightness-125 ${e.correlated ? "bg-neon-yellow" : "bg-neon-red"}`}
                        style={{ left: `${left}%`, width: `${width}%` }}
                      />
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>

        <div className="space-y-1">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground border-b border-border pb-1">Concorrentes — sinal externo (BGP)</p>
          {COMPETITOR_ASN_LIST.map((comp) => {
            const rowIncidents = competitorIncidents.filter((c) => c.asn === comp.asn);
            return (
              <div key={comp.asn} className="grid grid-cols-[130px_1fr] items-center gap-3 min-h-[30px] border-t border-border/50 first:border-t-0 py-1">
                <div className="text-xs">
                  <div className="font-mono font-semibold">{comp.asn}</div>
                  <div className="text-muted-foreground text-[10px]">{comp.name}</div>
                </div>
                <div className="relative h-5 bg-muted/40 rounded">
                  {rowIncidents.map((inc, i) => {
                    const left = pct(new Date(inc.created_at), domainStart, domainEnd);
                    return (
                      <div
                        key={i}
                        title={`${formatTime(inc.created_at)} · ${inc.status}`}
                        className="absolute top-0 h-full w-[3px] rounded-sm bg-neon-cyan/70"
                        style={{ left: `${left}%` }}
                      />
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>

        <div className="grid grid-cols-[130px_1fr] text-[10px] text-muted-foreground font-mono">
          <div />
          <div className="flex justify-between px-0.5">
            <span>{formatTime(domainStart.toISOString())}</span>
            <span>agora</span>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-[1.3fr_1fr] gap-4">
        <Card className="p-5">
          <h3 className="text-sm font-semibold text-foreground mb-1">Incidentes recentes</h3>
          <p className="text-xs text-muted-foreground mb-3">Classificados automaticamente por correlação temporal</p>
          {episodes.length === 0 ? (
            <p className="text-sm text-muted-foreground py-6 text-center">Nenhum ataque confirmado nos últimos 7 dias.</p>
          ) : (
            <div className="divide-y divide-border">
              {episodes.slice(0, 12).map((e, i) => {
                const own = OWN_ASNS.find((o) => o.asn === e.asn);
                return (
                  <button
                    key={i}
                    type="button"
                    onClick={() => setSelectedEpisode(e)}
                    className="w-full text-left py-2.5 flex items-center gap-3 hover:bg-muted/40 rounded-lg px-2 -mx-2 transition-colors"
                  >

                    <span
                      className={`text-[10px] font-semibold px-2 py-0.5 rounded-full whitespace-nowrap ${
                        e.correlated
                          ? "bg-neon-yellow/10 text-neon-yellow border border-neon-yellow/30"
                          : "bg-neon-red/10 text-neon-red border border-neon-red/30"
                      }`}
                    >
                      {e.correlated ? "Correlacionado" : "Isolado"}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-mono font-semibold">{e.asn} · {own?.name}</p>
                      <p className="text-xs text-muted-foreground truncate">
                        Pico {formatMbps(e.peak_bps)}, {formatDuration(e.start_time, e.end_time)}
                        {e.correlated && e.correlated_with.length > 0 && ` — junto com ${e.correlated_with.join(", ")}`}
                      </p>
                    </div>
                    <span className="text-[10px] text-muted-foreground font-mono whitespace-nowrap">{formatTime(e.start_time)}</span>
                  </button>
                );
              })}
            </div>
          )}
        </Card>

        <Card className="p-5">
          <h3 className="text-sm font-semibold text-foreground mb-1">Concorrentes agora</h3>
          <p className="text-xs text-muted-foreground mb-3">Apenas sinal externo — sem visibilidade interna</p>
          <div className="space-y-2">
            {COMPETITOR_ASN_LIST.map((comp) => {
              const last = lastCompetitorSignal[comp.asn];
              const recentlyActive = last && Date.now() - new Date(last).getTime() < 60 * 60 * 1000;
              return (
                <div key={comp.asn} className="flex items-center justify-between px-3 py-2.5 bg-muted/40 rounded-lg">
                  <div>
                    <p className="text-xs font-mono font-semibold">{comp.asn}</p>
                    <p className="text-[10px] text-muted-foreground">{comp.name}</p>
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                    {recentlyActive ? (
                      <>
                        <ShieldAlert className="h-3 w-3 text-neon-yellow" />
                        <span>Sinal recente</span>
                      </>
                    ) : last ? (
                      <>
                        <Radio className="h-3 w-3" />
                        <span>Última: {formatTime(last)}</span>
                      </>
                    ) : (
                      <>
                        <Radio className="h-3 w-3 text-neon-green" />
                        <span>Estável</span>
                      </>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      </div>

      <IncidentReport episode={selectedEpisode} onClose={() => setSelectedEpisode(null)} />
    </div>
  );
}
