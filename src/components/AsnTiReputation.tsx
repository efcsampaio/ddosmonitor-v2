import { useState, useEffect } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Loader2, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import { cn } from "@/lib/utils";

interface TiRow {
  asn: string;
  asn_name: string;
  first_window: string;
  last_window: string;
  ips_total_amostrados: number;
  ips_com_score: number;
  avg_score_medio: number;
  gn_noise_ratio_avg: number;
  gn_malicious_ratio_avg: number;
  gn_riot_ratio_avg: number;
}

interface WindowDetail {
  asn: string;
  window_start: string;
  window_end: string;
  ips_total: number;
  ips_with_score: number;
  high_score_ips: number;
  avg_score: number | null;
  gn_noise_ratio: number;
  gn_malicious_ratio: number;
  gn_riot_ratio: number;
}

function getReputationBadge(score: number) {
  if (score >= 50) {
    return (
      <Badge variant="destructive" className="gap-1 text-[10px]">
        <ShieldAlert className="h-3 w-3" /> ALTA
      </Badge>
    );
  }
  if (score >= 10) {
    return (
      <Badge className="gap-1 text-[10px] bg-orange-500/20 text-orange-400 border-orange-500/30 hover:bg-orange-500/30">
        <ShieldQuestion className="h-3 w-3" /> MODERADA
      </Badge>
    );
  }
  return (
    <Badge className="gap-1 text-[10px] bg-emerald-500/20 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/30">
      <ShieldCheck className="h-3 w-3" /> BAIXA
    </Badge>
  );
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString("pt-BR", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function AsnTiReputation() {
  const [data, setData] = useState<TiRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedAsn, setSelectedAsn] = useState<string | null>(null);
  const [windowDetails, setWindowDetails] = useState<WindowDetail[]>([]);
  const [loadingDetails, setLoadingDetails] = useState(false);

  useEffect(() => {
    fetchRanking();
  }, []);

  async function fetchRanking() {
    setLoading(true);

    const [windowsResult, namesResult] = await Promise.all([
      supabase
        .from("asn_ip_reputation_window")
        .select("asn, window_start, window_end, ips_total, ips_with_score, avg_score, gn_noise_ratio, gn_malicious_ratio, gn_riot_ratio")
        .eq("source", "abuseipdb")
        .gt("ips_with_score", 0)
        .gt("avg_score", 0)
        .gte("window_start", new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()),
      supabase
        .from("monitored_asns")
        .select("asn, name"),
    ]);

    const rows = windowsResult.data;
    const asnNames = namesResult.data;

    if (!rows) { setData([]); setLoading(false); return; }

    const nameMap: Record<string, string> = {};
    for (const a of (asnNames || [])) { if (a.name) nameMap[a.asn] = a.name; }

    const map = new Map<string, {
      totalIps: number; comScore: number; sumAvg: number; count: number;
      firstW: string; lastW: string;
      sumGnNoise: number; sumGnMalicious: number; sumGnRiot: number;
    }>();

    for (const r of rows) {
      const existing = map.get(r.asn);
      if (!existing) {
        map.set(r.asn, {
          totalIps: r.ips_total, comScore: r.ips_with_score,
          sumAvg: Number(r.avg_score ?? 0), count: 1,
          firstW: r.window_start, lastW: r.window_end,
          sumGnNoise: Number(r.gn_noise_ratio ?? 0),
          sumGnMalicious: Number(r.gn_malicious_ratio ?? 0),
          sumGnRiot: Number(r.gn_riot_ratio ?? 0),
        });
      } else {
        existing.totalIps += r.ips_total;
        existing.comScore += r.ips_with_score;
        existing.sumAvg += Number(r.avg_score ?? 0);
        existing.count++;
        existing.sumGnNoise += Number(r.gn_noise_ratio ?? 0);
        existing.sumGnMalicious += Number(r.gn_malicious_ratio ?? 0);
        existing.sumGnRiot += Number(r.gn_riot_ratio ?? 0);
        if (r.window_start < existing.firstW) existing.firstW = r.window_start;
        if (r.window_end > existing.lastW) existing.lastW = r.window_end;
      }
    }

    const result: TiRow[] = Array.from(map.entries())
      .map(([asn, v]) => ({
        asn,
        asn_name: nameMap[asn] || "",
        first_window: v.firstW,
        last_window: v.lastW,
        ips_total_amostrados: v.totalIps,
        ips_com_score: v.comScore,
        avg_score_medio: Math.round((v.sumAvg / v.count) * 100) / 100,
        gn_noise_ratio_avg: Math.round((v.sumGnNoise / v.count) * 1000) / 1000,
        gn_malicious_ratio_avg: Math.round((v.sumGnMalicious / v.count) * 1000) / 1000,
        gn_riot_ratio_avg: Math.round((v.sumGnRiot / v.count) * 1000) / 1000,
      }))
      .sort((a, b) => b.avg_score_medio - a.avg_score_medio);

    setData(result);
    setLoading(false);
  }

  async function openDetails(asn: string) {
    setSelectedAsn(asn);
    setLoadingDetails(true);
    const { data: rows } = await supabase
      .from("asn_ip_reputation_window")
      .select("*")
      .eq("asn", asn)
      .eq("source", "abuseipdb")
      .gte("window_start", new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString())
      .order("window_start", { ascending: false });

    setWindowDetails((rows as WindowDetail[]) ?? []);
    setLoadingDetails(false);
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        <span className="ml-2 text-muted-foreground text-sm">Carregando reputação TI...</span>
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground text-sm">
        Nenhum dado de reputação TI nos últimos 7 dias.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        Ranking de ASNs por reputação AbuseIPDB + GreyNoise (últimos 7 dias). Clique em um ASN para detalhes por janela.
      </p>

      <div className="rounded-lg border border-border overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="bg-muted/50">
              <TableHead className="text-xs">ASN</TableHead>
              <TableHead className="text-xs text-center">Score Médio</TableHead>
              <TableHead className="text-xs text-center">Nível</TableHead>
              <TableHead className="text-xs text-center">IPs Amostrados</TableHead>
              <TableHead className="text-xs text-center">GreyNoise</TableHead>
              <TableHead className="text-xs">Período</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.map((row) => (
              <TableRow
                key={row.asn}
                className={cn(
                  "cursor-pointer transition-colors hover:bg-muted/30",
                  row.avg_score_medio >= 50 && "bg-destructive/5"
                )}
                onClick={() => openDetails(row.asn)}
              >
                <TableCell className="font-mono text-sm font-medium text-foreground">
                  <div>{row.asn}</div>
                  {row.asn_name && (
                    <div className="text-[10px] text-muted-foreground font-sans">{row.asn_name}</div>
                  )}
                </TableCell>
                <TableCell className="text-center font-mono text-sm">
                  {row.avg_score_medio}
                </TableCell>
                <TableCell className="text-center">
                  {getReputationBadge(row.avg_score_medio)}
                </TableCell>
                <TableCell className="text-center text-sm text-muted-foreground">
                  {row.ips_total_amostrados}
                </TableCell>
                <TableCell className="text-center">
                  <div className="flex flex-wrap gap-1 justify-center">
                    {row.gn_malicious_ratio_avg >= 0.3 && (
                      <Badge variant="destructive" className="text-[9px] px-1.5">GN: Malicioso</Badge>
                    )}
                    {row.gn_noise_ratio_avg >= 0.5 && (
                      <Badge className="text-[9px] px-1.5 bg-muted text-muted-foreground border-border">GN: Scanner</Badge>
                    )}
                    {row.gn_riot_ratio_avg >= 0.5 && (
                      <Badge className="text-[9px] px-1.5 bg-emerald-500/20 text-emerald-400 border-emerald-500/30">GN: Legítimo</Badge>
                    )}
                    {row.gn_malicious_ratio_avg < 0.3 && row.gn_noise_ratio_avg < 0.5 && row.gn_riot_ratio_avg < 0.5 && (
                      <span className="text-[10px] text-muted-foreground">—</span>
                    )}
                  </div>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                  {formatDate(row.first_window)} → {formatDate(row.last_window)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Detail dialog */}
      <Dialog open={!!selectedAsn} onOpenChange={(open) => !open && setSelectedAsn(null)}>
        <DialogContent className="sm:max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="font-mono">{selectedAsn} — Janelas de Reputação TI</DialogTitle>
          </DialogHeader>
          {loadingDetails ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : windowDetails.length === 0 ? (
            <p className="text-muted-foreground text-sm text-center py-4">Nenhuma janela encontrada.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/50">
                  <TableHead className="text-xs">Início</TableHead>
                  <TableHead className="text-xs">Fim</TableHead>
                  <TableHead className="text-xs text-center">IPs Total</TableHead>
                  <TableHead className="text-xs text-center">Avg Score</TableHead>
                  <TableHead className="text-xs text-center">GN Malicioso</TableHead>
                  <TableHead className="text-xs text-center">GN Scanner</TableHead>
                  <TableHead className="text-xs text-center">GN Legítimo</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {windowDetails.map((w, i) => {
                  const gnMalicious = Number(w.gn_malicious_ratio ?? 0);
                  const gnNoise = Number(w.gn_noise_ratio ?? 0);
                  const gnRiot = Number(w.gn_riot_ratio ?? 0);
                  return (
                    <TableRow key={i}>
                      <TableCell className="text-xs whitespace-nowrap">{formatDate(w.window_start)}</TableCell>
                      <TableCell className="text-xs whitespace-nowrap">{formatDate(w.window_end)}</TableCell>
                      <TableCell className="text-center text-sm">{w.ips_total}</TableCell>
                      <TableCell className="text-center text-sm font-mono">{w.avg_score ?? "—"}</TableCell>
                      <TableCell className="text-center text-sm">
                        {gnMalicious > 0 ? (
                          <span className={gnMalicious >= 0.3 ? "text-destructive font-semibold" : "text-orange-400"}>
                            {(gnMalicious * 100).toFixed(1)}%
                          </span>
                        ) : "—"}
                      </TableCell>
                      <TableCell className="text-center text-sm">
                        {gnNoise > 0 ? `${(gnNoise * 100).toFixed(1)}%` : "—"}
                      </TableCell>
                      <TableCell className="text-center text-sm">
                        {gnRiot > 0 ? (
                          <span className={gnRiot >= 0.5 ? "text-emerald-400" : ""}>
                            {(gnRiot * 100).toFixed(1)}%
                          </span>
                        ) : "—"}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
