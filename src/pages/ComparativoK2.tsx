import { useState, useMemo } from "react";
import { DashboardHeader } from "@/components/DashboardHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { CalendarIcon, RefreshCw, Download, CheckCircle2, AlertTriangle, XCircle, Wifi, WifiOff, Database, ChevronDown, BarChart2 } from "lucide-react";
import { format } from "date-fns";
import { toast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useWanguardAnomalies, useWanguardStatus, type WanguardEvent } from "@/hooks/useWanguard";
import { fetchExternalAnomalies, type ExternalAnomaly } from "@/services/wanguardService";
import { correlateEvents, getCorrelationSummary, exportCorrelationCSV, type CorrelationResult } from "@/utils/correlateEvents";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, ReferenceLine } from "recharts";
import { ExternalCoverageCard } from "@/components/ExternalCoverageCard";

type SortDir = "asc" | "desc";

function formatBps(bps: number) {
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(1)} Gbps`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(0)} Mbps`;
  return `${(bps / 1e3).toFixed(0)} Kbps`;
}

function formatPps(pps: number) {
  if (pps >= 1e6) return `${(pps / 1e6).toFixed(1)}M pps`;
  if (pps >= 1e3) return `${(pps / 1e3).toFixed(0)}K pps`;
  return `${pps} pps`;
}

function SortableHeader({ label, active, dir, onClick }: { label: string; active: boolean; dir: SortDir; onClick: () => void }) {
  return (
    <TableHead className="cursor-pointer select-none hover:text-foreground transition-colors" onClick={onClick}>
      <span className="flex items-center gap-1">
        {label}
        {active && <span className="text-xs">{dir === "asc" ? "▲" : "▼"}</span>}
      </span>
    </TableHead>
  );
}

const ITEMS_PER_PAGE = 20;

export default function ComparativoK2() {
  const [startDate, setStartDate] = useState<Date>(() => {
    const d = new Date(); d.setDate(d.getDate() - 7); return d;
  });
  const [endDate, setEndDate] = useState<Date>(new Date());
  const [refreshKey, setRefreshKey] = useState(0);

  // Wanguard table sort/page
  const [wgSort, setWgSort] = useState<{ col: keyof WanguardEvent; dir: SortDir }>({ col: "timestamp", dir: "desc" });
  const [wgPage, setWgPage] = useState(0);

  // External table sort/page
  const [extSort, setExtSort] = useState<{ col: keyof ExternalAnomaly; dir: SortDir }>({ col: "timestamp", dir: "desc" });
  const [extPage, setExtPage] = useState(0);

  // Correlation page
  const [corrPage, setCorrPage] = useState(0);
  const [docsOpen, setDocsOpen] = useState(false);

  const { data: wanguardEvents, source: wanguardSource, apiError: wanguardApiError, isLoading: wgLoading, refetch: refetchWg } = useWanguardAnomalies(startDate, endDate, refreshKey);
  const { online: wanguardOnline } = useWanguardStatus();

  const { data: externalAnomalies = [], isLoading: extLoading } = useQuery({
    queryKey: ["external-anomalies", startDate.toISOString(), endDate.toISOString(), refreshKey],
    queryFn: () => fetchExternalAnomalies(startDate, endDate),
  });

  const correlationResults = useMemo(
    () => correlateEvents(wanguardEvents, externalAnomalies, 30),
    [wanguardEvents, externalAnomalies]
  );
  const summary = useMemo(() => getCorrelationSummary(correlationResults), [correlationResults]);

  // Sort helpers
  function sortedData<T>(data: T[], col: keyof T, dir: SortDir): T[] {
    return [...data].sort((a, b) => {
      const va = a[col], vb = b[col];
      if (va == null) return 1;
      if (vb == null) return -1;
      if (va < vb) return dir === "asc" ? -1 : 1;
      if (va > vb) return dir === "asc" ? 1 : -1;
      return 0;
    });
  }

  const sortedWg = sortedData(wanguardEvents, wgSort.col, wgSort.dir);
  const pagedWg = sortedWg.slice(wgPage * ITEMS_PER_PAGE, (wgPage + 1) * ITEMS_PER_PAGE);
  const wgTotalPages = Math.ceil(sortedWg.length / ITEMS_PER_PAGE);

  const sortedExt = sortedData(externalAnomalies, extSort.col, extSort.dir);
  const pagedExt = sortedExt.slice(extPage * ITEMS_PER_PAGE, (extPage + 1) * ITEMS_PER_PAGE);
  const extTotalPages = Math.ceil(sortedExt.length / ITEMS_PER_PAGE);

  const pagedCorr = correlationResults.slice(corrPage * ITEMS_PER_PAGE, (corrPage + 1) * ITEMS_PER_PAGE);
  const corrTotalPages = Math.ceil(correlationResults.length / ITEMS_PER_PAGE);

  // Timeline chart data
  const timelineData = useMemo(() => {
    const buckets = new Map<string, { hour: string; wanguard: number; external: number }>();
    const allEvents = [
      ...wanguardEvents.map((e) => ({ time: e.timestamp, type: "wanguard" as const })),
      ...externalAnomalies.map((e) => ({ time: e.timestamp, type: "external" as const })),
    ];
    allEvents.forEach(({ time, type }) => {
      const key = `${time.toLocaleDateString("pt-BR")} ${String(time.getHours()).padStart(2, "0")}h`;
      if (!buckets.has(key)) buckets.set(key, { hour: key, wanguard: 0, external: 0 });
      const b = buckets.get(key)!;
      if (type === "wanguard") b.wanguard++;
      else b.external++;
    });
    return Array.from(buckets.values()).sort((a, b) => a.hour.localeCompare(b.hour));
  }, [wanguardEvents, externalAnomalies]);

  function handleExportCSV() {
    const csv = exportCorrelationCSV(correlationResults);
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `correlacao_k2_${format(startDate, "yyyy-MM-dd")}_${format(endDate, "yyyy-MM-dd")}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function toggleWgSort(col: keyof WanguardEvent) {
    setWgSort((p) => ({ col, dir: p.col === col && p.dir === "desc" ? "asc" : "desc" }));
    setWgPage(0);
  }

  function toggleExtSort(col: keyof ExternalAnomaly) {
    setExtSort((p) => ({ col, dir: p.col === col && p.dir === "desc" ? "asc" : "desc" }));
    setExtPage(0);
  }

  const isLoading = wgLoading || extLoading;

  return (
    <div className="min-h-screen bg-background">
      <DashboardHeader />
      <main className="max-w-7xl mx-auto px-3 md:px-4 py-4 md:py-6 space-y-4 md:space-y-6">
        {/* Título */}
        <p className="text-sm text-muted-foreground">Comparativo K2 – AS267458</p>

        {/* Controls */}
        <Card>
          <CardContent className="py-4 flex flex-wrap items-center gap-3">
            <DatePicker label="Início" date={startDate} onSelect={(d) => d && setStartDate(d)} />
            <DatePicker label="Fim" date={endDate} onSelect={(d) => d && setEndDate(d)} />
            <Button size="sm" className="gap-1.5" onClick={() => setRefreshKey((k) => k + 1)} disabled={isLoading}>
              <RefreshCw className={cn("h-4 w-4", isLoading && "animate-spin")} /> Atualizar
            </Button>
            <div className="flex items-center gap-1.5 ml-auto">
              {wanguardOnline ? (
                <Badge className="gap-1 bg-emerald-600/20 text-emerald-400 border-emerald-500/30"><Wifi className="h-3 w-3" /> Wanguard Online</Badge>
              ) : (
                <Badge variant="destructive" className="gap-1"><WifiOff className="h-3 w-3" /> Wanguard Offline</Badge>
              )}
              {wanguardSource === "live" && (
                <Badge variant="outline" className="gap-1 text-[10px]">Dados reais</Badge>
              )}
              {wanguardSource === "error" && (
                <Badge variant="secondary" className="gap-1 text-[10px]">Erro</Badge>
              )}
              <Button size="sm" variant="outline" className="gap-1.5 text-xs" onClick={() => setDocsOpen(true)}>
                <BarChart2 className="h-3.5 w-3.5" /> Métricas do Aprendizado
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Two tables side by side */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {/* Wanguard Table */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold">Eventos Wanguard (AS267458)</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-auto max-h-[420px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <SortableHeader label="Data" active={wgSort.col === "date"} dir={wgSort.dir} onClick={() => toggleWgSort("date")} />
                      <SortableHeader label="Início" active={wgSort.col === "startTime"} dir={wgSort.dir} onClick={() => toggleWgSort("startTime")} />
                      <SortableHeader label="Fim" active={wgSort.col === "endTime"} dir={wgSort.dir} onClick={() => toggleWgSort("endTime")} />
                      <TableHead>Duração</TableHead>
                      <TableHead>Prefixo</TableHead>
                      <SortableHeader label="Tamanho" active={wgSort.col === "sizeBps"} dir={wgSort.dir} onClick={() => toggleWgSort("sizeBps")} />
                      <TableHead>Tipo</TableHead>
                      <SortableHeader label="Status" active={wgSort.col === "status"} dir={wgSort.dir} onClick={() => toggleWgSort("status")} />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {pagedWg.map((e) => (
                      <TableRow key={e.id} className={e.sizeBps >= 5e9 ? "bg-destructive/10" : ""}>
                        <TableCell className="text-xs">{e.date}</TableCell>
                        <TableCell className="text-xs font-mono">{e.startTime || "—"}</TableCell>
                        <TableCell className="text-xs font-mono">{e.status === "Ativo" ? <span className="text-destructive font-semibold">Em andamento</span> : (e.endTime || "—")}</TableCell>
                        <TableCell className="text-xs">{e.durationMinutes}min</TableCell>
                        <TableCell className="text-xs font-mono">{e.prefix}</TableCell>
                        <TableCell className="text-xs">
                          <span className="block">{formatBps(e.sizeBps)}</span>
                          <span className="text-muted-foreground">{formatPps(e.sizePps)}</span>
                        </TableCell>
                        <TableCell className="text-xs">{e.attackType}</TableCell>
                        <TableCell>
                          <Badge variant={e.status === "Ativo" ? "destructive" : e.status === "Mitigado" ? "secondary" : "outline"} className="text-[10px]">
                            {e.status}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                    {pagedWg.length === 0 && !wanguardApiError && (
                      <TableRow><TableCell colSpan={8} className="text-center text-muted-foreground py-8">Nenhum evento encontrado no período</TableCell></TableRow>
                    )}
                    {pagedWg.length === 0 && wanguardApiError && (
                      <TableRow><TableCell colSpan={8} className="text-center py-8 text-destructive">
                        Não foi possível carregar os dados do Wanguard. Tente novamente.
                      </TableCell></TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
              <Pagination page={wgPage} totalPages={wgTotalPages} onPageChange={setWgPage} />
            </CardContent>
          </Card>

          {/* External Anomalies Table */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold">Anomalias APIs Externas (AS267458)</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-auto max-h-[420px]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <SortableHeader label="Data" active={extSort.col === "date"} dir={extSort.dir} onClick={() => toggleExtSort("date")} />
                      <SortableHeader label="Hora" active={extSort.col === "time"} dir={extSort.dir} onClick={() => toggleExtSort("time")} />
                      <SortableHeader label="Fonte" active={extSort.col === "source"} dir={extSort.dir} onClick={() => toggleExtSort("source")} />
                      <TableHead>Tipo</TableHead>
                      <SortableHeader label="Severidade" active={extSort.col === "severity"} dir={extSort.dir} onClick={() => toggleExtSort("severity")} />
                      <TableHead>Prefixo</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {pagedExt.map((e) => (
                      <TableRow key={e.id} className={e.severity === "Alta" ? "bg-destructive/10" : ""}>
                        <TableCell className="text-xs">{e.date}</TableCell>
                        <TableCell className="text-xs font-mono">{e.time}</TableCell>
                        <TableCell className="text-xs">
                          <Badge variant="outline" className="text-[10px]">{e.source}</Badge>
                        </TableCell>
                        <TableCell className="text-xs">{e.anomalyType}</TableCell>
                        <TableCell>
                          <Badge variant={e.severity === "Alta" ? "destructive" : e.severity === "Média" ? "secondary" : "outline"} className="text-[10px]">
                            {e.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs font-mono">{e.prefix ?? "—"}</TableCell>
                      </TableRow>
                    ))}
                    {pagedExt.length === 0 && (
                      <TableRow><TableCell colSpan={6} className="text-center text-muted-foreground py-8">Nenhuma anomalia encontrada</TableCell></TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
              <Pagination page={extPage} totalPages={extTotalPages} onPageChange={setExtPage} />
            </CardContent>
          </Card>
        </div>

        {/* Correlation Table */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle className="text-sm font-semibold">Correlação entre Wanguard e APIs Externas</CardTitle>
              <Button size="sm" variant="outline" className="gap-1.5 text-xs" onClick={handleExportCSV}>
                <Download className="h-3.5 w-3.5" /> Exportar CSV
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Summary */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <SummaryBadge label="Total Wanguard" value={summary.total} />
              <SummaryBadge label="Correlacionados" value={`${summary.correlated} (${summary.correlatedPercent}%)`} color="text-emerald-400" />
              <SummaryBadge label="Parciais" value={`${summary.partial} (${summary.partialPercent}%)`} color="text-yellow-400" />
              <SummaryBadge label="Sem correlação" value={`${summary.noCorrelation} (${summary.noCorrelationPercent}%)`} color="text-destructive" />
            </div>

            <div className="overflow-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Data/Hora Wanguard</TableHead>
                    <TableHead>Prefixo</TableHead>
                    <TableHead>Tamanho</TableHead>
                    <TableHead>Anomalia Correlacionada</TableHead>
                    <TableHead>Janela (min)</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pagedCorr.map((r, i) => (
                    <TableRow key={i}>
                      <TableCell className="text-xs font-mono">{r.wanguardEvent.date} {r.wanguardEvent.startTime}</TableCell>
                      <TableCell className="text-xs font-mono">{r.wanguardEvent.prefix}</TableCell>
                      <TableCell className="text-xs">{formatBps(r.wanguardEvent.sizeBps)}</TableCell>
                      <TableCell className="text-xs">
                        {r.correlatedAnomalies.length > 0
                          ? r.correlatedAnomalies.map((a) => `${a.source}: ${a.anomalyType}`).join(", ")
                          : "—"}
                      </TableCell>
                      <TableCell className="text-xs font-mono">{r.timeDiffMinutes ?? "—"}</TableCell>
                      <TableCell>
                        {r.status === "correlacionado" && <Badge className="gap-1 bg-emerald-600/20 text-emerald-400 border-emerald-500/30 text-[10px]"><CheckCircle2 className="h-3 w-3" /> Correlacionado</Badge>}
                        {r.status === "parcial" && <Badge className="gap-1 bg-yellow-600/20 text-yellow-400 border-yellow-500/30 text-[10px]"><AlertTriangle className="h-3 w-3" /> Parcial</Badge>}
                        {r.status === "sem_correlacao" && <Badge variant="destructive" className="gap-1 text-[10px]"><XCircle className="h-3 w-3" /> Sem correlação</Badge>}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <Pagination page={corrPage} totalPages={corrTotalPages} onPageChange={setCorrPage} />
          </CardContent>
        </Card>

        {/* Timeline Chart */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Linha do Tempo</CardTitle>
          </CardHeader>
          <CardContent>
            {timelineData.length > 0 ? (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={timelineData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
                  <XAxis dataKey="hour" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} interval="preserveStartEnd" />
                  <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} allowDecimals={false} />
                  <Tooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Bar dataKey="wanguard" name="Wanguard" fill="hsl(var(--neon-red))" radius={[3, 3, 0, 0]} />
                  <Bar dataKey="external" name="APIs Externas" fill="hsl(var(--neon-yellow))" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-center text-muted-foreground py-8 text-sm">Nenhum dado para exibir no período selecionado</p>
            )}
          </CardContent>
        </Card>

        {/* Dataset Generation Panel */}
        <DatasetPanel />

        {/* External Coverage Metrics */}
        <ExternalCoverageCard asn="AS267458" />

        {/* Documentation Modal */}
        <DatasetDocsModal open={docsOpen} onOpenChange={setDocsOpen} />
      </main>
    </div>
  );
}

function DatasetPanel() {
  const [dsStart, setDsStart] = useState(() => {
    const d = new Date(); d.setDate(d.getDate() - 1); return format(d, "yyyy-MM-dd'T'HH:mm");
  });
  const [dsEnd, setDsEnd] = useState(() => format(new Date(), "yyyy-MM-dd'T'HH:mm"));
  const [step, setStep] = useState(5);
  const [window, setWindow] = useState(30);
  const [generating, setGenerating] = useState(false);

  async function handleGenerate() {
    setGenerating(true);
    try {
      const projectId = import.meta.env.VITE_SUPABASE_PROJECT_ID;
      const anonKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
      // Antes: usava a anon key como Authorization bearer — generate-dataset
      // agora exige sessão real de um usuário com role admin/moderator/
      // master_admin (ou a service role key). Manda o token da sessão atual.
      const { data: { session } } = await supabase.auth.getSession();
      if (!session?.access_token) throw new Error("Não autenticado");

      const res = await fetch(`https://${projectId}.supabase.co/functions/v1/generate-dataset`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session.access_token}`,
          apikey: anonKey,
        },
        body: JSON.stringify({
          asn: "AS267458",
          startDate: new Date(dsStart).toISOString(),
          endDate: new Date(dsEnd).toISOString(),
          stepMinutes: step,
          windowMinutes: window,
        }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || "Erro ao gerar dataset");
      toast({
        title: "Dataset gerado com sucesso",
        description: `${json.samplesCreated} amostras criadas (${json.wanguardAnomaliesFound} anomalias Wanguard encontradas).`,
      });
    } catch (e: any) {
      toast({
        title: "Erro ao gerar dataset",
        description: e.message,
        variant: "destructive",
      });
    } finally {
      setGenerating(false);
    }
  }

  return (
    <Collapsible>
      <Card>
        <CollapsibleTrigger asChild>
          <CardHeader className="pb-3 cursor-pointer hover:bg-secondary/30 transition-colors">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Database className="h-4 w-4" />
              Geração de Dataset (AS267458)
              <ChevronDown className="h-4 w-4 ml-auto" />
            </CardTitle>
          </CardHeader>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent className="space-y-4">
            <p className="text-xs text-muted-foreground">
              Gera amostras de treino cruzando dados Wanguard (labels) com anomalias externas (features).
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="space-y-1">
                <Label className="text-xs">Data/hora início</Label>
                <Input type="datetime-local" value={dsStart} onChange={(e) => setDsStart(e.target.value)} className="text-xs" />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Data/hora fim</Label>
                <Input type="datetime-local" value={dsEnd} onChange={(e) => setDsEnd(e.target.value)} className="text-xs" />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Step (min)</Label>
                <Input type="number" min={1} max={60} value={step} onChange={(e) => setStep(Number(e.target.value))} className="text-xs" />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Janela (min)</Label>
                <Input type="number" min={5} max={120} value={window} onChange={(e) => setWindow(Number(e.target.value))} className="text-xs" />
              </div>
            </div>
            <Button size="sm" className="gap-1.5" onClick={handleGenerate} disabled={generating}>
              <Database className="h-4 w-4" />
              {generating ? "Gerando..." : "Gerar dataset"}
            </Button>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}

// Sub-components
function DatePicker({ label, date, onSelect }: { label: string; date: Date; onSelect: (d: Date | undefined) => void }) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="gap-1.5 text-xs min-w-[150px] justify-start">
          <CalendarIcon className="h-3.5 w-3.5" />
          {label}: {format(date, "dd/MM/yyyy")}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-auto p-0" align="start">
        <Calendar mode="single" selected={date} onSelect={onSelect} initialFocus className="p-3 pointer-events-auto" />
      </PopoverContent>
    </Popover>
  );
}

function Pagination({ page, totalPages, onPageChange }: { page: number; totalPages: number; onPageChange: (p: number) => void }) {
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-between px-4 py-2 border-t border-border">
      <Button size="sm" variant="ghost" className="text-xs" disabled={page === 0} onClick={() => onPageChange(page - 1)}>
        ← Anterior
      </Button>
      <span className="text-xs text-muted-foreground">{page + 1} / {totalPages}</span>
      <Button size="sm" variant="ghost" className="text-xs" disabled={page >= totalPages - 1} onClick={() => onPageChange(page + 1)}>
        Próxima →
      </Button>
    </div>
  );
}

function SummaryBadge({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="bg-secondary/50 rounded-lg px-3 py-2 text-center">
      <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</p>
      <p className={cn("text-lg font-bold", color || "text-foreground")}>{value}</p>
    </div>
  );
}

function DatasetDocsModal({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const { data: metrics } = useQuery({
    queryKey: ["coverage-metrics-docs", "AS267458"],
    queryFn: async () => {
      const projectId = import.meta.env.VITE_SUPABASE_PROJECT_ID;
      const anonKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
      // Antes: usava a anon key como Authorization bearer — learning-metrics
      // agora exige sessão real de usuário.
      const { data: { session } } = await supabase.auth.getSession();
      if (!session?.access_token) throw new Error("Não autenticado");
      const res = await fetch(
        `https://${projectId}.supabase.co/functions/v1/learning-metrics?asn=AS267458`,
        { headers: { Authorization: `Bearer ${session.access_token}`, apikey: anonKey } }
      );
      if (!res.ok) throw new Error("Falha");
      return res.json();
    },
    enabled: open,
  });

  const totalSamples = metrics?.total_samples || 0;
  const attackTotal = metrics?.attack_windows_total || 0;
  const attackWithExt = metrics?.attack_windows_with_external || 0;
  const attackCoverage = attackTotal > 0 ? ((attackWithExt / attackTotal) * 100).toFixed(1) : "0.0";
  const noAttackTotal = metrics?.no_attack_windows_total || 0;
  const noAttackClean = metrics?.no_attack_windows_without_external || 0;
  const cleanRatio = noAttackTotal > 0 ? ((noAttackClean / noAttackTotal) * 100).toFixed(1) : "0.0";
  const highSev = metrics?.by_severity?.find((s: any) => s.severity === "HIGH");
  const highTotal = highSev?.total || 0;
  const highWithExt = highSev?.with_external || 0;
  const highCoverage = highTotal > 0 ? ((highWithExt / highTotal) * 100).toFixed(1) : "0.0";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[85vh] p-0">
        <DialogHeader className="px-6 pt-6 pb-2">
          <DialogTitle className="text-lg">Documentação – Geração de Dataset de Treino</DialogTitle>
          <p className="text-xs text-muted-foreground">ASN AS267458 | K2 Network</p>
        </DialogHeader>
        <ScrollArea className="px-6 pb-2 max-h-[65vh]">
          <div className="prose prose-invert prose-sm max-w-none space-y-4 text-sm text-foreground/90">
            <h2 className="text-base font-bold text-foreground">Visão geral</h2>
            <p>
              Este card mede o quanto conseguimos "enxergar" ataques do Wanguard usando apenas sinais externos de roteamento
              e integridade (BGP interno, Qrator, RPKI e RIPEstat). As métricas abaixo foram calculadas sobre o dataset dos
              últimos 7 dias para o AS267458.
            </p>

            <h2 className="text-base font-bold text-foreground">Fontes externas consideradas como anomalia forte</h2>
            <ul className="list-disc pl-5 space-y-1">
              <li><strong>BGP interno</strong>: perda de vizinhos BGP e perda de prefixos anunciados.</li>
              <li><strong>Qrator</strong>: eventos de <code>PATH_ANOMALY</code> e anomalias de visibilidade.</li>
              <li><strong>RPKI</strong>: validações de origem combinadas com anomalias de caminho.</li>
              <li><strong>RIPEstat</strong>: quedas relevantes de visibilidade (<code>VISIBILITY_DROP</code>) e surtos de updates (<code>ASPATH_ANOMALY</code>).</li>
            </ul>

            <h2 className="text-base font-bold text-foreground">Métricas atuais (últimos 7 dias)</h2>
            <ul className="list-disc pl-5 space-y-1">
              <li><strong>Total de janelas analisadas</strong>: {totalSamples}</li>
              <li><strong>Cobertura em janelas com ataque</strong>: {attackCoverage}% ({attackWithExt} de {attackTotal} janelas com ataque tiveram pelo menos uma anomalia externa forte)</li>
              <li><strong>Confiabilidade sem ataque</strong>: {cleanRatio}% ({noAttackClean} de {noAttackTotal} janelas sem ataque não tiveram nenhuma anomalia externa forte)</li>
              <li><strong>Cobertura em ataques de severidade HIGH</strong>: {highCoverage}% ({highWithExt} de {highTotal} janelas HIGH com sinal externo)</li>
            </ul>

            <h2 className="text-base font-bold text-foreground">Interpretação</h2>
            <ul className="list-disc pl-5 space-y-1">
              <li>A cobertura de ~{attackCoverage}% mostra que uma parte dos ataques vistos pelo Wanguard já deixa "pegadas" claras em fontes externas (especialmente em eventos de rota).</li>
              <li>A confiabilidade de ~{cleanRatio}% indica que, na maior parte do tempo sem ataque, as fontes externas permanecem silenciosas, mantendo o ruído sob controle.</li>
              <li>Esse equilíbrio entre cobertura e confiabilidade é intencional: preferimos um sinal externo mais conservador (menos ruído) e vamos ampliando fontes aos poucos (como RPKI e RIPEstat) à medida que validamos o impacto.</li>
            </ul>

            <h2 className="text-base font-bold text-foreground">Evolução do aprendizado</h2>
            <ul className="list-disc pl-5 space-y-1">
              <li><strong>Versão inicial</strong>: apenas Qrator + BGP interno como fontes externas fortes.</li>
              <li><strong>Versão atual</strong>: inclusão de RPKI como anomalia forte e integração do RIPEstat para visibilidade e updates BGP, além de geração diária automática do dataset.</li>
              <li><strong>Próximo passo</strong>: acompanhar se RIPEstat passa a contribuir com novos incidentes e reavaliar periodicamente a cobertura e a confiabilidade, ajustando limiares conforme a experiência operacional.</li>
              <li><strong>Automação</strong>: dataset regenerado automaticamente todo dia às 03:00 UTC via pg_cron, cobrindo sempre os últimos 7 dias, garantindo que as métricas estejam sempre atualizadas sem intervenção manual.</li>
            </ul>
          </div>
        </ScrollArea>
        <DialogFooter className="px-6 pb-6">
          <Button variant="outline" onClick={() => onOpenChange(false)}>Fechar</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
