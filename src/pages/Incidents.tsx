import { useState, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import { format } from "date-fns";
import { ptBR } from "date-fns/locale";
import { DashboardHeader } from "@/components/DashboardHeader";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  ShieldAlert,
  AlertTriangle,
  CalendarIcon,
  ArrowLeft,
  Filter,
  Clock,
  Globe,
  Wifi,
  Activity,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { fetchIncidents, type Incident } from "@/services/asnApi";

const statusConfig: Record<string, { label: string; icon: typeof ShieldAlert; class: string }> = {
  UNDER_ATTACK: {
    label: "Sob Ataque",
    icon: ShieldAlert,
    class: "bg-destructive/20 text-destructive border-destructive/30",
  },
  WARNING: {
    label: "Alerta",
    icon: AlertTriangle,
    class: "bg-yellow-500/20 text-yellow-500 border-yellow-500/30",
  },
};

type SignalCategory = "all" | "hijack" | "route_leak" | "rpki" | "bgp_anomaly";

const signalCategoryConfig: Record<Exclude<SignalCategory, "all">, { label: string; keywords: string[] }> = {
  hijack: { label: "Hijack", keywords: ["HIJACK", "hijack"] },
  route_leak: { label: "Route Leak / MOAS", keywords: ["ROUTE_LEAK", "MOAS", "route leak", "Múltiplas origens"] },
  rpki: { label: "RPKI", keywords: ["RPKI"] },
  bgp_anomaly: { label: "Anomalia BGP", keywords: ["BGP", "vizinhos", "prefixos", "Visibilidade", "withdrawals", "oscilando", "FLAPPING", "WITHDRAWN"] },
};

function matchesSignalCategory(signals: string[], category: SignalCategory): boolean {
  if (category === "all") return true;
  const { keywords } = signalCategoryConfig[category];
  return signals.some(s => keywords.some(k => s.includes(k)));
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterAsn, setFilterAsn] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [filterCategory, setFilterCategory] = useState<SignalCategory>("all");
  const [dateFrom, setDateFrom] = useState<Date | undefined>(undefined);
  const [dateTo, setDateTo] = useState<Date | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const data = await fetchIncidents({ days: 90 });
        if (!cancelled) setIncidents(data);
      } catch (err) {
        console.error("Erro ao buscar incidentes:", err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  const uniqueAsns = useMemo(() => {
    const map = new Map<string, string>();
    incidents.forEach((i) => map.set(i.asn, i.name));
    return Array.from(map.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  }, [incidents]);

  const filtered = useMemo(() => {
    return incidents.filter((i) => {
      if (filterAsn !== "all" && i.asn !== filterAsn) return false;
      if (filterStatus !== "all" && i.status !== filterStatus) return false;
      if (filterCategory !== "all" && !matchesSignalCategory(i.signals, filterCategory)) return false;
      if (dateFrom) {
        const d = new Date(i.created_at);
        if (d < dateFrom) return false;
      }
      if (dateTo) {
        const d = new Date(i.created_at);
        const end = new Date(dateTo);
        end.setHours(23, 59, 59, 999);
        if (d > end) return false;
      }
      return true;
    });
  }, [incidents, filterAsn, filterStatus, filterCategory, dateFrom, dateTo]);

  const stats = useMemo(() => {
    const attacks = filtered.filter((i) => i.status === "UNDER_ATTACK").length;
    const warnings = filtered.filter((i) => i.status === "WARNING").length;
    return { total: filtered.length, attacks, warnings };
  }, [filtered]);

  return (
    <div className="min-h-screen bg-background">
      <DashboardHeader />
      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        {/* Back + Title */}
        <div className="flex items-center gap-3">
          <Link to="/">
            <Button variant="ghost" size="icon" className="shrink-0">
              <ArrowLeft className="h-5 w-5" />
            </Button>
          </Link>
          <div>
            <h2 className="text-xl font-bold text-foreground">Histórico de Incidentes</h2>
            <p className="text-sm text-muted-foreground">
              Registro completo de alertas e ataques detectados
            </p>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <Card className="bg-card border-border p-4 flex items-center gap-3">
            <Activity className="h-5 w-5 text-primary" />
            <div>
              <p className="text-2xl font-bold text-foreground">{stats.total}</p>
              <p className="text-xs text-muted-foreground">Total de incidentes</p>
            </div>
          </Card>
          <Card className="bg-card border-border p-4 flex items-center gap-3">
            <ShieldAlert className="h-5 w-5 text-destructive" />
            <div>
              <p className="text-2xl font-bold text-destructive">{stats.attacks}</p>
              <p className="text-xs text-muted-foreground">Ataques detectados</p>
            </div>
          </Card>
          <Card className="bg-card border-border p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-yellow-500" />
            <div>
              <p className="text-2xl font-bold text-yellow-500">{stats.warnings}</p>
              <p className="text-xs text-muted-foreground">Alertas</p>
            </div>
          </Card>
        </div>

        {/* Filters */}
        <Card className="bg-card border-border p-4">
          <div className="flex items-center gap-2 mb-3">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-medium text-foreground">Filtros</span>
          </div>
          <div className="flex flex-wrap gap-3">
            <Select value={filterAsn} onValueChange={setFilterAsn}>
              <SelectTrigger className="w-[220px] h-9 text-xs">
                <SelectValue placeholder="Todos os ASNs" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Todos os ASNs</SelectItem>
                {uniqueAsns.map(([asn, name]) => (
                  <SelectItem key={asn} value={asn}>
                    {asn} — {name.length > 25 ? name.slice(0, 24) + "…" : name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={filterStatus} onValueChange={setFilterStatus}>
              <SelectTrigger className="w-[160px] h-9 text-xs">
                <SelectValue placeholder="Todos os status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Todos os status</SelectItem>
                <SelectItem value="UNDER_ATTACK">Sob Ataque</SelectItem>
                <SelectItem value="WARNING">Alerta</SelectItem>
              </SelectContent>
            </Select>

            <Select value={filterCategory} onValueChange={(v) => setFilterCategory(v as SignalCategory)}>
              <SelectTrigger className="w-[200px] h-9 text-xs">
                <SelectValue placeholder="Tipo de falha" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Todos os tipos</SelectItem>
                <SelectItem value="hijack">🔴 Hijack</SelectItem>
                <SelectItem value="route_leak">🟡 Route Leak / MOAS</SelectItem>
                <SelectItem value="rpki">🔒 RPKI</SelectItem>
                <SelectItem value="bgp_anomaly">📡 Anomalia BGP</SelectItem>
              </SelectContent>
            </Select>

            <Popover>
              <PopoverTrigger asChild>
                <Button variant="outline" size="sm" className={cn("h-9 text-xs gap-1.5", !dateFrom && "text-muted-foreground")}>
                  <CalendarIcon className="h-3.5 w-3.5" />
                  {dateFrom ? format(dateFrom, "dd/MM/yyyy") : "Data início"}
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-auto p-0" align="start">
                <Calendar
                  mode="single"
                  selected={dateFrom}
                  onSelect={setDateFrom}
                  locale={ptBR}
                  className={cn("p-3 pointer-events-auto")}
                />
              </PopoverContent>
            </Popover>

            <Popover>
              <PopoverTrigger asChild>
                <Button variant="outline" size="sm" className={cn("h-9 text-xs gap-1.5", !dateTo && "text-muted-foreground")}>
                  <CalendarIcon className="h-3.5 w-3.5" />
                  {dateTo ? format(dateTo, "dd/MM/yyyy") : "Data fim"}
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-auto p-0" align="start">
                <Calendar
                  mode="single"
                  selected={dateTo}
                  onSelect={setDateTo}
                  locale={ptBR}
                  className={cn("p-3 pointer-events-auto")}
                />
              </PopoverContent>
            </Popover>

            {(filterAsn !== "all" || filterStatus !== "all" || filterCategory !== "all" || dateFrom || dateTo) && (
              <Button
                variant="ghost"
                size="sm"
                className="h-9 text-xs"
                onClick={() => {
                  setFilterAsn("all");
                  setFilterStatus("all");
                  setFilterCategory("all");
                  setDateFrom(undefined);
                  setDateTo(undefined);
                }}
              >
                Limpar filtros
              </Button>
            )}
          </div>
        </Card>

        {/* Incidents List */}
        <Card className="bg-card border-border p-5">
          {loading ? (
            <p className="text-sm text-muted-foreground text-center py-12 animate-pulse">
              Carregando histórico de incidentes...
            </p>
          ) : filtered.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-12">
              Nenhum incidente encontrado com os filtros selecionados.
            </p>
          ) : (
            <ScrollArea className="h-[520px]">
              <div className="space-y-2">
                {filtered.map((inc) => {
                  const cfg = statusConfig[inc.status] || statusConfig.WARNING;
                  const Icon = cfg.icon;
                  const dt = new Date(inc.created_at);

                  return (
                    <div
                      key={inc.id}
                      className="flex items-start gap-3 p-4 rounded-lg bg-secondary/30 border border-border hover:bg-secondary/50 transition-colors"
                    >
                      <Icon className="h-5 w-5 shrink-0 mt-0.5 text-muted-foreground" />
                      <div className="flex-1 min-w-0 space-y-1.5">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-semibold text-sm text-foreground">
                            {inc.name || inc.asn}
                          </span>
                          <span className="text-xs text-muted-foreground font-mono">
                            {inc.asn}
                          </span>
                          <Badge variant="outline" className={cn("text-[10px]", cfg.class)}>
                            {cfg.label}
                          </Badge>
                        </div>

                        {/* Signals */}
                        {inc.signals && inc.signals.length > 0 && (
                          <div className="space-y-0.5">
                            {inc.signals.map((s, idx) => (
                              <p key={idx} className="text-xs text-muted-foreground">
                                {s}
                              </p>
                            ))}
                          </div>
                        )}

                        {/* Metrics row */}
                        <div className="flex items-center gap-4 text-[11px] text-muted-foreground">
                          {inc.bgp_state && (
                            <span className="flex items-center gap-1">
                              <Globe className="h-3 w-3" /> BGP: {inc.bgp_state}
                            </span>
                          )}
                          {inc.visibility_percent != null && (
                            <span className="flex items-center gap-1">
                              <Wifi className="h-3 w-3" /> Visib: {inc.visibility_percent}%
                            </span>
                          )}
                          {inc.packet_loss_percent != null && (
                            <span>Perda: {inc.packet_loss_percent}%</span>
                          )}
                          {inc.withdrawals > 0 && (
                            <span>Withdrawals: {inc.withdrawals}</span>
                          )}
                        </div>
                      </div>

                      <div className="text-right shrink-0">
                        <div className="flex items-center gap-1 text-xs text-muted-foreground">
                          <Clock className="h-3 w-3" />
                          {format(dt, "HH:mm:ss")}
                        </div>
                        <div className="text-[10px] text-muted-foreground">
                          {format(dt, "dd/MM/yyyy")}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </ScrollArea>
          )}
        </Card>
      </main>
    </div>
  );
}
