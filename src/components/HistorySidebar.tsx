import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { format } from "date-fns";
import { ptBR } from "date-fns/locale";
import { Home, History, ShieldAlert, AlertTriangle, ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { fetchIncidents, type Incident } from "@/services/asnApi";

const statusConfig: Record<string, { label: string; icon: typeof ShieldAlert; className: string }> = {
  UNDER_ATTACK: {
    label: "Ataque",
    icon: ShieldAlert,
    className: "bg-destructive/20 text-destructive border-destructive/30",
  },
  WARNING: {
    label: "Alerta",
    icon: AlertTriangle,
    className: "bg-yellow-500/20 text-yellow-500 border-yellow-500/30",
  },
};

export function HistorySidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchIncidents({ days: 7 })
      .then((data) => setIncidents(data.slice(0, 50)))
      .catch(console.error)
      .finally(() => setLoading(false));

    const interval = setInterval(() => {
      fetchIncidents({ days: 7 })
        .then((data) => setIncidents(data.slice(0, 50)))
        .catch(console.error);
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  return (
    <aside
      className={cn(
        "h-full border-r border-border bg-card flex flex-col transition-all duration-300 shrink-0",
        collapsed ? "w-12" : "w-72"
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between p-2 border-b border-border">
        {!collapsed && (
          <div className="flex items-center gap-2 px-1">
            <History className="h-4 w-4 text-primary" />
            <span className="text-sm font-semibold text-foreground">Histórico</span>
          </div>
        )}
        <Button
          variant="ghost"
          size="sm"
          className="h-8 w-8 p-0 shrink-0"
          onClick={() => setCollapsed(!collapsed)}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </Button>
      </div>

      {/* Home link */}
      <div className="p-2 border-b border-border">
        <Link to="/">
          <Button variant="ghost" size="sm" className={cn("gap-2 text-xs w-full", collapsed ? "justify-center px-0" : "justify-start")}>
            <Home className="h-4 w-4 shrink-0" />
            {!collapsed && <span>Página Inicial</span>}
          </Button>
        </Link>
      </div>

      {/* Incidents list */}
      {!collapsed && (
        <ScrollArea className="flex-1">
          <div className="p-2 space-y-1.5">
            {loading ? (
              <p className="text-xs text-muted-foreground text-center py-4 animate-pulse">
                Carregando...
              </p>
            ) : incidents.length === 0 ? (
              <p className="text-xs text-muted-foreground text-center py-4">
                Nenhum incidente recente
              </p>
            ) : (
              incidents.map((inc) => {
                const cfg = statusConfig[inc.status];
                const Icon = cfg?.icon || AlertTriangle;
                return (
                  <div
                    key={inc.id}
                    className="rounded-md border border-border bg-secondary/30 p-2 space-y-1"
                  >
                    <div className="flex items-center gap-1.5">
                      <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                      <span className="text-xs font-medium text-foreground truncate">
                        {inc.asn}
                      </span>
                      {cfg && (
                        <Badge variant="outline" className={cn("text-[10px] px-1 py-0 ml-auto", cfg.className)}>
                          {cfg.label}
                        </Badge>
                      )}
                    </div>
                    <p className="text-[10px] text-muted-foreground truncate">{inc.name}</p>
                    <p className="text-[10px] text-muted-foreground">
                      {format(new Date(inc.created_at), "dd/MM HH:mm", { locale: ptBR })}
                    </p>
                    {inc.signals.length > 0 && (
                      <p className="text-[10px] text-muted-foreground truncate">
                        {inc.signals[0]}
                      </p>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </ScrollArea>
      )}

      {/* Collapsed: icon-only tooltip */}
      {collapsed && (
        <div className="flex-1 flex flex-col items-center pt-2 gap-2">
          <History className="h-4 w-4 text-muted-foreground" />
        </div>
      )}

      {/* Footer link to full history */}
      {!collapsed && (
        <div className="p-2 border-t border-border">
          <Link to="/incidents">
            <Button variant="outline" size="sm" className="w-full text-xs gap-1.5">
              <History className="h-3.5 w-3.5" /> Ver histórico completo
            </Button>
          </Link>
        </div>
      )}
    </aside>
  );
}
