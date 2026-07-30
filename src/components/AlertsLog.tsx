import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { AlertTriangle, ShieldAlert, ShieldCheck, Globe } from "lucide-react";
import type { AlertLog } from "@/hooks/useNetworkMonitor";

interface Props {
  alertas: AlertLog[];
}

const tipoConfig = {
  ataque_detectado: { label: "Ataque", icon: ShieldAlert, cor: "bg-neon-red/20 text-neon-red border-neon-red/30" },
  alerta: { label: "Alerta", icon: AlertTriangle, cor: "bg-neon-yellow/20 text-neon-yellow border-neon-yellow/30" },
  recuperado: { label: "Recuperado", icon: ShieldCheck, cor: "bg-neon-green/20 text-neon-green border-neon-green/30" },
  rota_instavel: { label: "Rota Instável", icon: Globe, cor: "bg-neon-yellow/20 text-neon-yellow border-neon-yellow/30" },
};

export function AlertsLogPanel({ alertas }: Props) {
  return (
    <Card className="bg-card border-border p-5">
      <h2 className="text-lg font-bold text-foreground mb-4 flex items-center gap-2">
        <AlertTriangle className="h-5 w-5 text-neon-yellow" />
        Registro de Alertas
      </h2>
      <ScrollArea className="h-64">
        {alertas.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">
            Nenhum alerta registrado ainda.
          </p>
        ) : (
          <div className="space-y-2">
            {alertas.map((a) => {
              const cfg = tipoConfig[a.tipo];
              const Icon = cfg.icon;
              return (
                <div
                  key={a.id}
                  className="flex items-center gap-3 p-3 rounded-lg bg-secondary/50 border border-border"
                >
                  <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-foreground truncate">{a.mensagem}</p>
                    <p className="text-xs text-muted-foreground">
                      {a.timestamp.toLocaleTimeString("pt-BR")} — {a.asn}
                    </p>
                  </div>
                  <Badge variant="outline" className={`shrink-0 text-xs ${cfg.cor}`}>
                    {cfg.label}
                  </Badge>
                </div>
              );
            })}
          </div>
        )}
      </ScrollArea>
    </Card>
  );
}
