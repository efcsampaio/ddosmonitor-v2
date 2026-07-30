import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { motion } from "motion/react";
import {
  Activity,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Wifi,
  WifiOff,
  Server,
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";

interface ApiEndpoint {
  id: string;
  name: string;
  description: string;
  url: string;
  method: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
  category: "edge-function" | "external" | "database";
}

interface ApiStatus {
  id: string;
  status: "online" | "offline" | "degraded" | "checking";
  latencyMs: number | null;
  lastChecked: Date | null;
  error?: string;
  httpStatus?: number;
}

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL as string;
const SUPABASE_KEY = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY as string;

const API_ENDPOINTS: ApiEndpoint[] = [
  {
    id: "asn-monitor",
    name: "ASN Monitor",
    description: "Monitoramento de ASNs e métricas de rede",
    url: `${SUPABASE_URL}/functions/v1/asn-monitor`,
    method: "GET",
    category: "edge-function",
  },
  {
    id: "wanguard-proxy",
    name: "Wanguard Proxy",
    description: "Proxy de dados do Wanguard (ataques DDoS)",
    url: `${SUPABASE_URL}/functions/v1/wanguard-proxy`,
    method: "GET",
    category: "edge-function",
  },
  {
    id: "estimate-attack-risk",
    name: "Estimativa de Risco",
    description: "Análise de risco de ataque por ASN",
    url: `${SUPABASE_URL}/functions/v1/estimate-attack-risk`,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ asn: "AS28168" }),
    category: "edge-function",
  },
  {
    id: "enrich-ip-reputation",
    name: "Reputação de IP",
    description: "Enriquecimento de reputação de IPs",
    url: `${SUPABASE_URL}/functions/v1/enrich-ip-reputation`,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ asn: "AS28168" }),
    category: "edge-function",
  },
  {
    id: "telegram-notify",
    name: "Telegram Notify",
    description: "Envio de notificações via Telegram",
    url: `${SUPABASE_URL}/functions/v1/telegram-notify`,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "health_check" }),
    category: "edge-function",
  },
  {
    id: "learning-metrics",
    name: "Learning Metrics",
    description: "Métricas de aprendizado do modelo",
    url: `${SUPABASE_URL}/functions/v1/learning-metrics`,
    method: "GET",
    category: "edge-function",
  },
  {
    id: "supabase-db",
    name: "Database",
    description: "Conexão com o banco de dados principal",
    url: "supabase-db",
    method: "GET",
    category: "database",
  },
  {
    id: "ripe-stat",
    name: "RIPEstat API",
    description: "Dados BGP e visibilidade de prefixos",
    url: "https://stat.ripe.net/data/network-info/data.json?resource=AS28168",
    method: "GET",
    category: "external",
  },
];

const STATUS_CONFIG = {
  online: {
    color: "hsl(142, 71%, 45%)",
    bg: "hsl(142, 71%, 45%, 0.1)",
    border: "hsl(142, 71%, 45%, 0.3)",
    icon: CheckCircle2,
    label: "Online",
  },
  degraded: {
    color: "hsl(45, 93%, 58%)",
    bg: "hsl(45, 93%, 58%, 0.1)",
    border: "hsl(45, 93%, 58%, 0.3)",
    icon: AlertTriangle,
    label: "Degradado",
  },
  offline: {
    color: "hsl(0, 84%, 60%)",
    bg: "hsl(0, 84%, 60%, 0.1)",
    border: "hsl(0, 84%, 60%, 0.3)",
    icon: XCircle,
    label: "Offline",
  },
  checking: {
    color: "hsl(var(--muted-foreground))",
    bg: "hsl(var(--muted) / 0.5)",
    border: "hsl(var(--border))",
    icon: Clock,
    label: "Verificando...",
  },
};

async function checkEndpoint(ep: ApiEndpoint, sessionToken: string | null): Promise<Omit<ApiStatus, "id">> {
  const start = performance.now();

  try {
    if (ep.category === "database") {
      const { error } = await supabase.from("monitored_asns").select("asn").limit(1);
      const latency = Math.round(performance.now() - start);
      if (error) {
        return { status: "offline", latencyMs: latency, lastChecked: new Date(), error: error.message };
      }
      return {
        status: latency > 2000 ? "degraded" : "online",
        latencyMs: latency,
        lastChecked: new Date(),
      };
    }

    // Antes: usava sempre a anon key como Authorization bearer. Agora manda
    // o token de sessão real quando disponível — várias functions
    // (wanguard-proxy, estimate-attack-risk) passaram a exigir um JWT de
    // usuário de verdade e rejeitariam a anon key com 401.
    const headers: Record<string, string> = {
      Authorization: `Bearer ${sessionToken || SUPABASE_KEY}`,
      apikey: SUPABASE_KEY,
      ...ep.headers,
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const res = await fetch(ep.url, {
      method: ep.method,
      headers: ep.category === "external" ? ep.headers ?? {} : headers,
      body: ep.method === "POST" ? ep.body : undefined,
      signal: controller.signal,
    });

    clearTimeout(timeout);
    const latency = Math.round(performance.now() - start);

    // 401/403 aqui não significa "quebrado" — algumas functions (ex:
    // enrich-ip-reputation) são de propósito restritas a service role e
    // vão sempre recusar um token de usuário comum. Um 401/403 correto é
    // sinal de que a function está no ar e aplicando a auth certa.
    if (res.ok || res.status === 400 || res.status === 401 || res.status === 403) {
      return {
        status: latency > 3000 ? "degraded" : "online",
        latencyMs: latency,
        lastChecked: new Date(),
        httpStatus: res.status,
      };
    }

    return {
      status: res.status >= 500 ? "offline" : "degraded",
      latencyMs: latency,
      lastChecked: new Date(),
      error: `HTTP ${res.status}`,
      httpStatus: res.status,
    };
  } catch (err: unknown) {
    const latency = Math.round(performance.now() - start);
    const msg = err instanceof Error ? err.message : "Unknown error";
    return {
      status: "offline",
      latencyMs: latency,
      lastChecked: new Date(),
      error: msg.includes("abort") ? "Timeout (10s)" : msg,
    };
  }
}

export function ApiStatusMonitor() {
  const [statuses, setStatuses] = useState<Record<string, ApiStatus>>(() => {
    const init: Record<string, ApiStatus> = {};
    API_ENDPOINTS.forEach((ep) => {
      init[ep.id] = { id: ep.id, status: "checking", latencyMs: null, lastChecked: null };
    });
    return init;
  });
  const [refreshing, setRefreshing] = useState(false);

  const checkAll = useCallback(async () => {
    setRefreshing(true);
    setStatuses((prev) => {
      const next = { ...prev };
      API_ENDPOINTS.forEach((ep) => {
        next[ep.id] = { ...next[ep.id], status: "checking" };
      });
      return next;
    });

    const { data: { session } } = await supabase.auth.getSession();
    const sessionToken = session?.access_token ?? null;

    const results = await Promise.allSettled(
      API_ENDPOINTS.map(async (ep) => {
        const result = await checkEndpoint(ep, sessionToken);
        setStatuses((prev) => ({ ...prev, [ep.id]: { id: ep.id, ...result } }));
        return { id: ep.id, ...result };
      })
    );

    setRefreshing(false);

    const fulfilled = results.filter((r) => r.status === "fulfilled") as PromiseFulfilledResult<ApiStatus>[];
    const offline = fulfilled.filter((r) => r.value.status === "offline").length;
    if (offline > 0) {
      toast.warning(`${offline} API(s) offline detectada(s)`);
    }
  }, []);

  useEffect(() => {
    checkAll();
    const interval = setInterval(checkAll, 60000);
    return () => clearInterval(interval);
  }, [checkAll]);

  const statusList = API_ENDPOINTS.map((ep) => ({ ...ep, ...statuses[ep.id] }));
  const onlineCount = statusList.filter((s) => s.status === "online").length;
  const degradedCount = statusList.filter((s) => s.status === "degraded").length;
  const offlineCount = statusList.filter((s) => s.status === "offline").length;

  const overallStatus: "online" | "degraded" | "offline" =
    offlineCount > 0 ? "offline" : degradedCount > 0 ? "degraded" : "online";
  const overallConfig = STATUS_CONFIG[overallStatus];
  const OverallIcon = overallStatus === "online" ? Wifi : WifiOff;

  return (
    <Card className="border-border/50">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <motion.div
              animate={{ rotate: refreshing ? 360 : 0 }}
              transition={{ duration: 1, repeat: refreshing ? Infinity : 0, ease: "linear" }}
            >
              <Server className="h-5 w-5 text-primary" />
            </motion.div>
            <div>
              <CardTitle className="text-base">Monitor de APIs</CardTitle>
              <CardDescription className="text-xs">
                Status em tempo real das APIs e serviços
              </CardDescription>
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={checkAll}
            disabled={refreshing}
            className="gap-2"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
            Atualizar
          </Button>
        </div>

        {/* Overall status bar */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="mt-4 flex items-center gap-4 rounded-lg p-3"
          style={{ backgroundColor: overallConfig.bg, border: `1px solid ${overallConfig.border}` }}
        >
          <OverallIcon className="h-5 w-5" style={{ color: overallConfig.color }} />
          <div className="flex-1">
            <p className="text-sm font-medium" style={{ color: overallConfig.color }}>
              {overallStatus === "online"
                ? "Todos os serviços operacionais"
                : overallStatus === "degraded"
                ? "Alguns serviços com latência elevada"
                : "Serviços com falha detectados"}
            </p>
            <p className="text-xs text-muted-foreground mt-0.5">
              {onlineCount} online · {degradedCount} degradados · {offlineCount} offline
            </p>
          </div>
          <div className="flex gap-1.5">
            {[...Array(API_ENDPOINTS.length)].map((_, i) => {
              const s = statusList[i];
              const cfg = STATUS_CONFIG[s?.status ?? "checking"];
              return (
                <motion.div
                  key={i}
                  className="h-2.5 w-2.5 rounded-full"
                  style={{ backgroundColor: cfg.color }}
                  animate={
                    s?.status === "offline"
                      ? { opacity: [1, 0.4, 1] }
                      : s?.status === "checking"
                      ? { opacity: [0.3, 0.7, 0.3] }
                      : {}
                  }
                  transition={
                    s?.status === "offline" || s?.status === "checking"
                      ? { duration: 1.5, repeat: Infinity }
                      : {}
                  }
                />
              );
            })}
          </div>
        </motion.div>
      </CardHeader>

      <CardContent className="space-y-2">
        {/* Category groups */}
        {(["edge-function", "database", "external"] as const).map((cat) => {
          const items = statusList.filter((s) => s.category === cat);
          if (items.length === 0) return null;
          const catLabel =
            cat === "edge-function"
              ? "Edge Functions"
              : cat === "database"
              ? "Banco de Dados"
              : "APIs Externas";

          return (
            <div key={cat}>
              <p className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-2 mt-3">
                {catLabel}
              </p>
              <div className="space-y-1.5">
                {items.map((item, idx) => {
                  const cfg = STATUS_CONFIG[item.status ?? "checking"];
                  const StatusIcon = cfg.icon;
                  return (
                    <motion.div
                      key={item.id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.05 }}
                      className="flex items-center gap-3 rounded-md px-3 py-2.5 transition-colors hover:bg-accent/50"
                      style={{ borderLeft: `3px solid ${cfg.color}` }}
                    >
                      <motion.div
                        animate={
                          item.status === "checking"
                            ? { rotate: 360 }
                            : item.status === "offline"
                            ? { scale: [1, 1.2, 1] }
                            : {}
                        }
                        transition={
                          item.status === "checking"
                            ? { duration: 1, repeat: Infinity, ease: "linear" }
                            : item.status === "offline"
                            ? { duration: 1.5, repeat: Infinity }
                            : {}
                        }
                      >
                        <StatusIcon className="h-4 w-4" style={{ color: cfg.color }} />
                      </motion.div>

                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-foreground truncate">{item.name}</p>
                        <p className="text-[11px] text-muted-foreground truncate">{item.description}</p>
                      </div>

                      <div className="flex items-center gap-3 shrink-0">
                        {item.latencyMs !== null && (
                          <span
                            className="text-xs font-mono tabular-nums"
                            style={{
                              color:
                                item.latencyMs > 3000
                                  ? "hsl(0, 84%, 60%)"
                                  : item.latencyMs > 1000
                                  ? "hsl(45, 93%, 58%)"
                                  : "hsl(142, 71%, 45%)",
                            }}
                          >
                            {item.latencyMs}ms
                          </span>
                        )}
                        <Badge
                          variant="outline"
                          className="text-[10px] px-2 py-0.5 border-none font-medium"
                          style={{ backgroundColor: cfg.bg, color: cfg.color }}
                        >
                          {cfg.label}
                        </Badge>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            </div>
          );
        })}

        {/* Last checked */}
        <div className="pt-3 border-t border-border/50 flex items-center gap-2 text-[11px] text-muted-foreground">
          <Activity className="h-3 w-3" />
          <span>Atualização automática a cada 60s</span>
          {statuses[API_ENDPOINTS[0].id]?.lastChecked && (
            <span className="ml-auto">
              Última verificação:{" "}
              {statuses[API_ENDPOINTS[0].id].lastChecked!.toLocaleTimeString("pt-BR")}
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
