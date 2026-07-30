import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { AlertTriangle, RefreshCw, ShieldCheck, ShieldAlert } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";

interface SeverityBreakdown {
  severity: string;
  total: number;
  with_external: number;
  without_external: number;
  coverage_ratio: number;
}

interface CoverageMetrics {
  asn: string;
  total_samples: number;
  attack_windows_total: number;
  attack_windows_with_external: number;
  attack_windows_without_external: number;
  attack_coverage_ratio: number;
  no_attack_windows_total: number;
  no_attack_windows_with_external: number;
  no_attack_windows_without_external: number;
  no_attack_clean_ratio: number;
  by_severity: SeverityBreakdown[];
}

async function fetchCoverageMetrics(asn: string): Promise<CoverageMetrics> {
  const projectId = import.meta.env.VITE_SUPABASE_PROJECT_ID;
  const anonKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
  // Antes: usava a anon key também como Authorization bearer — learning-metrics
  // agora exige um JWT de sessão real. O header apikey continua sendo a anon
  // key (identificador do projeto, não credencial de usuário).
  const { data: { session } } = await supabase.auth.getSession();
  if (!session?.access_token) throw new Error("Sessão expirada");
  const res = await fetch(
    `https://${projectId}.supabase.co/functions/v1/learning-metrics?asn=${encodeURIComponent(asn)}`,
    {
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        apikey: anonKey,
      },
    }
  );
  if (!res.ok) throw new Error("Falha ao carregar métricas");
  return res.json();
}

function pct(v: number): string {
  return `${(v * 100).toFixed(1)}%`;
}

const SEVERITY_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH"];
const SEVERITY_COLORS: Record<string, string> = {
  NONE: "text-muted-foreground",
  LOW: "text-yellow-400",
  MEDIUM: "text-orange-400",
  HIGH: "text-destructive",
};

export function ExternalCoverageCard({ asn = "AS267458" }: { asn?: string }) {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["coverage-metrics", asn],
    queryFn: () => fetchCoverageMetrics(asn),
  });

  if (isLoading) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Cobertura Externa vs Wanguard</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <Skeleton className="h-24 rounded-lg" />
            <Skeleton className="h-24 rounded-lg" />
          </div>
          <Skeleton className="h-32 rounded-lg" />
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Cobertura Externa vs Wanguard</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center gap-3 py-6 text-center">
            <AlertTriangle className="h-8 w-8 text-destructive" />
            <p className="text-sm text-muted-foreground">
              Não foi possível carregar as métricas de cobertura externa. Tente novamente.
            </p>
            <Button size="sm" variant="outline" className="gap-1.5" onClick={() => refetch()}>
              <RefreshCw className="h-3.5 w-3.5" /> Tentar novamente
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!data || data.total_samples === 0) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Cobertura Externa vs Wanguard</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-center text-sm text-muted-foreground py-8">
            Ainda não há dados suficientes em as_attack_samples para calcular as métricas de cobertura.
          </p>
        </CardContent>
      </Card>
    );
  }

  const sortedSeverity = [...data.by_severity].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <ShieldCheck className="h-4 w-4" />
          Cobertura Externa vs Wanguard
          <Badge variant="outline" className="ml-auto text-[10px]">{data.total_samples} amostras</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Two main stats */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="bg-secondary/50 rounded-lg px-4 py-3 text-center space-y-1">
            <div className="flex items-center justify-center gap-1.5">
              <ShieldAlert className="h-4 w-4 text-destructive" />
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
                Cobertura em janelas com ataque
              </p>
            </div>
            {data.attack_windows_total > 0 ? (
              <>
                <p className="text-2xl font-bold text-foreground">{pct(data.attack_coverage_ratio)}</p>
                <p className="text-[10px] text-muted-foreground">
                  {data.attack_windows_with_external} de {data.attack_windows_total} janelas com pelo menos 1 anomalia externa
                </p>
              </>
            ) : (
              <p className="text-xs text-muted-foreground py-2">
                Sem janelas com ataque Wanguard no dataset atual.
              </p>
            )}
          </div>

          <div className="bg-secondary/50 rounded-lg px-4 py-3 text-center space-y-1">
            <div className="flex items-center justify-center gap-1.5">
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
                Confiabilidade sem ataque
              </p>
            </div>
            {data.no_attack_windows_total > 0 ? (
              <>
                <p className="text-2xl font-bold text-foreground">{pct(data.no_attack_clean_ratio)}</p>
                <p className="text-[10px] text-muted-foreground">
                  {data.no_attack_windows_without_external} de {data.no_attack_windows_total} janelas sem anomalia externa reportada
                </p>
              </>
            ) : (
              <p className="text-xs text-muted-foreground py-2">
                Sem janelas sem ataque Wanguard no dataset atual.
              </p>
            )}
          </div>
        </div>

        {/* Severity breakdown table */}
        <div className="overflow-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Severidade</TableHead>
                <TableHead className="text-right">Amostras</TableHead>
                <TableHead className="text-right">Com sinal externo</TableHead>
                <TableHead className="text-right">Sem sinal externo</TableHead>
                <TableHead className="text-right">Cobertura externa</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sortedSeverity.map((s) => (
                <TableRow key={s.severity}>
                  <TableCell>
                    <Badge variant="outline" className={`text-[10px] ${SEVERITY_COLORS[s.severity] || ""}`}>
                      {s.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-right">{s.total}</TableCell>
                  <TableCell className="text-xs text-right">{s.with_external}</TableCell>
                  <TableCell className="text-xs text-right">{s.without_external}</TableCell>
                  <TableCell className="text-xs text-right font-mono">{pct(s.coverage_ratio)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
