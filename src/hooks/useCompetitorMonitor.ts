/**
 * Hook para monitorar os 3 ASNs concorrentes estratégicos.
 * Busca dados diretamente via ?asns= (sem filtro por user_id).
 */
import { useState, useEffect, useCallback, useRef } from "react";
import { fetchAsnStatusByList } from "@/services/asnApi";
import type { AsnMetrics } from "@/services/asnApi";
import type { ASNDataLocal } from "@/hooks/useNetworkMonitor";

/** ASNs concorrentes estratégicos — fixos e globais */
export const COMPETITOR_ASNS = ["AS268538", "AS267530", "AS268726"];

function formatarHora(d: Date): string {
  return d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function useCompetitorMonitor() {
  const [dados, setDados] = useState<Record<string, ASNDataLocal>>({});
  const [carregando, setCarregando] = useState(true);

  const buscarDados = useCallback(async () => {
    try {
      const metrics = await fetchAsnStatusByList(COMPETITOR_ASNS);
      if (!metrics || metrics.length === 0) {
        setCarregando(false);
        return;
      }
      setDados((prev) => {
        const next: Record<string, ASNDataLocal> = {};
        for (const m of metrics) {
          const existing = prev[m.asn];
          const historico = existing
            ? [...existing.historicoLatencia.slice(-29), { tempo: formatarHora(new Date()), valor: m.latency.avgMs }]
            : Array.from({ length: 30 }, (_, i) => ({
                tempo: formatarHora(new Date(Date.now() - (29 - i) * 60000)),
                valor: m.latency.avgMs + Math.round((Math.random() - 0.5) * 20),
              }));
          next[m.asn] = { metrics: m, historicoLatencia: historico };
        }
        return next;
      });
      setCarregando(false);
    } catch (err) {
      console.error("Erro ao buscar dados de concorrentes:", err);
      setCarregando(false);
    }
  }, []);

  useEffect(() => {
    buscarDados();
    const interval = setInterval(buscarDados, 30000); // 30s para concorrentes
    return () => clearInterval(interval);
  }, [buscarDados]);

  const dadosArray = Object.values(dados);

  return { dados: dadosArray, carregando, atualizar: buscarDados };
}
