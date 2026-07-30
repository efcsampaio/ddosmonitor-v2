import { useState, useEffect, useCallback, useRef } from "react";
import { fetchAsnStatus, simularAtaqueAPI, adicionarAsnAPI, removerAsnAPI } from "@/services/asnApi";
import type { AsnMetrics, AsnStatus } from "@/services/asnApi";

export type { AsnMetrics, AsnStatus };

export interface AlertLog {
  id: string;
  timestamp: Date;
  asn: string;
  empresa: string;
  tipo: "ataque_detectado" | "alerta" | "recuperado";
  mensagem: string;
}

export interface ASNDataLocal {
  metrics: AsnMetrics;
  historicoLatencia: { tempo: string; valor: number }[];
}

function formatarHora(d: Date): string {
  return d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

const statusLabel: Record<AsnStatus, string> = {
  HEALTHY: "Saudável",
  WARNING: "Alerta",
  UNDER_ATTACK: "Sob Ataque",
};

export function useNetworkMonitor() {
  const [dados, setDados] = useState<Record<string, ASNDataLocal>>({});
  const [alertas, setAlertas] = useState<AlertLog[]>([]);
  const [carregando, setCarregando] = useState(true);
  const alertIdRef = useRef(0);
  const prevStatusRef = useRef<Record<string, AsnStatus>>({});

  const adicionarAlerta = useCallback((asn: string, empresa: string, tipo: AlertLog["tipo"], mensagem: string) => {
    alertIdRef.current += 1;
    setAlertas((prev) => [{
      id: `alert-${alertIdRef.current}`,
      timestamp: new Date(),
      asn,
      empresa,
      tipo,
      mensagem,
    }, ...prev].slice(0, 50));
  }, []);

  const buscarDados = useCallback(async () => {
    try {
      const metrics = await fetchAsnStatus();
      if (!metrics || metrics.length === 0) {
        setCarregando(false);
        return; // preserve existing data
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

          // Detect status changes for alerts
          const prevStatus = prevStatusRef.current[m.asn];
          if (prevStatus && prevStatus !== m.status) {
            if (m.status === "UNDER_ATTACK") {
              adicionarAlerta(m.asn, m.name, "ataque_detectado", `Ataque DDoS detectado em ${m.asn} (${m.name})`);
            } else if (m.status === "WARNING") {
              adicionarAlerta(m.asn, m.name, "alerta", `Alerta de rede em ${m.asn} (${m.name})`);
            } else if (prevStatus === "UNDER_ATTACK" && m.status === "HEALTHY") {
              adicionarAlerta(m.asn, m.name, "recuperado", `${m.asn} (${m.name}) recuperado`);
            }
          }
          prevStatusRef.current[m.asn] = m.status;
        }
        return next;
      });
      setCarregando(false);
    } catch (err) {
      console.error("Erro ao buscar dados:", err);
      setCarregando(false);
    }
  }, [adicionarAlerta]);

  const simularAtaque = useCallback(async (asn: string) => {
    try {
      await simularAtaqueAPI(asn);
      await buscarDados();
    } catch (err) {
      console.error("Erro ao simular ataque:", err);
    }
  }, [buscarDados]);

  const adicionarAsn = useCallback(async (asn: string) => {
    await adicionarAsnAPI(asn);
    await buscarDados();
  }, [buscarDados]);

  const removerAsn = useCallback(async (asn: string) => {
    await removerAsnAPI(asn);
    await buscarDados();
  }, [buscarDados]);

  useEffect(() => {
    buscarDados();
    const interval = setInterval(buscarDados, 10000);
    return () => clearInterval(interval);
  }, [buscarDados]);

  const dadosArray = Object.values(dados);

  return { dados: dadosArray, alertas, simularAtaque, adicionarAsn, removerAsn, carregando, atualizar: buscarDados };
}
