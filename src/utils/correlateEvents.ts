import type { WanguardEvent, ExternalAnomaly } from "@/services/wanguardService";

export interface CorrelationResult {
  wanguardEvent: WanguardEvent;
  correlatedAnomalies: ExternalAnomaly[];
  timeDiffMinutes: number | null;
  status: "correlacionado" | "parcial" | "sem_correlacao";
}

export interface CorrelationSummary {
  total: number;
  correlated: number;
  partial: number;
  noCorrelation: number;
  correlatedPercent: number;
  partialPercent: number;
  noCorrelationPercent: number;
}

export function correlateEvents(
  wanguardEvents: WanguardEvent[],
  externalEvents: ExternalAnomaly[],
  windowMinutes: number = 30
): CorrelationResult[] {
  const windowMs = windowMinutes * 60 * 1000;

  return wanguardEvents.map((wEvent) => {
    const wTime = wEvent.timestamp.getTime();
    const matched = externalEvents.filter((ext) => {
      const diff = Math.abs(ext.timestamp.getTime() - wTime);
      return diff <= windowMs;
    });

    const closestDiff = matched.length > 0
      ? Math.min(...matched.map((m) => Math.abs(m.timestamp.getTime() - wTime)))
      : null;

    let status: CorrelationResult["status"] = "sem_correlacao";
    if (matched.length >= 2) status = "correlacionado";
    else if (matched.length === 1) status = "parcial";

    return {
      wanguardEvent: wEvent,
      correlatedAnomalies: matched,
      timeDiffMinutes: closestDiff !== null ? Math.round(closestDiff / 60000) : null,
      status,
    };
  });
}

export function getCorrelationSummary(results: CorrelationResult[]): CorrelationSummary {
  const total = results.length;
  const correlated = results.filter((r) => r.status === "correlacionado").length;
  const partial = results.filter((r) => r.status === "parcial").length;
  const noCorrelation = results.filter((r) => r.status === "sem_correlacao").length;

  return {
    total,
    correlated,
    partial,
    noCorrelation,
    correlatedPercent: total > 0 ? Math.round((correlated / total) * 100) : 0,
    partialPercent: total > 0 ? Math.round((partial / total) * 100) : 0,
    noCorrelationPercent: total > 0 ? Math.round((noCorrelation / total) * 100) : 0,
  };
}

export function exportCorrelationCSV(results: CorrelationResult[]): string {
  const headers = [
    "Data/Hora Wanguard",
    "Prefixo Atacado",
    "Tamanho Ataque (Mbps)",
    "Anomalia Correlacionada",
    "Fonte Externa",
    "Timestamp Externa",
    "Janela (min)",
    "Status"
  ].join(";");

  const statusMap = {
    correlacionado: "Correlacionado",
    parcial: "Parcial",
    sem_correlacao: "Sem correlação"
  };

  const rows = results.map((r) => {
    const anomaly = r.correlatedAnomalies[0];
    return [
      `${r.wanguardEvent.date} ${r.wanguardEvent.startTime}`,
      r.wanguardEvent.prefix,
      Math.round(r.wanguardEvent.sizeBps / 1e6),
      anomaly ? anomaly.anomalyType : "-",
      anomaly ? anomaly.source : "-",
      anomaly ? `${anomaly.date} ${anomaly.time}` : "-",
      r.timeDiffMinutes ?? "-",
      statusMap[r.status]
    ].join(";");
  });

  return [headers, ...rows].join("\n");
}
