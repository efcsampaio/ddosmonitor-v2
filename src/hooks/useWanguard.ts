import { useQuery } from "@tanstack/react-query";
import { fetchWanguardEvents, fetchWanguardStatus, type WanguardEvent, type WanguardStatus } from "@/services/wanguardService";

export function useWanguardAnomalies(startDate: Date, endDate: Date, refreshKey = 0) {
  const query = useQuery({
    queryKey: ["wanguard-anomalies", startDate.toISOString(), endDate.toISOString(), refreshKey],
    queryFn: () => fetchWanguardEvents(startDate, endDate),
  });

  return {
    data: query.data?.events ?? [],
    source: query.data?.source ?? "error" as const,
    apiError: query.data?.error,
    isLoading: query.isLoading,
    error: query.error,
    refetch: query.refetch,
  };
}

export function useWanguardStatus() {
  const query = useQuery({
    queryKey: ["wanguard-status"],
    queryFn: () => fetchWanguardStatus(),
    refetchInterval: 60000,
  });

  return {
    online: query.data?.online ?? false,
    checkedAt: query.data?.checkedAt ?? "",
    isLoading: query.isLoading,
  };
}

export type { WanguardEvent, WanguardStatus };
