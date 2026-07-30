import { useState, useEffect, useRef, useMemo } from "react";
import { DashboardHeader } from "@/components/DashboardHeader";
import { SummaryCards } from "@/components/SummaryCards";
import { ASNCard, fetchRiskForAsn, type RiskData } from "@/components/ASNCard";
import { InstabilityRanking } from "@/components/InstabilityRanking";
import { AsnHistoryChart } from "@/components/AsnHistoryChart";
import { TelegramSettings } from "@/components/TelegramSettings";
import { ApiStatusMonitor } from "@/components/ApiStatusMonitor";
import { AsnTiReputation } from "@/components/AsnTiReputation";
import { AlertsHistory } from "@/components/AlertsHistory";
import { WanguardTab } from "@/components/WanguardTab";
import { HighVolumeAlertsCard } from "@/components/HighVolumeAlertsCard";
import { useWanguardAttacks, type PeriodOption } from "@/hooks/useWanguardAttacks";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { motion, AnimatePresence } from "motion/react";

import { useNetworkMonitor } from "@/hooks/useNetworkMonitor";
import { useCompetitorMonitor, COMPETITOR_ASNS } from "@/hooks/useCompetitorMonitor";
import { useAuthContext } from "@/App";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Plus, RefreshCw, SearchX } from "lucide-react";
import { cn } from "@/lib/utils";

function EventosAlertasContent() {
  const [period, setPeriod] = useState<PeriodOption>("7d");
  const [typeFilter, setTypeFilter] = useState("all");
  const { events, aggregates, isLoading, refetch } = useWanguardAttacks(period);

  const attackTypes = useMemo(
    () => aggregates.typeStats.filter((s) => s.count > 0).map((s) => s.type),
    [aggregates.typeStats]
  );

  const filteredAlerts = useMemo(() => {
    if (typeFilter === "all") return aggregates.highVolumeAlerts;
    return aggregates.highVolumeAlerts.filter((a) => a.attackType === typeFilter);
  }, [aggregates.highVolumeAlerts, typeFilter]);

  useEffect(() => setTypeFilter("all"), [period]);

  const PERIOD_OPTIONS: { value: PeriodOption; label: string }[] = [
    { value: "24h", label: "Últimas 24h" },
    { value: "7d", label: "Últimos 7 dias" },
    { value: "30d", label: "Últimos 30 dias" },
  ];

  return (
    <div className="mb-6 space-y-4">
      {/* Filtros animados */}
      <motion.div
        initial={{ opacity: 0, y: -15 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex items-center gap-2 flex-wrap"
      >
        {PERIOD_OPTIONS.map((p, i) => (
          <motion.div
            key={p.value}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: i * 0.05 }}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.98 }}
          >
            <Button
              size="sm"
              variant={period === p.value ? "default" : "outline"}
              onClick={() => setPeriod(p.value)}
            >
              {p.label}
            </Button>
          </motion.div>
        ))}
        {attackTypes.length > 1 && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="h-8 rounded-md border border-border bg-background px-2 text-sm text-foreground transition-all duration-200 focus:ring-2 focus:ring-primary/30 focus:border-primary"
            >
              <option value="all">Todos os tipos</option>
              {attackTypes.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </motion.div>
        )}
        {typeFilter !== "all" && (
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ type: "spring", stiffness: 500, damping: 30 }}
          >
            <Badge variant="secondary" className="text-xs">
              1 filtro ativo
            </Badge>
          </motion.div>
        )}
      </motion.div>

      {isLoading ? (
        <div className="space-y-3 py-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-20 rounded-lg bg-muted animate-pulse relative overflow-hidden">
              <div
                className="absolute inset-0 -translate-x-full animate-[shimmer_2s_infinite]"
                style={{ background: "linear-gradient(90deg, transparent, hsl(var(--muted) / 0.3), transparent)" }}
              />
            </div>
          ))}
        </div>
      ) : (
        <AnimatePresence mode="wait">
          <motion.div
            key={`${period}-${typeFilter}`}
            initial={{ opacity: 0, x: 15 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -15 }}
            transition={{ duration: 0.25 }}
          >
            <HighVolumeAlertsCard alerts={filteredAlerts} />
          </motion.div>
        </AnimatePresence>
      )}
    </div>
  );
}

const Index = () => {
  const { user, permissions } = useAuthContext();

  const { dados, alertas, adicionarAsn, removerAsn, carregando, atualizar } = useNetworkMonitor();

  const {
    dados: competitorDados,
    carregando: competitorCarregando,
    atualizar: atualizarConcorrentes,
  } = useCompetitorMonitor();

  const lastAlertIdRef = useRef<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [novoAsn, setNovoAsn] = useState("");
  const [adicionando, setAdicionando] = useState(false);
  const [atualizando, setAtualizando] = useState(false);

  const [riskMap, setRiskMap] = useState<Record<string, RiskData>>({});
  const [riskLoaded, setRiskLoaded] = useState(false);
  const [competitorRiskMap, setCompetitorRiskMap] = useState<Record<string, RiskData>>({});
  const [competitorRiskLoaded, setCompetitorRiskLoaded] = useState(false);
  const [activeTab, setActiveTab] = useState("visao-geral");

  const handleAtualizar = async () => {
    setAtualizando(true);
    try {
      await atualizar();
      loadAllRisks(dados.map(d => d.metrics.asn));
      toast.success("Dados atualizados");
    } catch {
      toast.error("Erro ao atualizar");
    } finally {
      setAtualizando(false);
    }
  };

  useEffect(() => {
    const latest = alertas[0];
    if (!latest || latest.id === lastAlertIdRef.current) return;
    lastAlertIdRef.current = latest.id;

    if (latest.tipo === "ataque_detectado") {
      toast.error(latest.mensagem, { description: latest.timestamp.toLocaleTimeString("pt-BR") });
    } else if (latest.tipo === "alerta") {
      toast.warning(latest.mensagem);
    } else if (latest.tipo === "recuperado") {
      toast.success(latest.mensagem);
    }
  }, [alertas]);

  const loadAllRisks = async (asns: string[]) => {
    const results = await Promise.all(
      asns.map(async (asn) => {
        const risk = await fetchRiskForAsn(asn);
        return { asn, risk };
      })
    );
    const map: Record<string, RiskData> = {};
    for (const { asn, risk } of results) {
      if (risk) map[asn] = risk;
    }
    setRiskMap(map);
    setRiskLoaded(true);
  };

  useEffect(() => {
    if (dados.length > 0 && !riskLoaded) {
      loadAllRisks(dados.map(d => d.metrics.asn));
    }
  }, [dados, riskLoaded]);

  useEffect(() => {
    if (competitorDados.length > 0 && !competitorRiskLoaded) {
      (async () => {
        const results = await Promise.all(
          competitorDados.map(async (d) => {
            const risk = await fetchRiskForAsn(d.metrics.asn);
            return { asn: d.metrics.asn, risk };
          })
        );
        const map: Record<string, RiskData> = {};
        for (const { asn, risk } of results) {
          if (risk) map[asn] = risk;
        }
        setCompetitorRiskMap(map);
        setCompetitorRiskLoaded(true);
      })();
    }
  }, [competitorDados, competitorRiskLoaded]);

  const sortedDados = useMemo(() => {
    return [...dados].sort((a, b) => {
      const riskA = riskMap[a.metrics.asn]?.risk_score ?? 0;
      const riskB = riskMap[b.metrics.asn]?.risk_score ?? 0;
      return riskB - riskA;
    });
  }, [dados, riskMap]);

  const sortedCompetitorDados = useMemo(() => {
    return [...competitorDados].sort((a, b) => {
      const riskA = competitorRiskMap[a.metrics.asn]?.risk_score ?? 0;
      const riskB = competitorRiskMap[b.metrics.asn]?.risk_score ?? 0;
      return riskB - riskA;
    });
  }, [competitorDados, competitorRiskMap]);

  const { countHigh, countMedium, countLow } = useMemo(() => {
    let high = 0, medium = 0, low = 0;
    for (const d of dados) {
      const label = riskMap[d.metrics.asn]?.risk_label;
      if (label === "HIGH") high++;
      else if (label === "MEDIUM") medium++;
      else if (label === "LOW") low++;
    }
    return { countHigh: high, countMedium: medium, countLow: low };
  }, [dados, riskMap]);

  const handleAdicionarAsn = async () => {
    const valor = novoAsn.trim();
    if (!valor) return;
    setAdicionando(true);
    try {
      await adicionarAsn(valor);
      toast.success(`ASN ${valor} adicionado com sucesso`);
      setNovoAsn("");
      setDialogOpen(false);
    } catch (err: any) {
      toast.error(err.message || "Erro ao adicionar ASN");
    } finally {
      setAdicionando(false);
    }
  };

  if (carregando) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: [0.4, 1, 0.4] }}
          transition={{ duration: 1.5, repeat: Infinity }}
          className="text-muted-foreground text-lg"
        >
          Carregando dados dos ASNs...
        </motion.p>
      </div>
    );
  }

  const tabs = [
    { value: "visao-geral", label: "Visão Geral", resource: "tab:visao-geral" },
    { value: "concorrentes", label: "Concorrentes", resource: "tab:concorrentes" },
    { value: "eventos-alertas", label: "Eventos/Alertas", resource: "tab:eventos-alertas" },
    { value: "inteligencia-ti", label: "Inteligência TI", resource: "tab:inteligencia-ti" },
    { value: "wanguard", label: "Wanguard", resource: "tab:wanguard" },
    { value: "configuracoes", label: "Configurações", resource: "tab:configuracoes" },
  ];

  const visibleTabs = tabs.filter(t => permissions.hasAccess(t.resource));
  const defaultTab = visibleTabs[0]?.value ?? "visao-geral";

  const tabDescriptions: Record<string, string> = {
    "visao-geral": "Visão consolidada de todos os ASNs que você monitora, com o nível de risco atual, tendências recentes e principais destaques de segurança do ambiente.",
    "concorrentes": "Monitoramento dedicado dos ASNs estratégicos de concorrentes, com comparação de risco, volume de eventos e detecção de possíveis ataques simultâneos.",
    "eventos-alertas": "Linha do tempo dos principais eventos e alertas de segurança, destacando períodos de ataque, picos de atividade suspeita e correlações relevantes.",
    "inteligencia-ti": "Métricas de reputação de IP e ASN com base em fontes externas (AbuseIPDB, GreyNoise), detalhando score de abuso, IPs críticos e indicadores de ameaça.",
    "wanguard": "Visão consolidada dos ataques detectados pelo Wanguard, com análise de níveis, periodicidade, volume e blocos mais visados, para identificação de padrões de ataque.",
    "configuracoes": "Área de configuração do monitoramento: gerenciamento de ASNs, parâmetros de detecção, integrações de inteligência e ajustes avançados do painel.",
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="min-h-screen bg-background"
    >
      <DashboardHeader />
      <main className="max-w-7xl mx-auto w-full px-3 md:px-4 py-4 md:py-6 space-y-4 md:space-y-6">
        <SummaryCards dados={dados} loading={carregando} />

        <Tabs defaultValue={defaultTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="mb-2 flex-wrap relative">
            {visibleTabs.map(t => (
              <TabsTrigger key={t.value} value={t.value} className="relative">
                {t.label}
                {activeTab === t.value && (
                  <motion.div
                    layoutId="activeTabUnderline"
                    className="absolute bottom-0 left-0 right-0 h-0.5 bg-primary rounded-full"
                    transition={{ type: "spring", stiffness: 500, damping: 30 }}
                  />
                )}
              </TabsTrigger>
            ))}
          </TabsList>

          <AnimatePresence mode="wait">
            {tabDescriptions[activeTab] && (
              <motion.p
                key={`desc-${activeTab}`}
                initial={{ opacity: 0, y: -5 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -5 }}
                transition={{ duration: 0.2, delay: 0.1 }}
                className="text-sm text-muted-foreground mb-4"
              >
                {tabDescriptions[activeTab]}
              </motion.p>
            )}
          </AnimatePresence>

          {/* ═══ ABA: VISÃO GERAL ═══ */}
          {permissions.hasAccess("tab:visao-geral") && (
            <TabsContent value="visao-geral" className="mt-0">
              <motion.div
                key="visao-geral"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3 }}
                className="space-y-4 md:space-y-6"
              >
                <div className="flex items-center justify-between gap-2">
                  <h2 className="text-base md:text-lg font-semibold text-foreground">ASNs Monitorados</h2>
                  <div className="flex items-center gap-2">
                    <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.98 }}>
                      <Button size="sm" variant="outline" className="gap-1.5" onClick={handleAtualizar} disabled={atualizando}>
                        <RefreshCw className={cn("h-4 w-4", atualizando && "animate-spin")} /> Atualizar
                      </Button>
                    </motion.div>
                    {permissions.hasAccess("tab:configuracoes") && (
                      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
                        <DialogTrigger asChild>
                          <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.98 }}>
                            <Button size="sm" className="gap-1.5">
                              <Plus className="h-4 w-4" /> Adicionar ASN
                            </Button>
                          </motion.div>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-md">
                          <DialogHeader>
                            <DialogTitle>Adicionar ASN ao monitoramento</DialogTitle>
                          </DialogHeader>
                          <div className="space-y-4">
                            <div>
                              <Input
                                placeholder="Ex: 268538 ou AS268538"
                                value={novoAsn}
                                onChange={(e) => setNovoAsn(e.target.value)}
                                onKeyDown={(e) => e.key === "Enter" && handleAdicionarAsn()}
                                maxLength={20}
                              />
                              <p className="text-xs text-muted-foreground mt-1.5">
                                Digite o número do ASN que deseja monitorar
                              </p>
                            </div>
                            <Button onClick={handleAdicionarAsn} disabled={adicionando || !novoAsn.trim()} className="w-full">
                              {adicionando ? "Adicionando..." : "Adicionar"}
                            </Button>
                          </div>
                        </DialogContent>
                      </Dialog>
                    )}
                  </div>
                </div>

                {riskLoaded && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.2 }}
                  >
                    <p className="text-xs text-muted-foreground mb-2">
                      Ordenado por risco estimado (decrescente, últimas 2h)
                    </p>
                    <div className="flex flex-wrap items-center gap-2 text-xs mb-3">
                      <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-muted text-muted-foreground">
                        <span className="w-2 h-2 rounded-full bg-neon-red" />
                        Risco alto: {countHigh}
                      </span>
                      <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-muted text-muted-foreground">
                        <span className="w-2 h-2 rounded-full bg-orange-400" />
                        Risco médio: {countMedium}
                      </span>
                      <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-muted text-muted-foreground">
                        <span className="w-2 h-2 rounded-full bg-neon-yellow" />
                        Risco baixo: {countLow}
                      </span>
                    </div>
                  </motion.div>
                )}

                {sortedDados.length === 0 ? (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="text-center py-16"
                  >
                    <motion.div animate={{ scale: [1, 1.1, 1] }} transition={{ duration: 2, repeat: Infinity }}>
                      <SearchX className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
                    </motion.div>
                    <p className="text-muted-foreground">Nenhum ASN monitorado ainda.</p>
                    <p className="text-xs text-muted-foreground mt-1">Use "Adicionar ASN" para começar.</p>
                  </motion.div>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3 md:gap-4">
                    {sortedDados.map((d, i) => (
                      <motion.div
                        key={d.metrics.asn}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.35, delay: i * 0.08 }}
                        layout
                      >
                        <ASNCard
                          dados={d}
                          externalRiskData={riskMap[d.metrics.asn] ?? null}
                          highlightHigh
                          onRemoverAsn={async (asn) => {
                            try { await removerAsn(asn); toast.success(`${asn} removido`); } catch { toast.error("Erro ao remover ASN"); }
                          }}
                        />
                      </motion.div>
                    ))}
                  </div>
                )}

                <InstabilityRanking dados={dados} />
                <AsnHistoryChart asns={dados.map(d => d.metrics.asn)} />
              </motion.div>
            </TabsContent>
          )}

          {/* ═══ ABA: CONCORRENTES ═══ */}
          {permissions.hasAccess("tab:concorrentes") && (
            <TabsContent value="concorrentes" className="mt-0">
              <motion.div
                key="concorrentes"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3 }}
                className="space-y-4 md:space-y-6"
              >
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <h2 className="text-base md:text-lg font-semibold text-foreground">ASNs Concorrentes</h2>
                    <p className="text-xs text-muted-foreground mt-1">
                      Monitoramento focado: AS268538 (Conecta Network), AS267530 (TJ Telecom), AS268726 (TOPNET)
                    </p>
                  </div>
                  <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.98 }}>
                    <Button
                      size="sm"
                      variant="outline"
                      className="gap-1.5"
                      onClick={async () => {
                        try { await atualizarConcorrentes(); toast.success("Concorrentes atualizados"); } catch { toast.error("Erro ao atualizar"); }
                      }}
                    >
                      <RefreshCw className="h-4 w-4" /> Atualizar
                    </Button>
                  </motion.div>
                </div>

                {competitorCarregando ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <p className="animate-pulse">Carregando dados dos concorrentes...</p>
                  </div>
                ) : sortedCompetitorDados.length === 0 ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <p>Nenhum dado de concorrente disponível no momento.</p>
                    <p className="text-xs mt-1">Os dados serão carregados automaticamente.</p>
                  </div>
                ) : (
                  <>
                    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3 md:gap-4">
                      {sortedCompetitorDados.map((d, i) => (
                        <motion.div
                          key={d.metrics.asn}
                          initial={{ opacity: 0, y: 20 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ duration: 0.35, delay: i * 0.08 }}
                          layout
                        >
                          <ASNCard
                            dados={d}
                            externalRiskData={competitorRiskMap[d.metrics.asn] ?? null}
                            highlightHigh
                            onRemoverAsn={() => {}}
                          />
                        </motion.div>
                      ))}
                    </div>
                    <AsnHistoryChart asns={sortedCompetitorDados.map(d => d.metrics.asn)} />
                  </>
                )}
              </motion.div>
            </TabsContent>
          )}

          {/* ═══ ABA: EVENTOS/ALERTAS ═══ */}
          {permissions.hasAccess("tab:eventos-alertas") && (
            <TabsContent value="eventos-alertas" className="mt-0">
              <motion.div
                key="eventos-alertas"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3 }}
              >
                <EventosAlertasContent />
                <AlertsHistory />
              </motion.div>
            </TabsContent>
          )}

          {/* ═══ ABA: INTELIGÊNCIA DE AMEAÇAS ═══ */}
          {permissions.hasAccess("tab:inteligencia-ti") && (
            <TabsContent value="inteligencia-ti" className="mt-0">
              <motion.div
                key="inteligencia-ti"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3 }}
              >
                <AsnTiReputation />
              </motion.div>
            </TabsContent>
          )}

          {/* ═══ ABA: WANGUARD ═══ */}
          {permissions.hasAccess("tab:wanguard") && (
            <TabsContent value="wanguard" className="mt-0">
              <motion.div
                key="wanguard"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3 }}
              >
                <WanguardTab />
              </motion.div>
            </TabsContent>
          )}

          {/* ═══ ABA: CONFIGURAÇÕES ═══ */}
          {permissions.hasAccess("tab:configuracoes") && (
            <TabsContent value="configuracoes" className="mt-0">
              <motion.div
                key="configuracoes"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3 }}
                className="space-y-6"
              >
                <div>
                  <h2 className="text-base md:text-lg font-semibold text-foreground">Configurações</h2>
                  <p className="text-xs text-muted-foreground mt-1">
                    Configurações de notificação e monitoramento
                  </p>
                </div>
                <ApiStatusMonitor />
                <TelegramSettings />
              </motion.div>
            </TabsContent>
          )}
        </Tabs>
      </main>
    </motion.div>
  );
};

export default Index;
