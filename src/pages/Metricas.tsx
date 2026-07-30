import { Link } from "react-router-dom";
import { ArrowLeft, BookOpen, Shield, Cpu, Globe, Clock, Brain } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

function Section({ icon: Icon, title, children }: { icon: React.ElementType; title: string; children: React.ReactNode }) {
  return (
    <Card className="bg-card border-border p-6 space-y-4">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
          <Icon className="h-5 w-5 text-primary" />
        </div>
        <h2 className="text-lg font-semibold text-foreground">{title}</h2>
      </div>
      <div className="text-sm text-muted-foreground leading-relaxed space-y-3">
        {children}
      </div>
    </Card>
  );
}

export default function Metricas() {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link to="/">
            <Button variant="ghost" size="sm" className="gap-1.5 text-xs">
              <ArrowLeft className="h-3.5 w-3.5" /> Voltar
            </Button>
          </Link>
          <Separator orientation="vertical" className="h-6" />
          <div className="flex items-center gap-2">
            <BookOpen className="h-5 w-5 text-primary" />
            <h1 className="text-lg font-bold text-foreground">Como Funciona</h1>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto p-6 space-y-6">

        {/* Bloco 1 – Intuito do aplicativo */}
        <Section icon={Shield} title="Intuito do Aplicativo">
          <p>
            Este painel monitora continuamente a superfície de ataque associada aos seus ASNs e aos ASNs de
            concorrentes estratégicos. A cada janela de tempo, ele coleta sinais externos de reputação, cruza
            com eventos observados e transforma tudo em uma visão clara de risco, alertas de ataques e
            comparativos entre você e o mercado.
          </p>
        </Section>

        {/* Bloco 2 – Arquitetura em alto nível */}
        <Section icon={Cpu} title="Arquitetura em Alto Nível">
          <p>O pipeline de dados segue estas etapas:</p>
          <ul className="list-disc ml-5 space-y-2 mt-2">
            <li>
              <strong className="text-foreground">Coleta de ASNs/IPs monitorados</strong> — os ASNs cadastrados pelo
              usuário (e os ASNs estratégicos de concorrentes) são consultados periodicamente. Para cada ASN, os
              prefixos IP são obtidos via RIPEstat e uma amostra de IPs é selecionada.
            </li>
            <li>
              <strong className="text-foreground">Enriquecimento com AbuseIPDB e GreyNoise</strong> — cada IP amostrado
              é consultado no AbuseIPDB (score de abuso, número de reports) e no GreyNoise (classificação de ruído,
              RIOT, malicioso). Os resultados são armazenados com cache independente (24h para AbuseIPDB, 7 dias para
              GreyNoise).
            </li>
            <li>
              <strong className="text-foreground">Cálculo de métricas por janela de 30 minutos</strong> — os dados
              individuais de IP são agregados por ASN em janelas de 30 minutos, gerando indicadores como
              <code className="bg-muted px-1 rounded text-xs mx-1">ti_abuse_avg_score</code>,
              <code className="bg-muted px-1 rounded text-xs mx-1">gn_malicious_ratio</code>,
              <code className="bg-muted px-1 rounded text-xs mx-1">ti_combined_score</code>, entre outros.
            </li>
            <li>
              <strong className="text-foreground">Armazenamento</strong> — os dados ficam nas tabelas
              <code className="bg-muted px-1 rounded text-xs mx-1">ip_reputation</code> (nível IP),
              <code className="bg-muted px-1 rounded text-xs mx-1">asn_ip_reputation_window</code> (agregados por janela) e
              <code className="bg-muted px-1 rounded text-xs mx-1">as_attack_samples</code> (feature vectors para detecção).
            </li>
          </ul>
        </Section>

        {/* Bloco 3 – APIs internas e integrações externas */}
        <Section icon={Globe} title="APIs Internas e Integrações Externas">
          <p className="font-medium text-foreground">Endpoints internos (Edge Functions):</p>
          <ul className="list-disc ml-5 space-y-2 mt-2">
            <li>
              <code className="bg-muted px-1 rounded text-xs">GET /asn-monitor/status</code> — retorna o status
              de todos os ASNs monitorados pelo usuário logado (risco, eventos, métricas).
            </li>
            <li>
              <code className="bg-muted px-1 rounded text-xs">GET /asn-monitor/status?asns=AS268538,AS267530,AS268726</code> — retorna
              o status dos ASNs de concorrentes estratégicos (sem filtro por usuário).
            </li>
            <li>
              <code className="bg-muted px-1 rounded text-xs">GET /asn-monitor/incidents</code> — histórico de
              incidentes registrados por ASN.
            </li>
            <li>
              <code className="bg-muted px-1 rounded text-xs">POST /estimate-attack-risk</code> — calcula o
              risco de ataque com base no feature vector da janela atual.
            </li>
          </ul>

          <p className="font-medium text-foreground mt-4">Integrações externas:</p>
          <ul className="list-disc ml-5 space-y-2 mt-2">
            <li>
              <strong className="text-foreground">AbuseIPDB</strong> — fonte primária de reputação de IP. Fornece
              score de abuso (0–100) e contagem de reports. Cache de 24 horas por IP.
            </li>
            <li>
              <strong className="text-foreground">GreyNoise</strong> — segunda fonte de inteligência de ameaças.
              Classifica IPs como noise, RIOT ou malicioso. Cache de 7 dias por IP.
            </li>
            <li>
              <strong className="text-foreground">RIPEstat Data API</strong> — dados BGP públicos: visibilidade,
              announcements/withdrawals, prefixos anunciados, vizinhos BGP.
            </li>
            <li>
              <strong className="text-foreground">Qrator Radar</strong> — análise de AS Paths para detecção de
              hijacks e route leaks.
            </li>
          </ul>
        </Section>

        {/* Bloco 4 – Rotinas agendadas */}
        <Section icon={Clock} title="Rotinas Agendadas">
          <p>
            O job principal é o <strong className="text-foreground">enrich-ip-reputation</strong>, executado
            automaticamente a cada 30 minutos pelo cron do sistema. Seu fluxo é:
          </p>
          <ol className="list-decimal ml-5 space-y-2 mt-2">
            <li>
              <strong className="text-foreground">Cálculo da janela</strong> — define automaticamente
              <code className="bg-muted px-1 rounded text-xs mx-1">window_start</code> e
              <code className="bg-muted px-1 rounded text-xs mx-1">window_end</code> com base no horário atual
              (janela de 30 minutos).
            </li>
            <li>
              <strong className="text-foreground">Seleção de IPs por ASN</strong> — para cada ASN monitorado,
              obtém os prefixos via RIPEstat e amostra IPs. ASNs estratégicos (concorrentes) recebem amostragem
              densa: até 30 IPs e 10 chamadas ao GreyNoise por ciclo.
            </li>
            <li>
              <strong className="text-foreground">Consulta AbuseIPDB</strong> — cada IP com cache expirado
              (&gt; 24h) é consultado na API. O resultado é salvo em
              <code className="bg-muted px-1 rounded text-xs mx-1">ip_reputation</code>.
            </li>
            <li>
              <strong className="text-foreground">Consulta GreyNoise</strong> — cada IP com cache GN expirado
              (&gt; 7 dias) é consultado. Os campos
              <code className="bg-muted px-1 rounded text-xs mx-1">gn_noise</code>,
              <code className="bg-muted px-1 rounded text-xs mx-1">gn_riot</code> e
              <code className="bg-muted px-1 rounded text-xs mx-1">gn_classification</code> são atualizados.
            </li>
            <li>
              <strong className="text-foreground">Agregação por janela</strong> — os dados de IP são agregados e
              gravados em
              <code className="bg-muted px-1 rounded text-xs mx-1">asn_ip_reputation_window</code>, incluindo
              ratios de ruído, malicioso e RIOT do GreyNoise, score médio de abuso e o
              <code className="bg-muted px-1 rounded text-xs mx-1">ti_combined_score</code>.
            </li>
          </ol>
        </Section>

        {/* Bloco 5 – Como funciona o aprendizado */}
        <Section icon={Brain} title="Como Funciona o Aprendizado">
          <p>
            O sistema aprende o comportamento "normal" de cada ASN observando múltiplas janelas consecutivas.
            Ao acumular dados históricos, ele constrói uma linha de base que permite identificar desvios
            significativos.
          </p>
          <ul className="list-disc ml-5 space-y-2 mt-2">
            <li>
              <strong className="text-foreground">Linha de base por ASN</strong> — a cada nova janela, os
              indicadores (score de abuso médio, ratios GreyNoise, contagem de eventos BGP) são comparados com o
              histórico recente do mesmo ASN.
            </li>
            <li>
              <strong className="text-foreground">Detecção de desvios</strong> — picos no score de abuso, aumento
              repentino de IPs classificados como maliciosos ou noise, e quedas de visibilidade BGP são
              identificados como anomalias.
            </li>
            <li>
              <strong className="text-foreground">Alertas inteligentes</strong> — quando um desvio ultrapassa os
              limiares configurados, o sistema gera alertas automáticos, incluindo notificações via Telegram.
            </li>
            <li>
              <strong className="text-foreground">Detecção de ataques simultâneos</strong> — ao monitorar os ASNs
              de concorrentes em paralelo, o sistema consegue detectar padrões de ataque coordenado (quando
              múltiplos ASNs da mesma região apresentam degradação simultânea).
            </li>
          </ul>
        </Section>

      </main>
    </div>
  );
}
