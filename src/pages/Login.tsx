import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { Shield, Lock, User, Eye, EyeOff } from "lucide-react";
import { toast } from "sonner";
import loginBg from "@/assets/login-bg.jpg";

const AUTH_TIMEOUT_MS = 8000;
const SESSION_CHECK_TIMEOUT_MS = 2500;

async function withTimeout<T>(promise: PromiseLike<T>, timeoutMs: number, timeoutMessage: string): Promise<T> {
  return Promise.race([
    Promise.resolve(promise),
    new Promise<T>((_, reject) => {
      window.setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
    }),
  ]);
}

async function wait(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const navigate = useNavigate();

  const waitForRecoveredSession = async () => {
    for (let attempt = 0; attempt < 4; attempt += 1) {
      try {
        const { data } = await withTimeout(
          supabase.auth.getSession(),
          SESSION_CHECK_TIMEOUT_MS,
          "SESSION_TIMEOUT"
        );

        if (data.session) {
          return true;
        }
      } catch {
        // ignore and retry
      }

      await wait(750);
    }

    return false;
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) return;

    setLoading(true);
    try {
      const normalizedUsername = username.trim().toLowerCase();
      const candidateEmails = [
        `${normalizedUsername}@ddosmonitor.local`,
        `${normalizedUsername}@monitor.local`,
      ];

      let lastError: { message?: string; status?: number } | null = null;
      let authenticated = false;

      for (const email of candidateEmails) {
        const { error } = await withTimeout(
          supabase.auth.signInWithPassword({ email, password }),
          AUTH_TIMEOUT_MS,
          "AUTH_TIMEOUT"
        );

        if (!error) {
          authenticated = true;
          break;
        }

        lastError = error;
      }

      if (!authenticated) {
        const msg = lastError?.message?.includes("timeout") || lastError?.status === 504
          ? "Servidor temporariamente indisponível. Tente novamente em alguns segundos."
          : "Credenciais inválidas. Verifique seu usuário e senha.";
        toast.error(msg);
        return;
      }

      toast.success("Login realizado com sucesso!");
      navigate("/", { replace: true });
    } catch (error) {
      const recoveredSession = await waitForRecoveredSession();

      if (recoveredSession) {
        toast.success("Login realizado com sucesso!");
        navigate("/", { replace: true });
        return;
      }

      const msg = error instanceof Error && error.message === "AUTH_TIMEOUT"
        ? "A autenticação demorou demais para responder. Tente novamente em alguns segundos."
        : "Erro ao fazer login.";

      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex">
      {/* Left side — image */}
      <div className="hidden lg:flex lg:w-3/5 relative overflow-hidden">
        <img
          src={loginBg}
          alt="Cybersecurity background"
          className="absolute inset-0 w-full h-full object-cover"
          width={1920}
          height={1080}
        />
        <div className="absolute inset-0 bg-gradient-to-r from-background/90 via-background/40 to-transparent" />
        <div className="relative z-10 flex flex-col justify-end p-12">
          <p className="text-neon-green font-mono text-sm mb-2 tracking-widest uppercase">
            // Sistema de Monitoramento
          </p>
           <h2 className="text-4xl font-bold text-foreground leading-tight mb-3">
             DDoS Monitor
           </h2>
          <p className="text-muted-foreground max-w-md text-sm">
            Monitoramento BGP em tempo real com detecção de anomalias e análise de visibilidade de rede.
          </p>
        </div>
      </div>

      {/* Right side — login form */}
      <div className="flex-1 flex items-center justify-center bg-background p-8">
        <Card className="w-full max-w-md bg-card border-border p-8 space-y-6">
          <div className="text-center space-y-2">
            <div className="flex justify-center">
              <div className="p-3 rounded-full bg-primary/10 border border-primary/20">
                <Shield className="h-8 w-8 text-primary" />
              </div>
            </div>
            <h1 className="text-2xl font-bold text-foreground tracking-tight">
              Acesso Restrito
            </h1>
            <p className="text-sm text-muted-foreground">
              Insira suas credenciais para acessar o sistema
            </p>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Usuário</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Digite seu usuário"
                  className="pl-10"
                  autoComplete="username"
                  autoFocus
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Senha</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Digite sua senha"
                  className="pl-10 pr-10"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <Button type="submit" className="w-full" disabled={loading || !username.trim() || !password.trim()}>
              {loading ? "Autenticando..." : "Entrar"}
            </Button>
          </form>

          <div className="text-center">
            <p className="text-[10px] text-muted-foreground font-mono">
              DDoS Monitor v1.0 — Acesso autorizado apenas
            </p>
          </div>
        </Card>
      </div>
    </div>
  );
}
