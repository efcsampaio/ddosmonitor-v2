import { useState, useEffect } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { toast } from "sonner";
import { Send, Settings, Loader2 } from "lucide-react";

interface TelegramConfig {
  id?: string;
  chat_id: string;
  enabled: boolean;
  notify_attacks: boolean;
  notify_warnings: boolean;
  notify_recovery: boolean;
}

export function TelegramSettings() {
  const [config, setConfig] = useState<TelegramConfig>({
    chat_id: "",
    enabled: true,
    notify_attacks: true,
    notify_warnings: false,
    notify_recovery: true,
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    loadConfig();
  }, []);

  async function loadConfig() {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return;

      const { data, error } = await supabase
        .from("telegram_config")
        .select("*")
        .eq("user_id", user.id)
        .maybeSingle();

      if (data && !error) {
        setConfig({
          id: data.id,
          chat_id: data.chat_id,
          enabled: data.enabled,
          notify_attacks: data.notify_attacks,
          notify_warnings: data.notify_warnings,
          notify_recovery: data.notify_recovery,
        });
      }
    } catch (err) {
      console.error("Error loading telegram config:", err);
    } finally {
      setLoading(false);
    }
  }

  async function handleSave() {
    if (!config.chat_id.trim()) {
      toast.error("Informe o Chat ID do Telegram");
      return;
    }

    setSaving(true);
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error("Não autenticado");

      const payload = {
        user_id: user.id,
        chat_id: config.chat_id.trim(),
        enabled: config.enabled,
        notify_attacks: config.notify_attacks,
        notify_warnings: config.notify_warnings,
        notify_recovery: config.notify_recovery,
      };

      if (config.id) {
        const { error } = await supabase
          .from("telegram_config")
          .update(payload)
          .eq("id", config.id);
        if (error) throw error;
      } else {
        const { data, error } = await supabase
          .from("telegram_config")
          .insert(payload)
          .select()
          .single();
        if (error) throw error;
        setConfig(prev => ({ ...prev, id: data.id }));
      }

      toast.success("Configuração do Telegram salva!");
    } catch (err: any) {
      toast.error(err.message || "Erro ao salvar configuração");
    } finally {
      setSaving(false);
    }
  }

  async function handleTest() {
    if (!config.chat_id.trim()) {
      toast.error("Informe o Chat ID primeiro");
      return;
    }

    setTesting(true);
    try {
      const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
      const { data: { session } } = await supabase.auth.getSession();
      const response = await fetch(`${supabaseUrl}/functions/v1/telegram-notify/test`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
          ...(session?.access_token ? { "Authorization": `Bearer ${session.access_token}` } : {}),
        },
        body: JSON.stringify({ chat_id: config.chat_id.trim() }),
      });

      const data = await response.json();
      if (data.ok) {
        toast.success("Mensagem de teste enviada! Verifique seu Telegram.");
      } else {
        toast.error("Falha ao enviar mensagem. Verifique o Chat ID.");
      }
    } catch {
      toast.error("Erro ao enviar mensagem de teste");
    } finally {
      setTesting(false);
    }
  }

  if (loading) {
    return (
      <Card className="border-border/50">
        <CardContent className="p-6 flex items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-border/50">
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-lg">
          <Send className="h-5 w-5 text-primary" />
          Notificações Telegram
        </CardTitle>
        <CardDescription>
          Receba alertas de incidentes diretamente no Telegram. Para obter seu Chat ID,
          envie <code>/start</code> para o bot <strong>@userinfobot</strong> no Telegram.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="space-y-2">
          <Label htmlFor="chat-id">Chat ID</Label>
          <div className="flex gap-2">
            <Input
              id="chat-id"
              placeholder="Ex: 123456789 ou -100..."
              value={config.chat_id}
              onChange={(e) => setConfig(prev => ({ ...prev, chat_id: e.target.value }))}
            />
            <Button
              variant="outline"
              size="sm"
              onClick={handleTest}
              disabled={testing || !config.chat_id.trim()}
              className="shrink-0"
            >
              {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
              <span className="ml-1 hidden sm:inline">Testar</span>
            </Button>
          </div>
        </div>

        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label htmlFor="enabled" className="cursor-pointer">Ativar notificações</Label>
            <Switch
              id="enabled"
              checked={config.enabled}
              onCheckedChange={(v) => setConfig(prev => ({ ...prev, enabled: v }))}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="attacks" className="cursor-pointer">🚨 Ataques DDoS</Label>
            <Switch
              id="attacks"
              checked={config.notify_attacks}
              onCheckedChange={(v) => setConfig(prev => ({ ...prev, notify_attacks: v }))}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="warnings" className="cursor-pointer">⚠️ Alertas (warnings)</Label>
            <Switch
              id="warnings"
              checked={config.notify_warnings}
              onCheckedChange={(v) => setConfig(prev => ({ ...prev, notify_warnings: v }))}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="recovery" className="cursor-pointer">✅ Recuperação</Label>
            <Switch
              id="recovery"
              checked={config.notify_recovery}
              onCheckedChange={(v) => setConfig(prev => ({ ...prev, notify_recovery: v }))}
            />
          </div>
        </div>

        <Button onClick={handleSave} disabled={saving} className="w-full">
          {saving ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Settings className="h-4 w-4 mr-2" />}
          Salvar Configuração
        </Button>
      </CardContent>
    </Card>
  );
}
