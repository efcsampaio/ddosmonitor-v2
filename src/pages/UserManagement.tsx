import { useState, useEffect } from "react";
import { DashboardHeader } from "@/components/DashboardHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { supabase } from "@/integrations/supabase/client";
import { useAuthContext } from "@/App";
import { Navigate } from "react-router-dom";
import { toast } from "sonner";
import { UserPlus, Shield, ShieldCheck, ShieldAlert, Key } from "lucide-react";
import { ROLE_LABELS, ROLE_DESCRIPTIONS } from "@/hooks/usePermissions";

type AppRole = "admin" | "moderator" | "user";

interface UserProfile {
  id: string;
  username: string;
  display_name: string | null;
  created_at: string;
  must_change_password: boolean;
  role: AppRole | null;
  isMasterAdmin: boolean;
}

function generateDefaultPassword(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  let pwd = "";
  for (let i = 0; i < 10; i++) pwd += chars[Math.floor(Math.random() * chars.length)];
  return pwd;
}

export default function UserManagement() {
  const { user, permissions } = useAuthContext();
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState(generateDefaultPassword());
  const [newRole, setNewRole] = useState<AppRole>("user");
  const [creating, setCreating] = useState(false);

  const loadUsers = async () => {
    setLoading(true);
    const { data: profiles } = await supabase.from("profiles").select("*");
    const { data: roles } = await supabase.from("user_roles").select("*");
    if (profiles) {
      const usersWithRoles = profiles.map((p) => {
        const userRoles = roles?.filter((r) => r.user_id === p.id) || [];
        // "master_admin" é o superusuário — guardado como um role à parte,
        // não é um dos níveis atribuíveis (admin/moderator/user).
        const isMasterAdmin = userRoles.some((r) => r.role === "master_admin");
        const assignableRole = userRoles.find((r) => r.role !== "master_admin");
        return { ...p, role: (assignableRole?.role as AppRole) || null, isMasterAdmin };
      });
      setUsers(usersWithRoles);
    }
    setLoading(false);
  };

  useEffect(() => {
    if (!permissions.loading && permissions.hasAccess("page:users")) loadUsers();
  }, [permissions.loading]);

  if (permissions.loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <p className="text-muted-foreground animate-pulse">Carregando...</p>
      </div>
    );
  }

  if (!permissions.hasAccess("page:users")) {
    return <Navigate to="/" replace />;
  }


  const handleCreateUser = async () => {
    if (!newUsername.trim() || !newPassword.trim()) return;
    setCreating(true);
    try {
      const email = `${newUsername.trim().toLowerCase()}@monitor.local`;
      const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
      const { data: { session } } = await supabase.auth.getSession();

      const res = await fetch(`${supabaseUrl}/functions/v1/asn-monitor/admin/create-user`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
          "authorization": `Bearer ${session?.access_token}`,
        },
        body: JSON.stringify({ username: newUsername.trim(), password: newPassword, role: newRole }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `Erro ao criar usuário (HTTP ${res.status})`);
      }

      toast.success(`Usuário ${newUsername} criado com sucesso`);
      setNewUsername("");
      setNewPassword(generateDefaultPassword());
      setNewRole("user");
      setDialogOpen(false);
      setTimeout(loadUsers, 1000);
    } catch (err: any) {
      toast.error(err.message);
    } finally {
      setCreating(false);
    }
  };

  const handleChangeRole = async (userId: string, newRole: AppRole) => {
    try {
      const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
      const { data: { session } } = await supabase.auth.getSession();

      const res = await fetch(`${supabaseUrl}/functions/v1/asn-monitor/admin/update-role`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
          "authorization": `Bearer ${session?.access_token}`,
        },
        body: JSON.stringify({ userId, role: newRole }),
      });

      if (!res.ok) throw new Error("Erro ao atualizar role");
      toast.success("Permissão atualizada");
      loadUsers();
    } catch (err: any) {
      toast.error(err.message);
    }
  };

  const handleResetPassword = async (userId: string, username: string) => {
    try {
      const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
      const { data: { session } } = await supabase.auth.getSession();

      const res = await fetch(`${supabaseUrl}/functions/v1/asn-monitor/admin/reset-password`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
          "authorization": `Bearer ${session?.access_token}`,
        },
        body: JSON.stringify({ userId }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `Erro ao resetar senha (HTTP ${res.status})`);
      }
      // O backend agora gera uma senha temporária aleatória a cada reset
      // (antes era sempre "Monitor@2026!") — precisa ser exibida aqui,
      // já que não existe envio por e-mail configurado.
      const data = await res.json().catch(() => ({} as { tempPassword?: string }));
      if (data.tempPassword) {
        toast.success(`Senha de ${username} resetada. Nova senha temporária: ${data.tempPassword}`, {
          duration: 20000,
        });
      } else {
        toast.success(`Senha de ${username} resetada`);
      }
      loadUsers();
    } catch (err: any) {
      toast.error(err.message);
    }
  };

  const roleIcon = (role: AppRole | null) => {
    switch (role) {
      case "admin": return <ShieldAlert className="h-4 w-4 text-neon-red" />;
      case "moderator": return <ShieldCheck className="h-4 w-4 text-neon-yellow" />;
      default: return <Shield className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const roleBadge = (role: AppRole | null) => {
    switch (role) {
      case "admin": return <Badge className="bg-red-500/20 text-red-400 border-red-500/30">{ROLE_LABELS.admin}</Badge>;
      case "moderator": return <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">{ROLE_LABELS.moderator}</Badge>;
      default: return <Badge variant="secondary">{ROLE_LABELS.user}</Badge>;
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <DashboardHeader />
      <main className="max-w-5xl mx-auto px-4 py-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold text-foreground">Gestão de Usuários</h2>
            <p className="text-sm text-muted-foreground">Gerenciar acessos e permissões do sistema</p>
          </div>
          <Dialog
            open={dialogOpen}
            onOpenChange={(open) => {
              setDialogOpen(open);
              if (open) setNewPassword(generateDefaultPassword());
            }}
          >
            <DialogTrigger asChild>
              <Button size="sm" className="gap-1.5">
                <UserPlus className="h-4 w-4" /> Novo Usuário
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle>Criar novo usuário</DialogTitle>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <label className="text-sm text-muted-foreground">Username</label>
                  <Input
                    placeholder="Ex: joao"
                    value={newUsername}
                    onChange={(e) => setNewUsername(e.target.value)}
                  />
                </div>
                <div>
                  <label className="text-sm text-muted-foreground">Senha inicial</label>
                  <Input
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground mt-1">Gerada automaticamente — pode editar. Será solicitada troca no primeiro login</p>
                </div>
                <div>
                  <label className="text-sm text-muted-foreground">Nível de acesso</label>
                  <Select value={newRole} onValueChange={(v) => setNewRole(v as AppRole)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="user">{ROLE_LABELS.user}</SelectItem>
                      <SelectItem value="moderator">{ROLE_LABELS.moderator}</SelectItem>
                      <SelectItem value="admin">{ROLE_LABELS.admin}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Button onClick={handleCreateUser} disabled={creating || !newUsername.trim()} className="w-full">
                  {creating ? "Criando..." : "Criar Usuário"}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Usuários do sistema</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <p className="text-muted-foreground text-sm animate-pulse">Carregando...</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Usuário</TableHead>
                    <TableHead>Nome</TableHead>
                    <TableHead>Nível</TableHead>
                    <TableHead>Criado em</TableHead>
                    <TableHead>Ações</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map((u) => (
                    <TableRow key={u.id}>
                      <TableCell className="font-medium">
                        <div className="flex items-center gap-2">
                          {u.isMasterAdmin ? <ShieldAlert className="h-4 w-4 text-neon-red" /> : roleIcon(u.role)}
                          {u.username}
                        </div>
                      </TableCell>
                      <TableCell>{u.display_name || "-"}</TableCell>
                      <TableCell>{u.isMasterAdmin ? <Badge className="bg-red-500/20 text-red-400 border-red-500/30">Master Admin</Badge> : roleBadge(u.role)}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(u.created_at).toLocaleDateString("pt-BR")}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {!u.isMasterAdmin && (
                            <>
                              <Select
                                value={u.role || "user"}
                                onValueChange={(v) => handleChangeRole(u.id, v as AppRole)}
                              >
                                <SelectTrigger className="w-32 h-8 text-xs">
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                   <SelectItem value="user">{ROLE_LABELS.user}</SelectItem>
                                   <SelectItem value="moderator">{ROLE_LABELS.moderator}</SelectItem>
                                   <SelectItem value="admin">{ROLE_LABELS.admin}</SelectItem>
                                </SelectContent>
                              </Select>
                              <Button
                                variant="outline"
                                size="sm"
                                className="h-8 gap-1 text-xs"
                                onClick={() => handleResetPassword(u.id, u.username)}
                              >
                                <Key className="h-3 w-3" /> Reset Senha
                              </Button>
                            </>
                          )}
                          {u.isMasterAdmin && (
                            <span className="text-xs text-muted-foreground italic">Master Admin</span>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Níveis de Acesso</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="flex items-start gap-3">
              <ShieldAlert className="h-5 w-5 text-neon-red mt-0.5" />
              <div>
                <p className="font-medium text-foreground">{ROLE_LABELS.admin}</p>
                <p className="text-muted-foreground">{ROLE_DESCRIPTIONS.admin}</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <ShieldCheck className="h-5 w-5 text-neon-yellow mt-0.5" />
              <div>
                <p className="font-medium text-foreground">{ROLE_LABELS.moderator}</p>
                <p className="text-muted-foreground">{ROLE_DESCRIPTIONS.moderator}</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <Shield className="h-5 w-5 text-muted-foreground mt-0.5" />
              <div>
                <p className="font-medium text-foreground">{ROLE_LABELS.user}</p>
                <p className="text-muted-foreground">{ROLE_DESCRIPTIONS.user}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
