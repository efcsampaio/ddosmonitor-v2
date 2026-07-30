/**
 * Hook central de permissões por role.
 *
 * Roles mapeados:
 *   - "admin"     → ADMIN      — Acesso total (todas abas, páginas, configurações, gestão de usuários)
 *   - "moderator" → ANALISTA   — Visão Geral, Concorrentes, Inteligência de Ameaças, Histórico, Métricas
 *   - "user"      → OPERADOR   — Visão Geral, Eventos/Alertas, Histórico
 *
 * Para adicionar um novo role:
 *   1. Adicionar o valor no enum app_role do banco (ALTER TYPE app_role ADD VALUE 'novo_role')
 *   2. Adicionar a entrada em ROLE_LABELS e ROLE_PERMISSIONS abaixo
 *   3. Atribuir o role ao usuário via tabela user_roles
 *
 * Para vincular um usuário a um role:
 *   INSERT INTO user_roles (user_id, role) VALUES ('<uuid>', 'admin');
 *   Ou pela tela de Gestão de Usuários (menu "Usuários")
 *
 * Master admin ("master_admin" em user_roles) é verificado via a RPC
 * is_master_admin() — não existe mais fallback por username hardcoded.
 */
import { useState, useEffect } from "react";
import { supabase } from "@/integrations/supabase/client";
import type { User } from "@supabase/supabase-js";

export type AppRole = "admin" | "moderator" | "user";

/** Labels amigáveis para exibição no frontend */
export const ROLE_LABELS: Record<AppRole, string> = {
  admin: "Admin",
  moderator: "Analista",
  user: "Operador",
};

/** Descrições dos roles para a tela de gestão */
export const ROLE_DESCRIPTIONS: Record<AppRole, string> = {
  admin: "Acesso total ao sistema, gestão de usuários, configurações, todas as abas",
  moderator: "Visão Geral, Concorrentes, Inteligência de Ameaças, Histórico, Métricas",
  user: "Visão Geral, Eventos/Alertas, Histórico",
};

/**
 * Páginas/abas do sistema e quais roles podem acessá-las.
 * Para adicionar uma nova página, basta adicionar a chave e os roles permitidos.
 */
export const ROLE_PERMISSIONS: Record<string, AppRole[]> = {
  // Abas da página principal
  "tab:visao-geral": ["admin", "moderator", "user"],
  "tab:concorrentes": ["admin", "moderator"],
  "tab:eventos-alertas": ["admin", "user"],
  "tab:inteligencia-ti": ["admin", "moderator"],
  "tab:wanguard": ["admin", "moderator"],
  "tab:configuracoes": ["admin"],

  // Páginas/rotas
  "page:home": ["admin", "moderator", "user"],
  "page:incidents": ["admin", "moderator", "user"],
  "page:metricas": ["admin", "moderator"],
  "page:comparativo-k2": ["admin", "moderator"],
  "page:users": ["admin"],
};

export interface PermissionsState {
  role: AppRole | null;
  roleLabel: string;
  isMasterAdmin: boolean;
  loading: boolean;
  /** Verifica se o usuário tem acesso a uma página ou aba */
  hasAccess: (resource: string) => boolean;
}

export function usePermissions(user: User | null): PermissionsState {
  const [role, setRole] = useState<AppRole | null>(null);
  const [isMasterAdmin, setIsMasterAdmin] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user) {
      setRole(null);
      setIsMasterAdmin(false);
      setLoading(false);
      return;
    }

    let cancelled = false;

    async function loadRole() {
      // Carrega role e verifica master admin em paralelo.
      // is_master_admin() é a única fonte de verdade — antes havia um
      // fallback "|| profiles.username === 'edson'" que foi removido.
      const [roleResult, masterResult] = await Promise.all([
        supabase.from("user_roles").select("role").eq("user_id", user!.id).maybeSingle(),
        supabase.rpc("is_master_admin"),
      ]);

      if (cancelled) return;

      const userRole = (roleResult.data?.role as AppRole) || "user";
      const isMaster = !!masterResult.data;

      // Master admin sempre tem role admin
      setRole(isMaster ? "admin" : userRole);
      setIsMasterAdmin(isMaster);
      setLoading(false);
    }

    loadRole();
    return () => { cancelled = true; };
  }, [user]);

  const hasAccess = (resource: string): boolean => {
    if (isMasterAdmin) return true; // Master admin tem acesso total
    if (!role) return false;
    const allowedRoles = ROLE_PERMISSIONS[resource];
    if (!allowedRoles) return true; // Recurso sem restrição → liberado
    return allowedRoles.includes(role);
  };

  return {
    role,
    roleLabel: role ? ROLE_LABELS[role] : "Sem role",
    isMasterAdmin,
    loading,
    hasAccess,
  };
}
