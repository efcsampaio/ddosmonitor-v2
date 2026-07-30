import { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { Shield, History, LogOut, BarChart3, Users, Menu, GitCompareArrows, MonitorDot } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger, SheetTitle } from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { useAuthContext } from "@/App";
import { motion } from "motion/react";

interface NavItem {
  to: string;
  label: string;
  icon: React.ElementType;
  resource: string;
}

const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "ASNs Monitorados", icon: MonitorDot, resource: "page:home" },
  { to: "/incidents", label: "Histórico", icon: History, resource: "page:incidents" },
  { to: "/metricas", label: "Como Funciona", icon: BarChart3, resource: "page:metricas" },
  { to: "/comparativo-k2", label: "Comparativo K2", icon: GitCompareArrows, resource: "page:comparativo-k2" },
  { to: "/users", label: "Usuários", icon: Users, resource: "page:users" },
];

export function DashboardHeader() {
  const [hora, setHora] = useState(new Date());
  const [menuOpen, setMenuOpen] = useState(false);
  const { signOut, permissions } = useAuthContext();
  const location = useLocation();

  useEffect(() => {
    const t = setInterval(() => setHora(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const visibleItems = NAV_ITEMS.filter((item) => permissions.hasAccess(item.resource));

  const navLinks = (
    <>
      {visibleItems.map((item) => (
        <Link key={item.to} to={item.to} onClick={() => setMenuOpen(false)}>
          <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.98 }}>
            <Button
              variant={location.pathname === item.to ? "default" : "outline"}
              size="sm"
              className="gap-1.5 text-xs w-full justify-start"
            >
              <item.icon className="h-3.5 w-3.5" /> {item.label}
            </Button>
          </motion.div>
        </Link>
      ))}
      <motion.div whileTap={{ scale: 0.98 }}>
        <Button variant="ghost" size="sm" className="gap-1.5 text-xs text-muted-foreground hover:text-destructive w-full justify-start" onClick={signOut}>
          <LogOut className="h-3.5 w-3.5" /> Sair
        </Button>
      </motion.div>
    </>
  );

  return (
    <header className="border-b border-border">
      <div className="px-4 md:px-6 py-3 md:py-4 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 md:gap-3 min-w-0">
          <motion.div
            animate={{ rotate: [0, 5, -5, 0] }}
            transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
          >
            <Shield className="h-6 w-6 md:h-8 md:w-8 text-primary shrink-0" />
          </motion.div>
          <div className="min-w-0">
            <h1 className="text-sm md:text-xl font-bold text-foreground tracking-tight truncate">
              Monitor DDoS — SBC
            </h1>
            <p className="text-[10px] md:text-sm text-muted-foreground hidden sm:block">
              Monitoramento de rede em tempo real
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {permissions.role && (
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: "spring", stiffness: 500, damping: 30 }}
            >
              <Badge variant="outline" className="text-[10px] hidden md:inline-flex">
                {permissions.roleLabel}
              </Badge>
            </motion.div>
          )}

          <div className="text-right">
            <motion.div
              animate={{ opacity: [1, 0.7, 1] }}
              transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
              className="text-base md:text-2xl font-mono text-neon-cyan tabular-nums"
            >
              {hora.toLocaleTimeString("pt-BR")}
            </motion.div>
            <div className="text-xs text-muted-foreground hidden md:block">
              {hora.toLocaleDateString("pt-BR", { weekday: "long", day: "numeric", month: "long", year: "numeric" })}
            </div>
          </div>

          <div className="md:hidden">
            <Sheet open={menuOpen} onOpenChange={setMenuOpen}>
              <SheetTrigger asChild>
                <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                  <Menu className="h-5 w-5" />
                </Button>
              </SheetTrigger>
              <SheetContent side="right" className="w-64">
                <SheetTitle className="text-foreground">Menu</SheetTitle>
                <nav className="flex flex-col gap-2 mt-4">
                  {navLinks}
                </nav>
                <div className="mt-6 text-xs text-muted-foreground">
                  {permissions.role && <p className="mb-1">Nível: {permissions.roleLabel}</p>}
                  {hora.toLocaleDateString("pt-BR", { weekday: "long", day: "numeric", month: "long", year: "numeric" })}
                </div>
              </SheetContent>
            </Sheet>
          </div>
        </div>
      </div>

      <div className="hidden md:flex items-center gap-2 px-6 pb-3">
        {navLinks}
      </div>
    </header>
  );
}
