import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes, Navigate } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useAuth } from "@/hooks/useAuth";
import { usePermissions, type PermissionsState } from "@/hooks/usePermissions";
import Index from "./pages/Index.tsx";
import Login from "./pages/Login.tsx";
import ChangePassword from "./pages/ChangePassword.tsx";
import Incidents from "./pages/Incidents.tsx";
import Metricas from "./pages/Metricas.tsx";
import UserManagement from "./pages/UserManagement.tsx";
import ComparativoK2 from "./pages/ComparativoK2.tsx";
import NotFound from "./pages/NotFound.tsx";
import { createContext, useContext } from "react";

const queryClient = new QueryClient();

type AuthContextType = ReturnType<typeof useAuth> & { permissions: PermissionsState };
const AuthContext = createContext<AuthContextType | null>(null);
export const useAuthContext = () => useContext(AuthContext)!;

/**
 * Guard de rota: redireciona para "/" se o usuário não tem acesso ao recurso.
 * Uso: <ProtectedRoute resource="page:users"><UserManagement /></ProtectedRoute>
 */
function ProtectedRoute({ resource, children }: { resource: string; children: React.ReactNode }) {
  const { permissions } = useAuthContext();
  if (permissions.loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <p className="text-muted-foreground animate-pulse">Verificando permissões...</p>
      </div>
    );
  }
  if (!permissions.hasAccess(resource)) {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}

function AppRoutes() {
  const auth = useAuth();
  const permissions = usePermissions(auth.user);

  if (auth.loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <p className="text-muted-foreground animate-pulse">Carregando...</p>
      </div>
    );
  }

  if (!auth.user) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  if (auth.mustChangePassword) {
    return (
      <AuthContext.Provider value={{ ...auth, permissions }}>
        <Routes>
          <Route path="/change-password" element={<ChangePassword />} />
          <Route path="*" element={<Navigate to="/change-password" replace />} />
        </Routes>
      </AuthContext.Provider>
    );
  }

  return (
    <AuthContext.Provider value={{ ...auth, permissions }}>
      <Routes>
        <Route path="/" element={<Index />} />
        <Route path="/incidents" element={<ProtectedRoute resource="page:incidents"><Incidents /></ProtectedRoute>} />
        <Route path="/metricas" element={<ProtectedRoute resource="page:metricas"><Metricas /></ProtectedRoute>} />
        <Route path="/users" element={<ProtectedRoute resource="page:users"><UserManagement /></ProtectedRoute>} />
        <Route path="/comparativo-k2" element={<ProtectedRoute resource="page:comparativo-k2"><ComparativoK2 /></ProtectedRoute>} />
        <Route path="/login" element={<Navigate to="/" replace />} />
        <Route path="/change-password" element={<Navigate to="/" replace />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </AuthContext.Provider>
  );
}

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
