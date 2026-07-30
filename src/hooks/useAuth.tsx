import { useState, useEffect, useCallback } from "react";
import { supabase } from "@/integrations/supabase/client";
import type { User, Session } from "@supabase/supabase-js";

interface AuthState {
  user: User | null;
  session: Session | null;
  loading: boolean;
  mustChangePassword: boolean;
}

export function useAuth(): AuthState & { signOut: () => Promise<void>; clearMustChangePassword: () => void } {
  const [state, setState] = useState<AuthState>({
    user: null,
    session: null,
    loading: true,
    mustChangePassword: false,
  });

  const checkProfileAndUpdate = useCallback((user: User | null, session: Session | null) => {
    if (!user) {
      setState({ user: null, session: null, loading: false, mustChangePassword: false });
      return Promise.resolve();
    }

    // Set user immediately, then check profile in background
    setState(prev => ({ ...prev, user, session, loading: true }));

    return Promise.resolve(
      supabase
        .from("profiles")
        .select("must_change_password")
        .eq("id", user.id)
        .single()
    )
      .then(({ data: profile, error }) => {
        const mustChange = error ? false : (profile?.must_change_password ?? false);
        setState({ user, session, loading: false, mustChangePassword: mustChange });
      })
      .catch(() => {
        setState({ user, session, loading: false, mustChangePassword: false });
      });
  }, []);

  useEffect(() => {
    let ignore = false;

    // Safety timeout: force loading=false after 5s, but preserve any session already found
    const safetyTimeout = setTimeout(() => {
      if (ignore) return;
      setState(prev => {
        if (prev.loading) {
          console.warn("Auth safety timeout triggered");
          // If we already have a user from a previous state update, keep it
          if (prev.user && prev.session) {
            return { ...prev, loading: false };
          }
          return { user: null, session: null, loading: false, mustChangePassword: false };
        }
        return prev;
      });
    }, 5000);

    // Listen for auth changes before getSession so login events are never missed
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (event, session) => {
        if (ignore) return;
        const user = session?.user ?? null;

        if (!user) {
          setState({ user: null, session: null, loading: false, mustChangePassword: false });
          return;
        }

        // On USER_UPDATED (password change), just update user/session without re-checking profile
        if (event === "USER_UPDATED") {
          setState(prev => ({ ...prev, user, session, loading: false }));
          return;
        }

        void checkProfileAndUpdate(user, session);
      }
    );

    // Get initial session
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (ignore) return;
      void checkProfileAndUpdate(session?.user ?? null, session ?? null);
    }).catch(() => {
      if (ignore) return;
      setState(prev => (
        prev.user && prev.session
          ? { ...prev, loading: false }
          : { user: null, session: null, loading: false, mustChangePassword: false }
      ));
    });

    return () => {
      ignore = true;
      clearTimeout(safetyTimeout);
      subscription.unsubscribe();
    };
  }, [checkProfileAndUpdate]);

  const signOut = async () => {
    await supabase.auth.signOut();
  };

  const clearMustChangePassword = () => {
    setState(prev => ({ ...prev, mustChangePassword: false }));
  };

  return { ...state, signOut, clearMustChangePassword };
}
