// Session de l'utilisateur : connexion, renouvellement anticipé du jeton, déconnexion.
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { apiGet, login, logout, refreshSession } from "../api/http";
import type { User } from "../api/types";
import { accessExpiresInMs, getAccessToken, getRefreshToken, onTokensChange } from "./tokens";

type Status = "loading" | "anonymous" | "authenticated";

interface AuthValue {
  status: Status;
  user: User | null;
  signIn: (username: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>(getRefreshToken() ? "loading" : "anonymous");
  const [user, setUser] = useState<User | null>(null);

  const loadUser = useCallback(async () => {
    const me = await apiGet<User>("/users/me");
    setUser(me);
    setStatus("authenticated");
  }, []);

  // Reprise de session après un rechargement de page.
  useEffect(() => {
    if (status !== "loading") return;
    void (async () => {
      try {
        if (await refreshSession()) {
          await loadUser();
          return;
        }
      } catch {
        // session illisible : retour à l'écran de connexion
      }
      setStatus("anonymous");
    })();
  }, [status, loadUser]);

  // Session perdue (jeton refusé, déconnexion dans un autre composant).
  useEffect(
    () =>
      onTokensChange(() => {
        if (!getAccessToken() && !getRefreshToken()) {
          setUser(null);
          setStatus("anonymous");
        }
      }),
    [],
  );

  // Renouvellement une minute avant l'expiration du jeton d'accès.
  useEffect(() => {
    if (status !== "authenticated") return;
    let timer: ReturnType<typeof setTimeout>;
    const schedule = () => {
      timer = setTimeout(
        () => {
          void refreshSession().then(schedule);
        },
        Math.max(accessExpiresInMs() - 60_000, 10_000),
      );
    };
    schedule();
    return () => clearTimeout(timer);
  }, [status]);

  const signIn = useCallback(
    async (username: string, password: string) => {
      await login(username, password);
      await loadUser();
    },
    [loadUser],
  );

  const signOut = useCallback(async () => {
    await logout();
    setUser(null);
    setStatus("anonymous");
  }, []);

  const value = useMemo(() => ({ status, user, signIn, signOut }), [status, user, signIn, signOut]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth hors de AuthProvider");
  return value;
}
