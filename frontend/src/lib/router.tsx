// Routage minimal de l'interface : quelques écrans, des adresses internes seulement.
// Il remplace React Router (vulnérabilités de redirection ouverte et XSS dans toute la
// branche 6, 10/10/2026) : ici, une adresse qui ne commence pas par un seul « / » est
// refusée, aucune redirection externe n'est possible.
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type AnchorHTMLAttributes,
  type MouseEvent,
  type ReactNode,
} from "react";

interface RouterValue {
  pathname: string;
  search: string;
  navigate: (to: string) => void;
}

const RouterContext = createContext<RouterValue | null>(null);

/** Adresse interne valide : « /chemin », jamais « //hote », « /\hote » ni « https:… ». */
export function isInternalPath(to: string): boolean {
  return /^\/(?![/\\])[^\s\\]*$/.test(to);
}

function current() {
  return { pathname: window.location.pathname, search: window.location.search };
}

export function Router({ children }: { children: ReactNode }) {
  const [location, setLocation] = useState(current);

  useEffect(() => {
    const onPop = () => setLocation(current());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const navigate = useCallback((to: string) => {
    if (!isInternalPath(to)) return;
    window.history.pushState(null, "", to);
    setLocation(current());
    document.getElementById("contenu")?.scrollTo(0, 0);
  }, []);

  const value = useMemo(() => ({ ...location, navigate }), [location, navigate]);
  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
}

export function useLocation(): RouterValue {
  const value = useContext(RouterContext);
  if (!value) throw new Error("useLocation hors de Router");
  return value;
}

type LinkProps = Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href"> & { to: string };

export function Link({ to, onClick, children, ...rest }: LinkProps) {
  const { navigate } = useLocation();
  const safe = isInternalPath(to) ? to : "/";
  const handle = (event: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event);
    // Ctrl/Cmd/Maj-clic et clic milieu : comportement normal du navigateur (nouvel onglet).
    if (event.defaultPrevented || event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    navigate(safe);
  };
  return (
    <a href={safe} onClick={handle} {...rest}>
      {children}
    </a>
  );
}

/** Vrai si `to` désigne l'écran courant (ou un de ses sous-écrans, sauf pour « / »). */
export function isActive(pathname: string, to: string): boolean {
  if (to === "/") return pathname === "/";
  return pathname === to || pathname.startsWith(`${to}/`);
}
