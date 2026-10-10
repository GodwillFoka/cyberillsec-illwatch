// Jetons de session. Le jeton d'accès (15 min) reste en mémoire ; le jeton de
// rafraîchissement est gardé dans sessionStorage (onglet courant seulement, effacé à la
// fermeture) pour survivre à un rechargement de page. La politique de sécurité du contenu
// (aucun script tiers, aucun script en ligne) limite le risque d'exfiltration par XSS.
import type { TokenResponse } from "../api/types";

const REFRESH_KEY = "illwatch.refresh";

let accessToken: string | null = null;
let accessExpiresAt = 0;
const listeners = new Set<() => void>();

export function getAccessToken(): string | null {
  return accessToken;
}

export function accessExpiresInMs(): number {
  return accessExpiresAt - Date.now();
}

export function getRefreshToken(): string | null {
  try {
    return sessionStorage.getItem(REFRESH_KEY);
  } catch {
    return null;
  }
}

export function storeTokens(tokens: TokenResponse): void {
  accessToken = tokens.access_token;
  accessExpiresAt = Date.now() + tokens.expires_in * 1000;
  try {
    sessionStorage.setItem(REFRESH_KEY, tokens.refresh_token);
  } catch {
    // Stockage indisponible (navigation privée stricte) : la session durera 15 min.
  }
  listeners.forEach((notify) => notify());
}

export function clearTokens(): void {
  accessToken = null;
  accessExpiresAt = 0;
  try {
    sessionStorage.removeItem(REFRESH_KEY);
  } catch {
    // rien à effacer
  }
  listeners.forEach((notify) => notify());
}

export function onTokensChange(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
