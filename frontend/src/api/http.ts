// Client HTTP de l'API : jeton Bearer, renouvellement transparent sur 401, erreurs lisibles.
import {
  accessExpiresInMs,
  clearTokens,
  getAccessToken,
  getRefreshToken,
  storeTokens,
} from "../auth/tokens";
import { filenameFrom } from "../lib/iocs";
import type { TokenResponse } from "./types";

export const API = "/api/v1";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function errorFrom(response: Response): Promise<ApiError> {
  let message = `Erreur ${response.status}`;
  try {
    const body: unknown = await response.json();
    if (body && typeof body === "object" && "detail" in body) {
      const detail = (body as { detail: unknown }).detail;
      if (typeof detail === "string") message = detail;
      // Erreur de validation (422) : liste de { loc, msg } produite par FastAPI.
      else if (Array.isArray(detail)) {
        const parts = detail
          .map((item) => (item && typeof item === "object" && "msg" in item ? String(item.msg) : ""))
          .filter(Boolean);
        if (parts.length) message = parts.join(" ; ");
      }
    }
  } catch {
    // corps non JSON : message générique
  }
  return new ApiError(response.status, message);
}

let refreshing: Promise<boolean> | null = null;

async function renew(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;
  try {
    const response = await fetch(`${API}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!response.ok) {
      clearTokens();
      return false;
    }
    storeTokens((await response.json()) as TokenResponse);
    return true;
  } catch {
    return false; // réseau coupé : on garde le jeton de rafraîchissement
  }
}

/**
 * Renouvelle le jeton d'accès. Une seule tentative à la fois dans l'onglet, et un seul onglet
 * à la fois (verrou partagé) : si un autre onglet vient de renouveler, ses jetons, reçus par
 * diffusion, sont repris tels quels au lieu de rejouer l'ancien jeton (ce qui révoquerait la
 * session).
 */
export function refreshSession(): Promise<boolean> {
  if (refreshing) return refreshing;
  const before = getRefreshToken();
  if (!before) return Promise.resolve(false);
  const attempt = async () => {
    const current = getRefreshToken();
    if (current !== before && getAccessToken() && accessExpiresInMs() > 60_000) return true;
    return renew();
  };
  const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
  // `.then((ok) => ok)` aplatit le résultat : selon la version de TypeScript, `locks.request`
  // est typé Promise<boolean> ou Promise<Promise<boolean>> (même valeur à l'exécution).
  const run: Promise<boolean> = locks
    ? locks.request("illwatch-refresh", attempt).then((ok) => ok)
    : attempt();
  const pending = run.finally(() => {
    refreshing = null;
  });
  refreshing = pending;
  return pending;
}

export async function login(username: string, password: string): Promise<void> {
  const response = await fetch(`${API}/auth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username, password }),
  });
  if (!response.ok) {
    if (response.status === 401) {
      throw new ApiError(401, "Identifiant ou mot de passe incorrect.");
    }
    throw await errorFrom(response);
  }
  storeTokens((await response.json()) as TokenResponse);
}

export async function logout(): Promise<void> {
  const refreshToken = getRefreshToken();
  clearTokens();
  if (refreshToken) {
    await fetch(`${API}/auth/logout`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    }).catch(() => undefined);
  }
}

type Query = Record<string, string | number | boolean | undefined>;

function withQuery(path: string, query?: Query): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined) params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `${path}?${text}` : path;
}

/** Requête authentifiée vers `/api/v1{path}`. Sur 401 : renouvellement puis un seul nouvel essai. */
export async function apiFetch(path: string, init: RequestInit = {}, query?: Query): Promise<Response> {
  const url = withQuery(`${API}${path}`, query);
  const send = () => {
    const headers = new Headers(init.headers);
    const token = getAccessToken();
    if (token) headers.set("Authorization", `Bearer ${token}`);
    return fetch(url, { ...init, headers });
  };
  let response = await send();
  if (response.status === 401 && (await refreshSession())) {
    response = await send();
  }
  if (response.status === 401) clearTokens();
  return response;
}

export async function apiGet<T>(path: string, query?: Query, signal?: AbortSignal): Promise<T> {
  const response = await apiFetch(path, { signal }, query);
  if (!response.ok) throw await errorFrom(response);
  return (await response.json()) as T;
}

export function apiPost<T>(path: string, body?: unknown): Promise<T> {
  return apiSend<T>("POST", path, body);
}

export async function apiSend<T>(method: "POST" | "PUT" | "PATCH", path: string, body?: unknown): Promise<T> {
  const response = await apiFetch(path, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) throw await errorFrom(response);
  return (await response.json()) as T;
}

/** Téléchargement authentifié (export) : le fichier est enregistré sous le nom donné par le serveur. */
export async function apiDownload(path: string, query: Query, fallbackName: string): Promise<string> {
  const response = await apiFetch(path, {}, query);
  if (!response.ok) throw await errorFrom(response);
  const name = filenameFrom(response.headers.get("Content-Disposition"), fallbackName);
  const url = URL.createObjectURL(await response.blob());
  try {
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
  } finally {
    // Laisse au navigateur le temps de démarrer l'enregistrement.
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }
  return name;
}
