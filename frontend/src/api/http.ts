// Client HTTP de l'API : jeton Bearer, renouvellement transparent sur 401, erreurs lisibles.
import {
  clearTokens,
  getAccessToken,
  getRefreshToken,
  storeTokens,
} from "../auth/tokens";
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
    }
  } catch {
    // corps non JSON : message générique
  }
  return new ApiError(response.status, message);
}

let refreshing: Promise<boolean> | null = null;

/** Renouvelle le jeton d'accès. Une seule tentative à la fois, partagée par les appelants. */
export function refreshSession(): Promise<boolean> {
  if (refreshing) return refreshing;
  const refreshToken = getRefreshToken();
  if (!refreshToken) return Promise.resolve(false);
  refreshing = (async () => {
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
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
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

export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const response = await apiFetch(path, {
    method: "POST",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) throw await errorFrom(response);
  return (await response.json()) as T;
}
