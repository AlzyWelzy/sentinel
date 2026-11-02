/**
 * The API client: typed from the FastAPI OpenAPI schema (npm run api), with
 * Sentinel's sign-in built in.
 *
 * - The access token lives in memory only. The refresh token is an httpOnly
 *   cookie the browser sends to /api/auth/refresh; JavaScript never sees it.
 * - A 401 triggers one refresh and one retry. Refreshes are serialised across
 *   tabs with the Web Locks API, because the server rotates the refresh token
 *   on every use and treats a reused one as stolen.
 * - The selected organisation goes out as X-Sentinel-Account; the server
 *   checks membership on every request.
 */
import createClient from "openapi-fetch";

import type { components, paths } from "./schema";

export const API_BASE = "/api";
const ORG_KEY = "pg.org";

export type User = components["schemas"]["UserOut"];
type Session = components["schemas"]["SessionOut"];

let accessToken: string | null = null;
let impersonationToken: string | null = null;
let refreshing: Promise<Session | null> | null = null;
const listeners = new Set<(user: User | null) => void>();

export function onSessionChange(fn: (user: User | null) => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function emit(user: User | null) {
  for (const fn of listeners) fn(user);
}

export function setSession(s: Session | null) {
  accessToken = s?.access_token ?? null;
  emit(s?.user ?? null);
}

export function getOrg(): string | null {
  try {
    return localStorage.getItem(ORG_KEY) ?? memoryOrg;
  } catch {
    return memoryOrg;
  }
}

let memoryOrg: string | null = null;
const orgListeners = new Set<() => void>();

export function setOrg(id: string | null) {
  memoryOrg = id;
  try {
    if (id) localStorage.setItem(ORG_KEY, id);
    else localStorage.removeItem(ORG_KEY);
  } catch {
    // Private mode: the selection lasts for this page only.
  }
  for (const fn of orgListeners) fn();
}

export function subscribeOrg(fn: () => void): () => void {
  orgListeners.add(fn);
  const onStorage = (e: StorageEvent) => e.key === ORG_KEY && fn();
  window.addEventListener("storage", onStorage);
  return () => {
    orgListeners.delete(fn);
    window.removeEventListener("storage", onStorage);
  };
}

/** A superadmin working in an organisation: this token replaces theirs. */
export function setImpersonation(token: string | null) {
  impersonationToken = token;
}

export function isImpersonating(): boolean {
  return impersonationToken !== null;
}

async function doRefresh(): Promise<Session | null> {
  const run = async () => {
    const r = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-Requested-With": "sentinel" },
    });
    if (!r.ok) return null;
    return (await r.json()) as Session;
  };
  const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
  const session = locks ? await locks.request("pg-refresh", run) : await run();
  setSession(session);
  return session;
}

/** One refresh at a time; concurrent callers share it. */
export function refreshSession(): Promise<Session | null> {
  refreshing ??= doRefresh().finally(() => {
    refreshing = null;
  });
  return refreshing;
}

function withAuth(req: Request): Request {
  const token = impersonationToken ?? accessToken;
  if (token) req.headers.set("Authorization", `Bearer ${token}`);
  const org = getOrg();
  if (
    org &&
    !impersonationToken &&
    !req.url.includes("/auth/") &&
    !req.headers.has("X-Sentinel-Account")
  ) {
    req.headers.set("X-Sentinel-Account", org);
  }
  return req;
}

async function authFetch(input: Request): Promise<Response> {
  const retry = input.clone();
  const res = await fetch(withAuth(input));
  if (res.status !== 401 || impersonationToken || input.url.includes("/auth/refresh")) {
    return res;
  }
  const session = await refreshSession();
  if (!session) return res;
  return fetch(withAuth(retry));
}

export const api = createClient<paths>({
  baseUrl: API_BASE,
  fetch: authFetch,
  credentials: "same-origin",
});

/** Plain fetch with the same auth, for downloads and non-JSON bodies. */
export function authed(path: string, init?: RequestInit): Promise<Response> {
  return authFetch(new Request(`${API_BASE}${path}`, init));
}

export async function signOut() {
  await fetch(`${API_BASE}/auth/logout`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "X-Requested-With": "sentinel" },
  });
  setImpersonation(null);
  setSession(null);
  try {
    new BroadcastChannel("pg-auth").postMessage("signed-out");
  } catch {
    // Old browsers: other tabs find out at their next request.
  }
}

/** FastAPI's error bodies, as one readable line. */
export function errorText(error: unknown, fallback = "Something went wrong"): string {
  if (!error || typeof error !== "object") return fallback;
  const detail = (error as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (detail && typeof detail === "object" && "message" in detail) {
    return String((detail as { message: unknown }).message);
  }
  if (Array.isArray(detail) && detail[0] && typeof detail[0] === "object" && "msg" in detail[0]) {
    return String((detail[0] as { msg: unknown }).msg).replace(/^Value error, /, "");
  }
  return fallback;
}

export function errorCode(error: unknown): string | undefined {
  const detail = (error as { detail?: { code?: string } } | undefined)?.detail;
  return typeof detail === "object" ? detail?.code : undefined;
}
