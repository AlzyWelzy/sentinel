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
  if (s) leaving = false;
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

const IMPERSONATION_KEY = "pg.impersonation";

/** A superadmin working in an organisation: this token replaces theirs.
 * Kept for this tab only (sessionStorage), so a reload stays in the
 * organisation until Leave or the token's hour runs out. */
export function setImpersonation(token: string | null) {
  impersonationToken = token;
  try {
    if (token) sessionStorage.setItem(IMPERSONATION_KEY, token);
    else sessionStorage.removeItem(IMPERSONATION_KEY);
  } catch {
    // Storage blocked: it lasts for this page only.
  }
}

if (typeof window !== "undefined") {
  try {
    impersonationToken = sessionStorage.getItem(IMPERSONATION_KEY);
  } catch {
    impersonationToken = null;
  }
}

/** Leave the organisation: the impersonation ends on the server too (so
 * the record shows when), and the superadmin's own session carries on. */
export async function endImpersonation() {
  const token = impersonationToken;
  setImpersonation(null);
  if (!token) return;
  try {
    const claims = JSON.parse(atob(token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/")));
    if (claims.imp) await authed(`/admin/v1/impersonations/${claims.imp}/end`, { method: "POST" });
  } catch {
    // It still expires on its own within the hour.
  }
}

export function isImpersonating(): boolean {
  return impersonationToken !== null;
}

async function doRefresh(): Promise<Session | null> {
  // Only the server saying no (401/403) ends the session. A deploy restarting
  // the API answers 502 or drops the connection for a few seconds; signing
  // everyone out then would be wrong, so those are retried. A refresh the
  // server did commit (response lost) is safe to repeat within its 10 s
  // reuse grace; a 502 from the proxy committed nothing.
  const run = async () => {
    for (let attempt = 0; ; attempt++) {
      try {
        const r = await fetch(`${API_BASE}/auth/refresh`, {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-Requested-With": "sentinel" },
        });
        if (r.ok) return (await r.json()) as Session;
        if (r.status < 500 || attempt >= 5) return null;
      } catch {
        if (attempt >= 5) return null;
      }
      await new Promise((done) => setTimeout(done, 1000 * 2 ** attempt)); // 1, 2, 4, 8, 16 s
    }
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
  if (res.status === 401 && impersonationToken) {
    // The impersonation ended or expired: back to the superadmin's own view.
    setImpersonation(null);
    return fetch(withAuth(retry));
  }
  if (res.status !== 401 || input.url.includes("/auth/refresh")) {
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

let leaving = false;

/** True after signOut(): the sign-in page shouldn't send them back here. */
export function signedOutOnPurpose(): boolean {
  return leaving;
}

/** End the session on purpose (the server already did: password change,
 * account deleted), without the "come back here" redirect. */
export function endSession() {
  leaving = true;
  setSession(null);
}

export async function signOut() {
  leaving = true;
  setImpersonation(null);
  await fetch(`${API_BASE}/auth/logout`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "X-Requested-With": "sentinel" },
  });
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
    const msg = String((detail[0] as { msg: unknown }).msg).replace(/^Value error, /, "");
    // A mistyped or truncated link: the id in the address isn't one.
    if (/valid UUID/i.test(msg)) return "Nothing here: the link may be mistyped or cut short";
    return msg;
  }
  return fallback;
}

export function errorCode(error: unknown): string | undefined {
  const detail = (error as { detail?: { code?: string } } | undefined)?.detail;
  return typeof detail === "object" ? detail?.code : undefined;
}
