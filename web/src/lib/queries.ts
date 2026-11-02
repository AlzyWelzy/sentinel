"use client";

import { useQuery } from "@tanstack/react-query";

import { api } from "./api/client";
import type { components } from "./api/schema";

export type Host = components["schemas"]["HostOut"];
export type Incident = components["schemas"]["IncidentOut"];
export type Rule = components["schemas"]["RuleOut"];
export type ServerHealth = components["schemas"]["ServerHealth"];

/** Throw the API's error so React Query shows it. */
export function unwrap<T>(r: { data?: T; error?: unknown }): T {
  if (r.error !== undefined) throw r.error;
  return r.data as T;
}

export function useOverview() {
  return useQuery({
    queryKey: ["overview"],
    refetchInterval: 30_000,
    queryFn: async () => unwrap(await api.GET("/v1/servers/overview")),
  });
}

export function useHosts() {
  return useQuery({
    queryKey: ["hosts"],
    refetchInterval: 30_000,
    queryFn: async () => unwrap(await api.GET("/v1/hosts")),
  });
}

export function useIncidents(status?: "open" | "resolved") {
  return useQuery({
    queryKey: ["incidents", status ?? "all"],
    refetchInterval: 30_000,
    queryFn: async () =>
      unwrap(await api.GET("/v1/incidents", { params: { query: status ? { status } : {} } })),
  });
}
