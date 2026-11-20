import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api/client";
import type { components } from "@/lib/api/schema";
import { unwrap } from "@/lib/queries";

export type Device = components["schemas"]["DeviceOut"];
export type Credential = components["schemas"]["CredentialOut"];
export type Poller = components["schemas"]["PollerOut"];
export type Profile = components["schemas"]["ProfileOut"];

export const ROLES = [
  { value: "core", label: "Core" },
  { value: "distribution", label: "Distribution" },
  { value: "access", label: "Access" },
  { value: "firewall", label: "Firewall" },
  { value: "router", label: "Router" },
  { value: "wireless", label: "Wireless" },
  { value: "other", label: "Other" },
] as const;

export function useCredentials() {
  return useQuery({
    queryKey: ["network", "credentials"],
    queryFn: async () => unwrap(await api.GET("/v1/network/credentials")),
  });
}

export function usePollers() {
  return useQuery({
    queryKey: ["network", "pollers"],
    queryFn: async () => unwrap(await api.GET("/v1/network/pollers")),
  });
}

export function useProfiles() {
  return useQuery({
    queryKey: ["network", "profiles"],
    queryFn: async () => unwrap(await api.GET("/v1/network/profiles")),
    staleTime: 10 * 60_000,
  });
}

/** Bits per second: "940 Mb/s", "1.2 Gb/s". */
export function bps(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return "—";
  const units = ["b/s", "kb/s", "Mb/s", "Gb/s", "Tb/s"];
  let i = 0;
  let v = n;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

/** Link speed: "10G", "100M", "1G". */
export function speed(n: number | null | undefined): string {
  if (!n) return "—";
  if (n >= 1e9) return `${+(n / 1e9).toFixed(1)}G`;
  if (n >= 1e6) return `${Math.round(n / 1e6)}M`;
  return `${Math.round(n / 1e3)}k`;
}
