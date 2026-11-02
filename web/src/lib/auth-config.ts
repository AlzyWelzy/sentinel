"use client";

import { useQuery } from "@tanstack/react-query";

import { api } from "./api/client";

export function useAuthConfig() {
  return useQuery({
    queryKey: ["auth-config"],
    staleTime: Infinity,
    queryFn: async () => {
      const { data, error } = await api.GET("/auth/config");
      if (error) throw error;
      return data;
    },
  });
}
