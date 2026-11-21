"use client";

/**
 * Who is signed in, and which organisation they're looking at.
 *
 * On load the provider tries the refresh cookie once; until that answers
 * the app shows a loading state rather than flashing the sign-in page.
 * Signing out in one tab signs every tab out.
 */
import {
  MutationCache,
  QueryClient,
  QueryClientProvider,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";

import { Toasts, toastError } from "@/components/toast";

import {
  api,
  errorText,
  getOrg,
  onSessionChange,
  endSession,
  refreshSession,
  setOrg as storeOrg,
  subscribeOrg,
  type User,
} from "./api/client";

type SessionState =
  | { status: "loading"; user: null }
  | { status: "signed-out"; user: null }
  | { status: "signed-in"; user: User };

const SessionContext = createContext<SessionState>({ status: "loading", user: null });

export function Providers({ children }: { children: ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        // A mutation that handles its own errors shows them in place; any
        // other failure still reaches the user.
        mutationCache: new MutationCache({
          onError: (error, _vars, _ctx, mutation) => {
            if (!mutation.options.onError) toastError(errorText(error));
          },
        }),
        defaultOptions: {
          queries: { staleTime: 15_000, retry: 1, refetchOnWindowFocus: true },
        },
      }),
  );
  return (
    <QueryClientProvider client={client}>
      <SessionProvider>{children}</SessionProvider>
      <Toasts />
    </QueryClientProvider>
  );
}

function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<SessionState>({ status: "loading", user: null });
  const qc = useQueryClient();

  useEffect(() => {
    const off = onSessionChange((user) =>
      setState(user ? { status: "signed-in", user } : { status: "signed-out", user: null }),
    );
    refreshSession().then((s) => {
      if (!s) setState({ status: "signed-out", user: null });
    });
    let channel: BroadcastChannel | null = null;
    try {
      channel = new BroadcastChannel("pg-auth");
      channel.onmessage = () => {
        endSession();
        qc.clear();
      };
    } catch {
      channel = null;
    }
    return () => {
      off();
      channel?.close();
    };
  }, [qc]);

  return <SessionContext.Provider value={state}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionState {
  return useContext(SessionContext);
}

export type Org = { tenant_id: string; name: string | null; email: string | null; role: string };

export function orgName(o: {
  name?: string | null;
  display_name?: string | null;
  email?: string | null;
}) {
  return o.name ?? o.display_name ?? (o.email ? `${o.email}'s organisation` : "Organisation");
}

/** The organisations the user belongs to and the one in use. */
export function useOrgs() {
  const qc = useQueryClient();
  const { status } = useSession();
  const current = useSyncExternalStore(subscribeOrg, getOrg, () => null);
  const accounts = useQuery({
    queryKey: ["accounts"],
    enabled: status === "signed-in",
    queryFn: async () => {
      const { data, error } = await api.GET("/v1/me/accounts");
      if (error) throw error;
      return data as Org[];
    },
  });
  const list = useMemo(() => accounts.data ?? [], [accounts.data]);
  const selected = list.find((o) => o.tenant_id === current) ?? list[0] ?? null;
  return {
    list,
    loading: accounts.isLoading,
    selected,
    select(id: string) {
      storeOrg(id);
      // Everything on screen belongs to the previous organisation.
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "accounts" });
    },
  };
}

/** The current organisation and the caller's role in it (from /v1/me). */
export function useMe() {
  const { status } = useSession();
  return useQuery({
    queryKey: ["me"],
    enabled: status === "signed-in",
    queryFn: async () => {
      const { data, error } = await api.GET("/v1/me");
      if (error) throw error;
      return data;
    },
  });
}

export const ROLE_LABELS: Record<string, string> = {
  owner: "Owner",
  admin: "Admin",
  operator: "Member",
  viewer: "Read-only",
  investigator: "Investigator",
  auditor: "Auditor",
  staff: "Superadmin",
};

export function canEdit(role: string | undefined) {
  return role === "owner" || role === "admin" || role === "staff";
}
