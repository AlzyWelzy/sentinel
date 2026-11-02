"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { Button, Loading, Notice } from "@/components/ui";
import { api, errorText, setOrg } from "@/lib/api/client";
import { useSession } from "@/lib/session";

function Invite() {
  const token = useSearchParams().get("token") ?? "";
  const router = useRouter();
  const { status, user } = useSession();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const invite = useQuery({
    queryKey: ["invite", token],
    enabled: !!token,
    retry: false,
    queryFn: async () => {
      const { data, error } = await api.GET("/auth/invitations/{token}", {
        params: { path: { token } },
      });
      if (error) throw new Error(errorText(error));
      return data;
    },
  });

  async function accept() {
    setBusy(true);
    const { data, error } = await api.POST("/auth/invitations/{token}/accept", {
      params: { path: { token } },
    });
    setBusy(false);
    if (data) {
      setOrg(data.tenant_id);
      router.replace("/");
    } else setError(errorText(error));
  }

  if (invite.isLoading || status === "loading") return <Loading />;
  if (invite.error) return <Notice tone="bad">{invite.error.message}</Notice>;
  const inv = invite.data!;
  const here = `/invite?token=${encodeURIComponent(token)}`;
  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Join {inv.organisation}</h1>
      <p className="text-sm text-ink-2">
        {inv.invited_by ?? "Someone"} invited <b className="text-ink">{inv.email}</b> as {inv.role}.
      </p>
      {error && <Notice tone="bad">{error}</Notice>}
      {status === "signed-in" ? (
        user.email === inv.email ? (
          <Button variant="primary" className="w-full" loading={busy} onClick={accept}>
            Accept invitation
          </Button>
        ) : (
          <Notice tone="warn">
            You&apos;re signed in as {user.email}. Sign out and sign in as {inv.email} to accept.
          </Notice>
        )
      ) : (
        <div className="space-y-2">
          <Link
            href={`/login?next=${encodeURIComponent(here)}`}
            className="flex h-9 items-center justify-center rounded-lg bg-brand text-sm font-medium text-brand-ink"
          >
            Sign in to accept
          </Link>
          <Link
            href="/signup"
            className="flex h-9 items-center justify-center rounded-lg border border-line text-sm font-medium"
          >
            Create an account with {inv.email}
          </Link>
          <p className="text-xs text-ink-3">
            After confirming your email, open this invitation link again to accept it.
          </p>
        </div>
      )}
    </div>
  );
}

export default function InvitePage() {
  return (
    <Suspense>
      <Invite />
    </Suspense>
  );
}
