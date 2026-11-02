"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { Button, Loading } from "@/components/ui";
import { api, setOrg } from "@/lib/api/client";
import { unwrap } from "@/lib/queries";
import { useSession } from "@/lib/session";

/** Right after confirming an email: the invitations waiting for it, before
 * an organisation of your own gets created. */
export default function InvitationsPage() {
  const router = useRouter();
  const { status } = useSession();
  const pending = useQuery({
    queryKey: ["pending-invitations"],
    enabled: status === "signed-in",
    queryFn: async () => unwrap(await api.GET("/auth/invitations/pending")),
  });
  const accept = useMutation({
    mutationFn: async (id: string) =>
      unwrap(
        await api.POST("/auth/invitations/pending/{member_id}/accept", {
          params: { path: { member_id: id } },
        }),
      ),
    onSuccess: (a) => {
      setOrg(a.tenant_id);
      router.replace("/overview");
    },
  });
  useEffect(() => {
    if (status === "signed-out") router.replace("/login?next=/invitations");
    if (pending.data && pending.data.length === 0) router.replace("/welcome");
  }, [status, pending.data, router]);

  if (!pending.data?.length) return <Loading />;
  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">You&apos;ve been invited</h1>
      {pending.data.map((p) => (
        <div
          key={p.id}
          className="flex items-center justify-between gap-3 rounded-lg border border-line p-3"
        >
          <div>
            <p className="font-medium">{p.organisation}</p>
            <p className="text-xs text-ink-3">
              as {p.role}
              {p.invited_by ? `, by ${p.invited_by}` : ""}
            </p>
          </div>
          <Button variant="primary" loading={accept.isPending} onClick={() => accept.mutate(p.id)}>
            Join
          </Button>
        </div>
      ))}
      <Link href="/welcome" className="block text-center text-sm text-ink-2 hover:text-ink">
        Skip, and set up my own organisation
      </Link>
    </div>
  );
}
