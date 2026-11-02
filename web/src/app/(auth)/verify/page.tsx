"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";

import { Loading, Notice } from "@/components/ui";
import { api, errorText, setSession } from "@/lib/api/client";

function Verify() {
  const token = useSearchParams().get("token");
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const once = useRef(false);

  useEffect(() => {
    if (!token || once.current) return;
    once.current = true; // the link is single use; Strict Mode mounts twice
    api.POST("/auth/verify", { body: { token } }).then(({ data, error }) => {
      if (data) {
        setSession(data);
        router.replace("/welcome");
      } else setError(errorText(error, "This link didn't work"));
    });
  }, [token, router]);

  if (!token)
    return <Notice tone="bad">This link is incomplete. Open the one from the email.</Notice>;
  if (error)
    return (
      <div className="space-y-3">
        <Notice tone="bad">{error}</Notice>
        <Link href="/login" className="text-sm font-medium text-brand">
          Go to sign in
        </Link>
      </div>
    );
  return <Loading label="Confirming your email" />;
}

export default function VerifyPage() {
  return (
    <Suspense>
      <Verify />
    </Suspense>
  );
}
