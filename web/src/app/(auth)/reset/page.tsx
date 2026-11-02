"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { Button, Field, Input, Notice } from "@/components/ui";
import { api, errorText } from "@/lib/api/client";

function Reset() {
  const token = useSearchParams().get("token") ?? "";
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    const { error } = await api.POST("/auth/password/reset", { body: { token, password } });
    setBusy(false);
    if (error) setError(errorText(error));
    else router.replace("/login?reset=1");
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <h1 className="text-lg font-semibold">Choose a new password</h1>
      <p className="text-sm text-ink-2">
        Every browser signed in to your account will be signed out.
      </p>
      {error && <Notice tone="bad">{error}</Notice>}
      <Field label="New password" hint="At least 10 characters.">
        <Input
          type="password"
          autoComplete="new-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </Field>
      <Button type="submit" variant="primary" loading={busy} className="w-full">
        Set password
      </Button>
    </form>
  );
}

export default function ResetPage() {
  return (
    <Suspense>
      <Reset />
    </Suspense>
  );
}
