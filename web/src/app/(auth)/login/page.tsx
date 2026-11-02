"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";

import { Button, Field, Input, Notice } from "@/components/ui";
import { api, errorCode, errorText, setSession } from "@/lib/api/client";
import { useSession } from "@/lib/session";

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const next = params.get("next") || "/overview";
  const { status } = useSession();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unverified, setUnverified] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (status === "signed-in")
      router.replace(next.startsWith("/") && !next.startsWith("//") ? next : "/overview");
  }, [status, next, router]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const { data, error } = await api.POST("/auth/login", {
      body: { email, password, totp_code: needCode ? code : null },
    });
    setBusy(false);
    if (data) {
      setSession(data);
      return;
    }
    const c = errorCode(error);
    if (c === "totp_required") {
      setNeedCode(true);
      return;
    }
    setUnverified(c === "email_unverified");
    setError(errorText(error, "Couldn't sign in"));
  }

  async function resend() {
    await api.POST("/auth/verify/resend", { body: { email } });
    setError("A new confirmation link is on its way.");
    setUnverified(false);
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Sign in</h1>
        <p className="mt-1 text-sm text-ink-2">Welcome back.</p>
      </div>
      {params.get("reset") && (
        <Notice tone="ok">Password changed. Sign in with the new one.</Notice>
      )}
      {error && <Notice tone={unverified ? "warn" : "bad"}>{error}</Notice>}
      {unverified && (
        <Button type="button" onClick={resend} className="w-full">
          Send the confirmation link again
        </Button>
      )}
      {!needCode ? (
        <>
          <Field label="Email">
            <Input
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </Field>
          <Field label="Password">
            <Input
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </Field>
        </>
      ) : (
        <Field label="Authentication code" hint="The 6-digit code from your authenticator app.">
          <Input
            inputMode="numeric"
            autoComplete="one-time-code"
            autoFocus
            required
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
        </Field>
      )}
      <Button type="submit" variant="primary" loading={busy} className="w-full">
        {needCode ? "Verify" : "Sign in"}
      </Button>
      <div className="flex justify-between text-sm">
        <Link href="/forgot" className="text-ink-2 hover:text-ink">
          Forgot password?
        </Link>
        <Link href="/signup" className="font-medium text-brand">
          Create an account
        </Link>
      </div>
    </form>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
