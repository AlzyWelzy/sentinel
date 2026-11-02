"use client";

import Link from "next/link";
import { useCallback, useState } from "react";

import { Turnstile } from "@/components/turnstile";
import { Button, Field, Input, Notice } from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { useAuthConfig } from "@/lib/auth-config";

export default function ForgotPage() {
  const config = useAuthConfig();
  const [email, setEmail] = useState("");
  const [captcha, setCaptcha] = useState<string | null>(null);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const onToken = useCallback((t: string) => setCaptcha(t), []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    const { error } = await api.POST("/auth/password/forgot", {
      body: { email, captcha_token: captcha },
    });
    setBusy(false);
    if (error) setError(errorText(error));
    else setSent(true);
  }

  if (sent)
    return (
      <div className="space-y-3">
        <h1 className="text-lg font-semibold">Check your email</h1>
        <p className="text-sm text-ink-2">
          If <b className="text-ink">{email}</b> has an account, a link to choose a new password is
          on its way. It works for an hour.
        </p>
      </div>
    );
  return (
    <form onSubmit={submit} className="space-y-4">
      <h1 className="text-lg font-semibold">Reset your password</h1>
      {error && <Notice tone="bad">{error}</Notice>}
      <Field label="Email">
        <Input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
      {config.data?.turnstile_site_key && (
        <Turnstile siteKey={config.data.turnstile_site_key} onToken={onToken} />
      )}
      <Button type="submit" variant="primary" loading={busy} className="w-full">
        Send reset link
      </Button>
      <Link href="/login" className="block text-center text-sm text-ink-2 hover:text-ink">
        Back to sign in
      </Link>
    </form>
  );
}
