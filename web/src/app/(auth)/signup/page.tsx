"use client";

import Link from "next/link";
import { useCallback, useState } from "react";

import { Turnstile } from "@/components/turnstile";
import { Button, Field, Input, Notice } from "@/components/ui";
import { api, errorText } from "@/lib/api/client";
import { useAuthConfig } from "@/lib/auth-config";

export default function SignupPage() {
  const config = useAuthConfig();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [captcha, setCaptcha] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const onToken = useCallback((t: string) => setCaptcha(t), []);
  const min = config.data?.password_min_length ?? 10;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (password.length < min) {
      setError(`Use at least ${min} characters for your password.`);
      return;
    }
    setBusy(true);
    setError(null);
    const { error } = await api.POST("/auth/signup", {
      body: { email, password, name: name || null, captcha_token: captcha },
    });
    setBusy(false);
    if (error) setError(errorText(error, "Couldn't create the account"));
    else setDone(true);
  }

  if (done) {
    return (
      <div className="space-y-3">
        <h1 className="text-lg font-semibold">Check your email</h1>
        <p className="text-sm text-ink-2">
          We sent a link to <b className="text-ink">{email}</b>. Open it to confirm your address and
          finish signing up. It works for 24 hours.
        </p>
      </div>
    );
  }
  if (config.data && !config.data.signup_enabled) {
    return <Notice>Sign-up is closed. Ask an organisation owner for an invitation.</Notice>;
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Create your account</h1>
        <p className="mt-1 text-sm text-ink-2">Monitor your servers in a couple of minutes.</p>
      </div>
      {error && <Notice tone="bad">{error}</Notice>}
      <Field label="Name">
        <Input autoComplete="name" value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="Work email">
        <Input
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
      </Field>
      <Field label="Password" hint={`At least ${min} characters.`}>
        <Input
          type="password"
          autoComplete="new-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </Field>
      {config.data?.turnstile_site_key && (
        <Turnstile siteKey={config.data.turnstile_site_key} onToken={onToken} />
      )}
      <Button type="submit" variant="primary" loading={busy} className="w-full">
        Create account
      </Button>
      <p className="text-center text-sm text-ink-2">
        Already have an account?{" "}
        <Link href="/login" className="font-medium text-brand">
          Sign in
        </Link>
      </p>
    </form>
  );
}
