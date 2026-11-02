import Link from "next/link";
import {
  cloneElement,
  isValidElement,
  useId,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
} from "react";

export function cx(...parts: (string | false | null | undefined)[]) {
  return parts.filter(Boolean).join(" ");
}

type Variant = "primary" | "secondary" | "ghost" | "danger";

const variants: Record<Variant, string> = {
  primary: "bg-brand text-brand-ink hover:opacity-90",
  secondary: "bg-panel border border-line text-ink hover:bg-panel-2",
  ghost: "text-ink-2 hover:bg-panel-2 hover:text-ink",
  danger: "bg-bad text-white hover:opacity-90",
};

export function Button({
  variant = "secondary",
  loading,
  className,
  children,
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; loading?: boolean }) {
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      className={cx(
        "inline-flex h-9 items-center justify-center gap-2 rounded-lg px-3.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50",
        variants[variant],
        className,
      )}
    >
      {loading && <Spinner small />}
      {children}
    </button>
  );
}

export function LinkButton({
  href,
  variant = "secondary",
  children,
  className,
}: {
  href: string;
  variant?: Variant;
  children: ReactNode;
  className?: string;
}) {
  return (
    <Link
      href={href}
      className={cx(
        "inline-flex h-9 items-center justify-center gap-2 rounded-lg px-3.5 text-sm font-medium transition",
        variants[variant],
        className,
      )}
    >
      {children}
    </Link>
  );
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={cx(
        "h-9 w-full rounded-lg border border-line bg-panel px-3 text-sm text-ink placeholder:text-ink-3 focus:border-brand focus:outline-none",
        props.className,
      )}
    />
  );
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...props}
      className={cx(
        "h-9 rounded-lg border border-line bg-panel px-2.5 text-sm text-ink focus:border-brand focus:outline-none",
        props.className,
      )}
    />
  );
}

/** A label tied to its control by id (not by wrapping it, which would put a
 * select's every option into its accessible name), with an optional hint
 * read out as the control's description. */
export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: ReactNode;
  children: ReactNode;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  const element = isValidElement<{ id?: string; "aria-describedby"?: string }>(children)
    ? children
    : null;
  const controlId = element ? (element.props.id ?? id) : undefined;
  const control = element
    ? cloneElement(element, {
        id: controlId,
        "aria-describedby": hint ? hintId : undefined,
      })
    : children;
  return (
    <div className="block space-y-1.5">
      <label htmlFor={controlId} className="block text-sm font-medium text-ink">
        {label}
      </label>
      {control}
      {hint && (
        <span id={hintId} className="block text-xs text-ink-3">
          {hint}
        </span>
      )}
    </div>
  );
}

export function Card({
  title,
  actions,
  children,
  className,
  pad = true,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  pad?: boolean;
}) {
  return (
    <section className={cx("rounded-xl border border-line bg-panel", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
          <h2 className="text-sm font-semibold text-ink">{title}</h2>
          {actions}
        </header>
      )}
      <div className={pad ? "p-4" : undefined}>{children}</div>
    </section>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-ink-2">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export type Tone = "ok" | "warn" | "bad" | "idle" | "brand";

const tones: Record<Tone, string> = {
  ok: "bg-ok/12 text-ok",
  warn: "bg-warn/12 text-warn",
  bad: "bg-bad/12 text-bad",
  idle: "bg-idle/15 text-ink-2",
  brand: "bg-brand/12 text-brand",
};

export function Badge({ tone = "idle", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium",
        tones[tone],
      )}
    >
      {children}
    </span>
  );
}

export function Dot({ tone }: { tone: Tone }) {
  const bg = { ok: "bg-ok", warn: "bg-warn", bad: "bg-bad", idle: "bg-idle", brand: "bg-brand" }[
    tone
  ];
  return <span className={cx("inline-block size-2 shrink-0 rounded-full", bg)} aria-hidden />;
}

export function Spinner({ small }: { small?: boolean }) {
  return (
    <span
      role="status"
      aria-label="Loading"
      className={cx(
        "inline-block animate-spin rounded-full border-2 border-current border-t-transparent",
        small ? "size-3.5" : "size-5 text-ink-3",
      )}
    />
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-16 text-sm text-ink-3">
      <Spinner /> {label}…
    </div>
  );
}

export function Empty({
  title,
  children,
  action,
}: {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <p className="font-medium text-ink">{title}</p>
      {children && <p className="max-w-md text-sm text-ink-2">{children}</p>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-12 text-center">
      <p className="text-sm text-bad">{message}</p>
      {retry && (
        <Button onClick={retry} variant="secondary">
          Try again
        </Button>
      )}
    </div>
  );
}

export function Notice({ tone = "idle", children }: { tone?: Tone; children: ReactNode }) {
  const border = {
    ok: "border-ok/30",
    warn: "border-warn/30",
    bad: "border-bad/30",
    idle: "border-line",
    brand: "border-brand/30",
  }[tone];
  return (
    <div className={cx("rounded-lg border px-3.5 py-2.5 text-sm", border, tones[tone])}>
      {children}
    </div>
  );
}

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm [&_td]:px-4 [&_td]:py-2.5 [&_th]:px-4 [&_th]:py-2 [&_th]:text-xs [&_th]:font-medium [&_th]:text-ink-3 [&_tbody_tr]:border-t [&_tbody_tr]:border-line">
        {children}
      </table>
    </div>
  );
}

export function Meter({
  value,
  warn = 80,
  bad = 90,
}: {
  value: number | null | undefined;
  warn?: number;
  bad?: number;
}) {
  if (value == null) return <span className="text-ink-3">—</span>;
  const tone = value >= bad ? "bg-bad" : value >= warn ? "bg-warn" : "bg-ok";
  return (
    <div className="flex min-w-24 items-center gap-2">
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-panel-2">
        <div
          className={cx("h-full rounded-full", tone)}
          style={{ width: `${Math.min(100, value)}%` }}
        />
      </div>
      <span className="w-11 text-right text-xs tabular text-ink-2">{value.toFixed(0)}%</span>
    </div>
  );
}

export function CopyBlock({ text }: { text: string }) {
  return (
    <div className="group relative">
      <pre className="overflow-x-auto rounded-lg border border-line bg-panel-2 p-3 pr-20 font-mono text-xs leading-relaxed text-ink">
        {text}
      </pre>
      <button
        type="button"
        onClick={() => navigator.clipboard.writeText(text)}
        className="absolute top-2 right-2 rounded-md border border-line bg-panel px-2 py-1 text-xs text-ink-2 hover:text-ink"
      >
        Copy
      </button>
    </div>
  );
}
