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
  primary:
    "bg-gradient-brand text-brand-ink shadow-glow hover:brightness-110 active:brightness-95 [text-shadow:0_1px_0_rgb(0_0_0/0.15)]",
  secondary:
    "bg-panel border border-line text-ink shadow-card hover:border-line-2 hover:bg-panel-2",
  ghost: "text-ink-2 hover:bg-panel-2 hover:text-ink",
  danger: "bg-bad text-white shadow-sm hover:brightness-110",
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
        "inline-flex h-9 items-center justify-center gap-2 rounded-[10px] px-3.5 text-sm font-medium whitespace-nowrap transition duration-150 select-none disabled:cursor-not-allowed disabled:opacity-50",
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
        "inline-flex h-9 items-center justify-center gap-2 rounded-[10px] px-3.5 text-sm font-medium whitespace-nowrap transition duration-150",
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
        "h-9 w-full rounded-[10px] border border-line bg-panel px-3 text-sm text-ink shadow-[inset_0_1px_2px_rgb(0_0_0/0.04)] transition placeholder:text-ink-3 hover:border-line-2 focus:border-brand focus:ring-4 focus:ring-brand/15 focus:outline-none",
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
        "h-9 rounded-[10px] border border-line bg-panel px-2.5 text-sm text-ink transition hover:border-line-2 focus:border-brand focus:ring-4 focus:ring-brand/15 focus:outline-none",
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
      <label htmlFor={controlId} className="block text-[13px] font-medium text-ink">
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
    <section
      className={cx("animate-rise rounded-2xl border border-line bg-panel shadow-card", className)}
    >
      {(title || actions) && (
        <header className="flex min-h-12 items-center justify-between gap-3 border-b border-line px-5 py-3">
          <h2 className="text-sm font-semibold tracking-tight text-ink">{title}</h2>
          {actions}
        </header>
      )}
      <div className={pad ? "p-5" : undefined}>{children}</div>
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
    <div className="mb-8 flex animate-rise flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-[-0.02em] text-ink sm:text-[28px]">
          {title}
        </h1>
        {subtitle && <p className="mt-1.5 text-sm text-ink-2">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export type Tone = "ok" | "warn" | "bad" | "idle" | "brand";

const tones: Record<Tone, string> = {
  ok: "bg-ok/10 text-ok ring-1 ring-inset ring-ok/25",
  warn: "bg-warn/10 text-warn ring-1 ring-inset ring-warn/25",
  bad: "bg-bad/10 text-bad ring-1 ring-inset ring-bad/25",
  idle: "bg-idle/10 text-ink-2 ring-1 ring-inset ring-idle/25",
  brand: "bg-brand/10 text-brand ring-1 ring-inset ring-brand/25",
};

export function Badge({ tone = "idle", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap",
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
  const text = {
    ok: "text-ok",
    warn: "text-warn",
    bad: "text-bad",
    idle: "text-idle",
    brand: "text-brand",
  }[tone];
  return (
    <span
      className={cx(
        "inline-block size-2 shrink-0 rounded-full",
        bg,
        text,
        tone === "bad" && "animate-pulse-ring",
      )}
      aria-hidden
    />
  );
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
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-16 text-center">
      <div className="relative mb-2 grid size-12 place-items-center rounded-2xl border border-line bg-panel-2 text-ink-3 shadow-card">
        <span className="absolute inset-0 rounded-2xl bg-gradient-brand opacity-[0.08]" />
        <svg
          viewBox="0 0 24 24"
          className="size-5"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.75"
          strokeLinecap="round"
          aria-hidden
        >
          <circle cx="12" cy="12" r="8" />
          <circle cx="12" cy="12" r="3" />
          <path d="M12 12l5-5" />
        </svg>
      </div>
      <p className="font-semibold tracking-tight text-ink">{title}</p>
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
    <div className={cx("rounded-xl border px-4 py-3 text-sm", border, tones[tone])}>{children}</div>
  );
}

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm [&_tbody_tr]:border-t [&_tbody_tr]:border-line [&_tbody_tr]:transition-colors [&_tbody_tr:hover]:bg-panel-2/50 [&_td]:px-5 [&_td]:py-3 [&_th]:bg-panel-2/40 [&_th]:px-5 [&_th]:py-2.5 [&_th]:text-[11px] [&_th]:font-semibold [&_th]:tracking-[0.06em] [&_th]:text-ink-3 [&_th]:uppercase">
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
  const tone =
    value >= bad ? "bg-bad" : value >= warn ? "bg-warn" : "bg-gradient-to-r from-brand to-brand-2";
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

export { CopyBlock } from "@/components/copy-block";

/** A headline number with a label, for overview rows. */
export function Stat({
  label,
  value,
  tone,
  href,
  hint,
}: {
  label: ReactNode;
  value: ReactNode;
  tone?: Tone;
  href?: string;
  hint?: ReactNode;
}) {
  const body = (
    <>
      <div className="flex items-center gap-2 text-xs font-medium text-ink-2">
        {tone && <Dot tone={tone} />}
        {label}
      </div>
      <div
        className={cx(
          "mt-3 text-[28px] leading-none font-semibold tracking-tight tabular",
          value === 0 && "text-ink-3",
        )}
      >
        {value}
      </div>
      {hint && <div className="mt-2 text-xs text-ink-3">{hint}</div>}
    </>
  );
  const cls =
    "group relative block animate-rise overflow-hidden rounded-2xl border border-line bg-panel p-4 shadow-card transition";
  return href ? (
    <Link href={href} className={cx(cls, "hover:-translate-y-0.5 hover:border-brand/40")}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  );
}
