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
    "plate px-4 text-[15px] tracking-[0.07em] hover:bg-[color-mix(in_srgb,var(--plate)_86%,var(--bad))]",
  secondary: "bg-panel border border-line-2 text-ink shadow-card hover:bg-panel-2",
  ghost: "text-ink-2 hover:bg-panel-2 hover:text-ink",
  danger: "bg-bad text-on-status hover:bg-[color-mix(in_srgb,var(--bad)_88%,black)]",
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
        "inline-flex h-9 items-center justify-center gap-2 rounded-[3px] px-3.5 text-sm font-medium whitespace-nowrap transition-[transform,background-color,border-color,color] duration-150 ease-(--ease-out) select-none active:scale-[0.97] disabled:cursor-not-allowed disabled:opacity-50 disabled:active:scale-100",
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
        "inline-flex h-9 items-center justify-center gap-2 rounded-[3px] px-3.5 text-sm font-medium whitespace-nowrap transition-[transform,background-color,border-color,color] duration-150 ease-(--ease-out) active:scale-[0.97]",
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
        "h-9 w-full rounded-[3px] border border-line-2 bg-panel px-3 text-sm text-ink shadow-[inset_0_1px_2px_rgb(0_0_0/0.06)] transition-[border-color,box-shadow] duration-150 placeholder:text-ink-3 hover:border-ink-3 focus:border-brand focus:ring-2 focus:ring-brand/25 focus:outline-none",
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
        "h-9 max-w-full truncate rounded-[3px] border border-line-2 bg-panel px-2.5 text-sm text-ink transition-[border-color,box-shadow] duration-150 hover:border-ink-3 focus:border-brand focus:ring-2 focus:ring-brand/25 focus:outline-none",
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
      className={cx("min-w-0 rounded-[3px] border border-line bg-panel shadow-card", className)}
    >
      {(title || actions) && (
        <header className="flex min-h-11 items-center justify-between gap-3 border-b border-line bg-panel-2/60 px-4 py-2">
          <h2 className="font-plate text-[15px] font-semibold tracking-[0.06em] text-ink uppercase">
            {title}
          </h2>
          {actions}
        </header>
      )}
      <div className={pad ? "p-4 sm:p-5" : undefined}>{children}</div>
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
    <div className="mb-7 flex flex-wrap items-end justify-between gap-4 border-b-2 border-ink pb-4">
      <div className="min-w-0">
        <h1 className="font-plate text-[30px] leading-none font-bold tracking-[0.005em] [overflow-wrap:anywhere] text-ink sm:text-[38px]">
          {title}
        </h1>
        {subtitle && <p className="mt-2 text-sm [overflow-wrap:anywhere] text-ink-2">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export type Tone = "ok" | "warn" | "bad" | "idle" | "brand";

const tones: Record<Tone, string> = {
  ok: "bg-ok/12 text-ok ring-1 ring-inset ring-ok/35",
  warn: "bg-warn/12 text-warn ring-1 ring-inset ring-warn/40",
  bad: "bg-bad text-on-status ring-1 ring-inset ring-bad [&>[aria-hidden]]:bg-on-status",
  idle: "bg-idle/12 text-ink-2 ring-1 ring-inset ring-idle/35",
  brand: "bg-brand/10 text-brand ring-1 ring-inset ring-brand/30",
};

export function Badge({ tone = "idle", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-[2px] px-1.5 py-px font-plate text-[12.5px] font-semibold tracking-[0.06em] whitespace-nowrap uppercase",
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
        "inline-block h-2.5 w-1.5 shrink-0 rounded-[1px]",
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
        "inline-block animate-[spin_0.6s_linear_infinite] rounded-full border-2 border-current border-t-transparent",
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
      <svg
        viewBox="0 0 32 40"
        className="mb-2 h-10 w-8 text-ink-3"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden
      >
        <rect x="2" y="2" width="28" height="36" rx="1.5" />
        <rect x="11" y="9" width="10" height="22" rx="1" />
        <rect x="12.5" y="10.5" width="7" height="9" rx="0.5" fill="currentColor" />
      </svg>
      <p className="font-plate text-lg font-semibold tracking-[0.04em] text-ink uppercase">
        {title}
      </p>
      {children && (
        <p className="max-w-md text-sm [overflow-wrap:anywhere] text-ink-2">{children}</p>
      )}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  const missing = /not found|nothing here/i.test(message);
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-20 text-center">
      <div
        className={cx(
          "grid size-11 place-items-center rounded-[3px] border",
          missing ? "border-line bg-panel-2 text-ink-3" : "border-bad/25 bg-bad/10 text-bad",
        )}
      >
        <svg
          viewBox="0 0 24 24"
          className="size-5"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.75"
          strokeLinecap="round"
          aria-hidden
        >
          {missing ? (
            <path d="M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4" />
          ) : (
            <path d="M12 8v5M12 16.5h.01M12 3l9.5 17h-19z" />
          )}
        </svg>
      </div>
      <p className="font-plate text-lg font-semibold tracking-[0.04em] text-ink uppercase">
        {missing ? "We couldn't find that" : "Something went wrong"}
      </p>
      <p className="max-w-md text-sm text-ink-2">{message}</p>
      <div className="mt-2 flex gap-2">
        {retry && !missing && (
          <Button onClick={retry} variant="secondary">
            Try again
          </Button>
        )}
        <LinkButton href="/overview" variant={missing ? "secondary" : "ghost"}>
          Back to overview
        </LinkButton>
      </div>
    </div>
  );
}

const noticeTones: Record<Tone, string> = {
  ...tones,
  bad: "bg-bad/10 text-bad ring-1 ring-inset ring-bad/30",
};

export function Notice({ tone = "idle", children }: { tone?: Tone; children: ReactNode }) {
  const border = {
    ok: "border-ok/30",
    warn: "border-warn/30",
    bad: "border-bad/30",
    idle: "border-line",
    brand: "border-brand/30",
  }[tone];
  return (
    <div className={cx("rounded-[3px] border px-4 py-3 text-sm", border, noticeTones[tone])}>
      {children}
    </div>
  );
}

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm [&_tbody_tr]:border-t [&_tbody_tr]:border-line [&_tbody_tr:hover]:bg-panel-2/70 [&_td]:px-4 [&_td]:py-2.5 [&_th]:border-b [&_th]:border-line-2 [&_th]:bg-panel-2 [&_th]:px-4 [&_th]:py-2 [&_th]:font-plate [&_th]:text-[12.5px] [&_th]:font-semibold [&_th]:tracking-[0.08em] [&_th]:text-ink-2 [&_th]:uppercase">
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
  const tone = value >= bad ? "bg-bad" : value >= warn ? "bg-warn" : "bg-ink-2";
  return (
    <div className="flex min-w-24 items-center gap-2">
      <div className="relative h-2 flex-1 overflow-hidden rounded-[1px] border border-line bg-panel-2">
        <div className={cx("h-full", tone)} style={{ width: `${Math.min(100, value)}%` }} />
        {/* Scale ticks every 10%, like a bar meter's face. */}
        <div className="pointer-events-none absolute inset-0 bg-[repeating-linear-gradient(90deg,transparent_0_calc(10%-1px),var(--panel)_calc(10%-1px)_10%)]" />
      </div>
      <span
        className={cx(
          "w-10 text-right font-mono text-xs tabular",
          value >= bad ? "text-bad" : value >= warn ? "text-warn" : "text-ink-2",
        )}
      >
        {value.toFixed(0)}%
      </span>
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
      <div className="flex items-center gap-2 font-plate text-[13px] font-semibold tracking-[0.08em] text-ink-2 uppercase">
        {tone && <Dot tone={tone} />}
        {label}
      </div>
      <div
        className={cx(
          "mt-2 font-mono text-[26px] leading-none font-medium tabular",
          value === 0 && "text-ink-3",
        )}
      >
        {value}
      </div>
      {hint && <div className="mt-2 text-xs text-ink-3">{hint}</div>}
    </>
  );
  const cls =
    "group relative block overflow-hidden rounded-[3px] border border-line bg-panel px-4 py-3.5 shadow-card transition-colors duration-150";
  return href ? (
    <Link href={href} className={cx(cls, "hover:border-ink-3 hover:bg-panel-2")}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  );
}

/** A breaker handle: up and dark when the circuit is energized, thrown down
 * in trip orange when it tripped. The flip is the one motion the panel owns. */
export function Breaker({ state }: { state: "on" | "tripped" | "off" | "warn" }) {
  const down = state === "tripped" || state === "off";
  const fill =
    state === "tripped"
      ? "fill-bad"
      : state === "warn"
        ? "fill-warn"
        : state === "off"
          ? "fill-idle"
          : "fill-ink";
  return (
    <svg viewBox="0 0 14 24" className="h-6 w-3.5 shrink-0" aria-hidden>
      <rect
        x="0.75"
        y="0.75"
        width="12.5"
        height="22.5"
        rx="1.5"
        className="fill-panel-2 stroke-line-2"
        strokeWidth="1.5"
      />
      <rect
        x="3"
        y="3"
        width="8"
        height="9"
        rx="1"
        className={cx(fill, "transition-transform duration-[160ms] ease-(--ease-out)")}
        style={{ transform: down ? "translateY(9px)" : undefined }}
      />
    </svg>
  );
}
