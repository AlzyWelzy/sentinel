import Link from "next/link";

import { Icon, Logo } from "@/components/icons";

const POINTS = [
  "Install in one command on Linux, BSD, Windows or Docker",
  "Alerts that name the disk, plugin or check that failed",
  "One email when a whole rack drops, not forty",
];

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid min-h-screen lg:grid-cols-[1fr_minmax(0,560px)]">
      <aside className="relative hidden overflow-hidden border-r-2 border-ink bg-plate text-plate-ink lg:flex lg:flex-col lg:justify-between lg:p-12">
        <Link href="/" className="relative flex items-center gap-3">
          <span className="grid size-9 place-items-center rounded-[2px] border border-plate-ink/40">
            <svg viewBox="0 0 32 32" className="size-7" aria-hidden>
              <rect
                x="11"
                y="6"
                width="10"
                height="20"
                rx="1"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.6"
              />
              <rect x="13" y="8" width="6" height="8" rx="0.6" fill="currentColor" />
            </svg>
          </span>
          <span className="font-plate text-2xl font-bold tracking-[0.12em] uppercase">
            Sentinel
          </span>
        </Link>
        <div className="relative max-w-md">
          <h2 className="font-plate text-5xl leading-[0.95] font-bold uppercase">
            Quiet when it&apos;s fine.
            <br />
            <span className="text-bad">Loud when it isn&apos;t.</span>
          </h2>
          <ul className="mt-8 border-t border-plate-ink/25 text-[15px]">
            {POINTS.map((p) => (
              <li key={p} className="flex gap-3 border-b border-plate-ink/25 py-3 opacity-85">
                <Icon name="check" className="mt-1 size-3.5 shrink-0" />
                {p}
              </li>
            ))}
          </ul>
        </div>
        <p className="relative font-mono text-sm opacity-60">sentinel.rajpoot.app</p>
      </aside>
      <main className="relative flex flex-col items-center justify-center px-4 py-12 sm:px-8">
        <Link href="/" className="relative mb-10 flex items-center gap-2.5 lg:hidden">
          <Logo className="size-8" />
          <span className="font-plate text-2xl font-bold tracking-[0.12em] uppercase">
            Sentinel
          </span>
        </Link>
        <div className="relative w-full max-w-sm [&_h1]:font-plate [&_h1]:text-3xl [&_h1]:font-bold [&_h1]:tracking-[0.02em] [&_h1]:uppercase">
          {children}
        </div>
      </main>
    </div>
  );
}
