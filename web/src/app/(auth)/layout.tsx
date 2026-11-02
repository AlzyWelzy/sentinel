import Link from "next/link";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-4 py-12">
      <Link href="/" className="mb-8 flex items-center gap-2 text-lg font-semibold text-ink">
        <span className="inline-block size-6 rounded-md bg-brand" aria-hidden />
        Pulsegrid
      </Link>
      <div className="w-full max-w-sm rounded-xl border border-line bg-panel p-6 shadow-sm">
        {children}
      </div>
    </main>
  );
}
