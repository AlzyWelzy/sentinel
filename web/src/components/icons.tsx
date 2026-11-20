/** A small line-icon set (24px grid, 1.75 stroke), drawn here so the app
 * carries no icon dependency. */
import type { SVGProps } from "react";

const PATHS = {
  overview: "M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z",
  servers: "M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01M12 7h4M12 17h4",
  fleet: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
  network: "M9 2h6v5H9zM2 17h6v5H2zM16 17h6v5h-6zM12 7v5M5 17v-5h14v5",
  incidents:
    "M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01",
  rules: "M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.9 1.9 0 0 0 3.4 0",
  checks:
    "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20",
  oncall:
    "M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3 19.5 19.5 0 0 1-6-6 19.8 19.8 0 0 1-3-8.7A2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1.9.4 1.8.7 2.7a2 2 0 0 1-.5 2.1L8 9.8a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.4c.9.3 1.8.6 2.7.7a2 2 0 0 1 1.7 2z",
  maintenance:
    "M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.8-3.8a6 6 0 0 1-7.9 7.9l-6.9 6.9a2.1 2.1 0 0 1-3-3l6.9-6.9a6 6 0 0 1 7.9-7.9z",
  status: "M22 12h-4l-3 9L9 3l-3 9H2",
  logs: "M4 6h16M4 10h16M4 14h10M4 18h7",
  apm: "M12 20V10M18 20V4M6 20v-4",
  dashboards: "M3 3h18v18H3zM3 9h18M9 21V9",
  reports: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 13h8M8 17h5",
  insights: "M9 18h6M10 22h4M12 2a7 7 0 0 0-4 12.7V16h8v-1.3A7 7 0 0 0 12 2z",
  contacts: "M4 4h16v16H4zM4 7l8 6 8-6",
  organisation:
    "M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8",
  tokens:
    "M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4",
  audit: "M12 8v4l3 3M3.05 11a9 9 0 1 1 .5 4M3 4v5h5",
  account: "M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z",
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  plus: "M12 5v14M5 12h14",
  arrow: "M5 12h14M13 6l6 6-6 6",
  check: "M20 6 9 17l-5-5",
  menu: "M4 6h16M4 12h16M4 18h16",
  sun: "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
  moon: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",
  monitor: "M2 3h20v14H2zM8 21h8M12 17v4",
  logout: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9",
  bolt: "M13 2 3 14h9l-1 8 10-12h-9z",
  layers: "M12 2 2 7l10 5 10-5zM2 17l10 5 10-5M2 12l10 5 10-5",
  mail: "M4 4h16v16H4zM4 7l8 6 8-6",
  globe:
    "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20",
  terminal: "M4 17l6-5-6-5M12 19h8",
  users:
    "M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8",
  database:
    "M12 8c4.4 0 8-1.3 8-3s-3.6-3-8-3-8 1.3-8 3 3.6 3 8 3zM4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
  chevron: "M6 9l6 6 6-6",
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({
  name,
  className = "size-4",
  ...rest
}: { name: IconName } & SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      className={className}
      {...rest}
    >
      <path d={PATHS[name]} />
    </svg>
  );
}

/** Sentinel's mark: a radar sweep inside a rounded square. The gradient is
 * CSS, not an SVG <linearGradient>, whose id would clash between copies (the
 * hidden sidebar's would win and the visible one would render blank). */
export function Logo({ className = "size-6" }: { className?: string }) {
  return (
    <span
      aria-hidden
      className={`inline-grid shrink-0 place-items-center rounded-[28%] bg-gradient-brand ${className}`}
    >
      <svg viewBox="0 0 32 32" className="size-full">
        <circle
          cx="16"
          cy="16"
          r="8.5"
          fill="none"
          stroke="#fff"
          strokeOpacity=".45"
          strokeWidth="1.6"
        />
        <circle
          cx="16"
          cy="16"
          r="4"
          fill="none"
          stroke="#fff"
          strokeOpacity=".7"
          strokeWidth="1.6"
        />
        <path d="M16 16 L22.5 9.5" stroke="#fff" strokeWidth="2.2" strokeLinecap="round" />
        <circle cx="16" cy="16" r="1.8" fill="#fff" />
      </svg>
    </span>
  );
}
