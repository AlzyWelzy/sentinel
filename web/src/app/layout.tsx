import type { Metadata, Viewport } from "next";
import { Barlow, Barlow_Condensed, JetBrains_Mono } from "next/font/google";

import { themeScript } from "@/components/theme";
import { Providers } from "@/lib/session";

import "./globals.css";

const body = Barlow({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-body",
});
const condensed = Barlow_Condensed({
  subsets: ["latin"],
  weight: ["500", "600", "700"],
  variable: "--font-condensed",
});
const data = JetBrains_Mono({ subsets: ["latin"], variable: "--font-data" });

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#dfe1dc" },
    { media: "(prefers-color-scheme: dark)", color: "#121416" },
  ],
};

export const metadata: Metadata = {
  title: { default: "Sentinel", template: "%s · Sentinel" },
  description:
    "Server and uptime monitoring with alerts that say exactly what failed. Metrics, logs, uptime checks and status pages.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${body.variable} ${condensed.variable} ${data.variable}`}
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
