import type { Metadata } from "next";

import { themeScript } from "@/components/theme";
import { Providers } from "@/lib/session";

import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Sentinel", template: "%s · Sentinel" },
  description: "Server and uptime monitoring.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
