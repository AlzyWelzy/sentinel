import type { MetadataRoute } from "next";

// Installable on phones and desktops: alerts arrive as notifications with
// Acknowledge on them (public/sw.js).
export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Sentinel",
    short_name: "Sentinel",
    description: "Server and uptime monitoring with alerts that say exactly what failed.",
    start_url: "/incidents",
    scope: "/",
    display: "standalone",
    background_color: "#121416",
    theme_color: "#121416",
    icons: [
      { src: "/icons/icon-192.png", sizes: "192x192", type: "image/png" },
      { src: "/icons/icon-512.png", sizes: "512x512", type: "image/png" },
      { src: "/icons/maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
    ],
    shortcuts: [
      { name: "Incidents", url: "/incidents" },
      { name: "Servers", url: "/servers" },
    ],
  };
}
