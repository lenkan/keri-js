import { cloudflare } from "@cloudflare/vite-plugin";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), cloudflare()],
  server: {
    // Bound explicitly, because "localhost" resolves to ::1 on some machines and
    // the dev server then listens on IPv6 only. KERIpy's HTTP client connects
    // over IPv4, so `kli oobi resolve` against this origin would hang.
    host: "127.0.0.1",
  },
});
