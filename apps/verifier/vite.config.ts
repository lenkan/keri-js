import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const VERIFIER_SERVER = process.env.VERIFIER_SERVER ?? "http://localhost:3002";

export default defineConfig({
  plugins: [react()],
  // Same-origin in dev, so the page needs no API base URL and no CORS. The
  // deployed build points at the verifier with VITE_VERIFIER_API instead.
  server: {
    proxy: {
      "/api": VERIFIER_SERVER,
      "/oobi": VERIFIER_SERVER,
    },
  },
});
