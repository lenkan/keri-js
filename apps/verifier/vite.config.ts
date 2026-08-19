import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const VERIFIER_SERVER = process.env.VERIFIER_SERVER ?? "http://localhost:3002";

export default defineConfig({
  plugins: [react()],
  // Dev runs the app and the verifier as two processes; deployed, the verifier
  // serves this build itself. The proxy is what makes both same-origin.
  server: {
    proxy: {
      "/api": VERIFIER_SERVER,
      "/oobi": VERIFIER_SERVER,
    },
  },
});
