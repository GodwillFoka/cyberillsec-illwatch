import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// En développement, Vite sert l'interface sur :5173 et relaie l'API vers FastAPI (:8000) :
// même origine vue du navigateur, comme en production (ADR-016), donc ni CORS ni jeton exposé.
const api = process.env.ILLWATCH_API ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: api, changeOrigin: false },
      "/health": { target: api },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    // Pas de script ni de style en ligne : compatible avec la politique `script-src 'self'`.
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 900,
  },
});
