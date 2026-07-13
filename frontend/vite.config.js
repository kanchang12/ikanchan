import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// npm run build  ->  outputs the site into ../static  (Flask serves it)
// npm run dev    ->  dev server on :5173, /api proxied to Flask on :8000
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: { outDir: "../static", emptyOutDir: true },
  server: { proxy: { "/api": "http://localhost:8000" } },
});
