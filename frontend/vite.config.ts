import { defineConfig } from "vite";

export default defineConfig({
  base: "/",
  build: {
    outDir: "dist",
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
