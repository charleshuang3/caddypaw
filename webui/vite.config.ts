import { defineConfig } from "vitest/config";
import vue from "@vitejs/plugin-vue";
import tailwindcss from "@tailwindcss/vite";

const apiTarget = process.env.VITE_API_TARGET ?? "http://127.0.0.1:8082";

export default defineConfig({
  base: "./",
  plugins: [vue(), tailwindcss()],
  server: {
    port: 5173,
    host: "127.0.0.1",
    proxy: {
      "/api": {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
  test: {
    execArgv: ["--disable-warning=ExperimentalWarning"],
    setupFiles: ["./src/test/setup.ts"],
  },
});
