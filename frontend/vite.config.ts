import path from "node:path";
import { readFileSync } from "node:fs";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const pkg = JSON.parse(readFileSync(path.resolve(__dirname, "package.json"), "utf-8")) as {
  version: string;
};

export default defineConfig({
  plugins: [react()],
  define: {
    __VIGIL_VERSION__: JSON.stringify(pkg.version),
  },
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    port: 5173,
    // The manager is reached from arbitrary clients on the operator's
    // network (laptops, tailnet, internal LAN, port-forwards). The
    // Host header has no security value for us — production deploys
    // serve the built UI through a real reverse proxy that does its
    // own validation. Disable Vite's DNS-rebind check.
    allowedHosts: true,
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
