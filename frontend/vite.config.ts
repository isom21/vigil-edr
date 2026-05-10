import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
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
