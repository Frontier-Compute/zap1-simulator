import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      external: ["/wasm/zap1_verify_wasm.js"],
    },
  },
});
