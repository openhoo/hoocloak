import { resolve } from "node:path";
import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

export default defineConfig({
  plugins: [solid()],
  build: {
    outDir: resolve(import.meta.dirname, "../../internal/idp/ui/dist"),
    emptyOutDir: true,
    sourcemap: false,
    minify: "oxc",
    lib: {
      entry: resolve(import.meta.dirname, "src/main.tsx"),
      formats: ["es"],
      fileName: "login",
      cssFileName: "login",
    },
    rolldownOptions: {
      output: {
        entryFileNames: "login.js",
        assetFileNames: "login.css",
      },
    },
  },
});
