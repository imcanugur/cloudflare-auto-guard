import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": new URL("./", import.meta.url).pathname
    }
  },
  test: {
    globals: true,
    environment: "node",
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"]
    }
  }
});
