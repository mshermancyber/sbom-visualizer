import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // happy-dom provides a lightweight DOM (window/location/document) for both
    // the pure-utility tests (util.safeUrl needs an origin) and the Compare
    // view render test. Chosen over jsdom, which has ESM/CJS interop issues
    // with its css-color dependency under this Node + vitest pool.
    environment: "happy-dom",
    include: ["src/**/*.test.ts"],
  },
});
