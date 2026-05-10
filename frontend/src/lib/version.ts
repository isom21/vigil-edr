// Single source of truth for the human-visible Vigil version. The
// value is injected at build time by Vite's `define` config from
// package.json's `version` field; bumping there flows through to
// the sidebar and any other surface that imports `APP_VERSION`.

declare const __VIGIL_VERSION__: string;

export const APP_VERSION: string =
  // Vite replaces __VIGIL_VERSION__ at build time. Fall back to
  // "dev" if someone runs the source through a non-Vite tool.
  typeof __VIGIL_VERSION__ === "string" ? __VIGIL_VERSION__ : "dev";
