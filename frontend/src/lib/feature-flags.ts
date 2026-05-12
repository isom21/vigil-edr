/// <reference types="vite/client" />

/**
 * Compile-time feature flags driven by Vite env vars (VITE_*).
 *
 * These are evaluated once at module load, so flipping the underlying
 * env var requires a full restart of the dev server / a fresh build.
 *
 * Keep this list short — it's a holding pen for things we'd like to
 * remove (because the gated path needs more work) rather than a
 * permanent runtime-config surface.
 */

/** Review HIGH #12: light theme has known visual breakage (invisible
 * sparkline on white, missing donut centre after toggle, --muted-
 * foreground ≈ 4.0:1 on white fails WCAG AA). The toggle is hidden in
 * production builds until parity ships; set
 * `VITE_VIGIL_UI_LIGHT_THEME=1` in the dev env to get the preview
 * surface back. */
export const LIGHT_THEME_ENABLED =
  import.meta.env.VITE_VIGIL_UI_LIGHT_THEME === "1" ||
  import.meta.env.VITE_VIGIL_UI_LIGHT_THEME === "true";
