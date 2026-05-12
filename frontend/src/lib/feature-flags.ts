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
 *
 * No active flags right now. Re-add an entry when you need to gate
 * something that isn't done.
 */

export {};
