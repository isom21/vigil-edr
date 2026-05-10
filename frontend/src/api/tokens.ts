/**
 * Token storage in localStorage. A small abstraction so we can swap to
 * httpOnly cookies later without touching call sites.
 */
const ACCESS_KEY = "edr.access";
const REFRESH_KEY = "edr.refresh";

type Listener = () => void;
const listeners = new Set<Listener>();

export const tokenStore = {
  getAccessToken: () => localStorage.getItem(ACCESS_KEY),
  getRefreshToken: () => localStorage.getItem(REFRESH_KEY),
  setTokens(access: string, refresh: string) {
    localStorage.setItem(ACCESS_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
    listeners.forEach((l) => l());
  },
  clear() {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
    listeners.forEach((l) => l());
  },
  subscribe(l: Listener): () => void {
    listeners.add(l);
    return () => {
      listeners.delete(l);
    };
  },
};
