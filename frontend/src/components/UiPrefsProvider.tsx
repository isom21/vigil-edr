import { ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { Density, Theme, UiPrefsContext } from "@/hooks/useUiPrefs";
import { LIGHT_THEME_ENABLED } from "@/lib/feature-flags";

const THEME_KEY = "vigil.ui.theme";
const DENSITY_KEY = "vigil.ui.density";

function readTheme(): Theme {
  if (!LIGHT_THEME_ENABLED) return "dark";
  const v = localStorage.getItem(THEME_KEY);
  return v === "light" ? "light" : "dark";
}

function readDensity(): Density {
  const v = localStorage.getItem(DENSITY_KEY);
  return v === "compact" ? "compact" : "comfortable";
}

function applyTheme(t: Theme) {
  const root = document.documentElement;
  // Even when LIGHT_THEME_ENABLED is on, the classList toggle is what
  // actually flips Tailwind's `.dark:` variants. Off-flag still calls
  // through here with t === "dark" (forced above), so the class is
  // applied exactly once.
  if (t === "dark") root.classList.add("dark");
  else root.classList.remove("dark");
}

export function UiPrefsProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => readTheme());
  const [density, setDensityState] = useState<Density>(() => readDensity());

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const setTheme = useCallback((t: Theme) => {
    // No-op when the flag is off — keeps the app dark even if some
    // older caller still tries to flip the theme.
    if (!LIGHT_THEME_ENABLED) return;
    localStorage.setItem(THEME_KEY, t);
    setThemeState(t);
  }, []);

  const setDensity = useCallback((d: Density) => {
    localStorage.setItem(DENSITY_KEY, d);
    setDensityState(d);
  }, []);

  const value = useMemo(
    () => ({ theme, density, setTheme, setDensity }),
    [theme, density, setTheme, setDensity],
  );

  return <UiPrefsContext.Provider value={value}>{children}</UiPrefsContext.Provider>;
}
