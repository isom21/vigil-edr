import { ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { Density, Theme, UiPrefsContext } from "@/hooks/useUiPrefs";

const THEME_KEY = "vigil.ui.theme";
const DENSITY_KEY = "vigil.ui.density";

function readTheme(): Theme {
  const v = localStorage.getItem(THEME_KEY);
  return v === "light" ? "light" : "dark";
}

function readDensity(): Density {
  const v = localStorage.getItem(DENSITY_KEY);
  return v === "compact" ? "compact" : "comfortable";
}

function applyTheme(t: Theme) {
  const root = document.documentElement;
  // classList toggle is what flips Tailwind's `.dark:` variants. Both
  // themes are first-class now (Top-20 #13); dark stays the default
  // for first-load so existing analysts don't notice a flicker.
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
