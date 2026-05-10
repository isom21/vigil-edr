import { createContext, useContext } from "react";

export type Theme = "dark" | "light";
export type Density = "comfortable" | "compact";

export interface UiPrefs {
  theme: Theme;
  density: Density;
  setTheme: (t: Theme) => void;
  setDensity: (d: Density) => void;
}

export const UiPrefsContext = createContext<UiPrefs | null>(null);

export function useUiPrefs(): UiPrefs {
  const v = useContext(UiPrefsContext);
  if (!v) throw new Error("useUiPrefs must be used inside <UiPrefsProvider>");
  return v;
}
