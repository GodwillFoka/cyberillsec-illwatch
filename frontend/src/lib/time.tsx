// Fuseau d'affichage : UTC par défaut (convention SOC), heure locale en option.
import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

interface TimeValue {
  utc: boolean;
  toggle: () => void;
}

const TimeContext = createContext<TimeValue>({ utc: true, toggle: () => undefined });

export function TimeProvider({ children }: { children: ReactNode }) {
  const [utc, setUtc] = useState(true);
  const value = useMemo(() => ({ utc, toggle: () => setUtc((u) => !u) }), [utc]);
  return <TimeContext.Provider value={value}>{children}</TimeContext.Provider>;
}

export function useTimeZone(): TimeValue {
  return useContext(TimeContext);
}
