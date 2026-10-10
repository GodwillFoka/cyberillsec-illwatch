import type { ReactNode } from "react";

import { RealtimeProvider } from "../realtime/RealtimeProvider";
import { Nav } from "./Nav";
import { TopBar } from "./TopBar";

export function Shell({ children }: { children: ReactNode }) {
  return (
    <RealtimeProvider>
      <div className="shell">
        <Nav />
        <TopBar />
        <main className="main" id="contenu">
          {children}
        </main>
      </div>
    </RealtimeProvider>
  );
}
