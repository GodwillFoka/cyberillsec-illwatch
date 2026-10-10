import { Outlet } from "react-router-dom";

import { RealtimeProvider } from "../realtime/RealtimeProvider";
import { Nav } from "./Nav";
import { TopBar } from "./TopBar";

export function Shell() {
  return (
    <RealtimeProvider>
      <div className="shell">
        <Nav />
        <TopBar />
        <main className="main" id="contenu">
          <Outlet />
        </main>
      </div>
    </RealtimeProvider>
  );
}
