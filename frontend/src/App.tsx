import type { ReactNode } from "react";
import { useHashPath, matchPath } from "./router";
import { AppShell } from "./components/layout/AppShell";
import { Board } from "./pages/Board";
import { Leaderboard } from "./pages/Leaderboard";
import { PostBounty } from "./pages/PostBounty";
import { Manage } from "./pages/Manage";
import { BountyDetail } from "./pages/BountyDetail";
import { SubmitConsole } from "./pages/SubmitConsole";
import { NotFound } from "./pages/NotFound";

interface RouteDef {
  pattern: string;
  render: (params: Record<string, string>) => ReactNode;
}

const ROUTES: RouteDef[] = [
  { pattern: "/", render: () => <Board /> },
  { pattern: "/leaderboard", render: () => <Leaderboard /> },
  { pattern: "/post", render: () => <PostBounty /> },
  { pattern: "/manage", render: () => <Manage /> },
  { pattern: "/bounty/:pda", render: (p) => <BountyDetail pda={p.pda} /> },
  { pattern: "/hunt/:pda", render: (p) => <SubmitConsole pda={p.pda} /> },
];

export default function App() {
  const path = useHashPath();

  let content: ReactNode = <NotFound />;
  for (const route of ROUTES) {
    const params = matchPath(route.pattern, path);
    if (params) {
      content = route.render(params);
      break;
    }
  }

  return <AppShell>{content}</AppShell>;
}
