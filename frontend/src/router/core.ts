import { useEffect, useState } from "react";

// Hash-router primitives (no JSX) — kept apart from the Link component so the
// module boundary is clean and fast-refresh stays happy.

export function currentPath(): string {
  const h = window.location.hash.replace(/^#/, "");
  return h.length > 0 ? h : "/";
}

export function navigate(to: string): void {
  window.location.hash = to.startsWith("/") ? to : `/${to}`;
}

export function useHashPath(): string {
  const [path, setPath] = useState(currentPath);
  useEffect(() => {
    const onChange = () => setPath(currentPath());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return path;
}

// Match "/bounty/:pda" against "/bounty/abc" -> { pda: "abc" }, else null.
export function matchPath(pattern: string, path: string): Record<string, string> | null {
  const pp = pattern.split("/").filter(Boolean);
  const ap = path.split("/").filter(Boolean);
  if (pp.length !== ap.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < pp.length; i++) {
    if (pp[i].startsWith(":")) params[pp[i].slice(1)] = decodeURIComponent(ap[i]);
    else if (pp[i] !== ap[i]) return null;
  }
  return params;
}
