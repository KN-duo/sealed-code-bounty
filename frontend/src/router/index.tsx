import { useEffect, useState, useCallback } from "react";
import type { AnchorHTMLAttributes, MouseEvent, ReactNode } from "react";

// A ~60-line hash router. react-router isn't in the allowed dependency set, and
// hash routing needs zero server config — perfect for a localnet-first dApp.

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

interface LinkProps extends AnchorHTMLAttributes<HTMLAnchorElement> {
  to: string;
  children: ReactNode;
}

export function Link({ to, children, onClick, ...rest }: LinkProps) {
  const handle = useCallback(
    (e: MouseEvent<HTMLAnchorElement>) => {
      // Let modified clicks (new tab) behave natively; otherwise SPA-navigate.
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      e.preventDefault();
      navigate(to);
      onClick?.(e);
    },
    [to, onClick],
  );
  return (
    <a href={`#${to}`} onClick={handle} {...rest}>
      {children}
    </a>
  );
}
