import { useCallback } from "react";
import type { AnchorHTMLAttributes, MouseEvent, ReactNode } from "react";
import { navigate } from "./core";

// Router primitives live in ./core (no JSX). This module exports only the Link
// component, so fast-refresh stays happy.

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
