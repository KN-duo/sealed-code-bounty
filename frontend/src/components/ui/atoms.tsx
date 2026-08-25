import type { CSSProperties, HTMLAttributes, ReactNode } from "react";
import { formatSol } from "../../lib/format";
import type { BN } from "@anchor-lang/core";

// Card ---------------------------------------------------------------------
interface CardProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode;
}
export function Card({ children, className = "", ...rest }: CardProps) {
  return (
    <div className={`card ${className}`.trim()} {...rest}>
      {children}
    </div>
  );
}

// Mono ---------------------------------------------------------------------
export function Mono({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <span className={`mono ${className}`.trim()}>{children}</span>;
}

// Pill (status / labels) ---------------------------------------------------
export function Pill({
  color,
  children,
  dot = true,
}: {
  color: string;
  children: ReactNode;
  dot?: boolean;
}) {
  return (
    <span className="pill" style={{ "--pill-color": color } as CSSProperties}>
      {dot && <span className="pill-dot" />}
      {children}
    </span>
  );
}

// SolAmount ----------------------------------------------------------------
export function SolAmount({ lamports, className = "" }: { lamports: BN | number; className?: string }) {
  return (
    <span className={`mono ${className}`.trim()}>
      {formatSol(lamports)} <span className="faint">SOL</span>
    </span>
  );
}

// StatBadge (label over value) --------------------------------------------
export function StatBadge({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="statbadge">
      <div className="statbadge-label">{label}</div>
      <div className="statbadge-value">{value}</div>
    </div>
  );
}
