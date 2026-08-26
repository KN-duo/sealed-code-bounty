import type { ReactNode } from "react";
import { AlertTriangle, Inbox, PlugZap, RotateCw } from "lucide-react";
import type { AsyncState } from "../../lib/async";
import { CLUSTER, RPC_URL } from "../../env";
import { Button } from "./Button";

export function Skeleton({ height = 16, width = "100%" }: { height?: number; width?: number | string }) {
  return <div className="skeleton" style={{ height, width }} />;
}

export function EmptyState({
  title,
  message,
  icon,
  action,
}: {
  title: string;
  message?: string;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="statebox">
      <div className="statebox-icon">{icon ?? <Inbox size={34} strokeWidth={1.5} />}</div>
      <h3>{title}</h3>
      {message && <p className="dim" style={{ margin: 0, maxWidth: 420 }}>{message}</p>}
      {action}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  // An offline network/service isn't an app error — it's an expected state
  // (especially on localnet before the validator is started). Present it calmly
  // and separately from a genuine failure.
  const offline = /reach the network|service running|offline|connection refused/i.test(message);
  return (
    <div className="statebox">
      <div
        className="statebox-icon"
        style={{ color: offline ? "var(--accent-amber)" : "var(--accent-red)" }}
      >
        {offline ? (
          <PlugZap size={34} strokeWidth={1.5} />
        ) : (
          <AlertTriangle size={34} strokeWidth={1.5} />
        )}
      </div>
      <h3>{offline ? "Network unavailable" : "Something went wrong"}</h3>
      <p className="dim" style={{ margin: 0, maxWidth: 460 }}>
        {offline
          ? CLUSTER === "localnet"
            ? "Couldn't reach the Solana cluster. If you're on localnet, start the validator, then retry."
            : `Couldn't reach the ${CLUSTER} RPC endpoint (${RPC_URL}). It looks unreachable — check VITE_RPC_URL and your connection, then retry.`
          : message}
      </p>
      {onRetry && (
        <Button onClick={onRetry}>
          <RotateCw size={15} /> Retry
        </Button>
      )}
    </div>
  );
}

// Render an AsyncState<T> through the four canonical states. `loading` and
// `empty` have sensible defaults so most callers only supply `success`.
export function AsyncView<T>({
  state,
  onRetry,
  loading,
  loadingVariant = "cards",
  empty,
  emptyTitle = "Nothing here yet",
  emptyMessage,
  children,
}: {
  state: AsyncState<T>;
  onRetry?: () => void;
  loading?: ReactNode;
  loadingVariant?: "cards" | "detail" | "list";
  empty?: ReactNode;
  emptyTitle?: string;
  emptyMessage?: string;
  children: (data: T) => ReactNode;
}) {
  switch (state.kind) {
    case "loading":
      return <>{loading ?? <LoadingSkeleton variant={loadingVariant} />}</>;
    case "empty":
      return <>{empty ?? <EmptyState title={emptyTitle} message={emptyMessage} />}</>;
    case "error":
      return <ErrorState message={state.message} onRetry={onRetry} />;
    case "success":
      return <>{children(state.data)}</>;
  }
}

function LoadingSkeleton({ variant }: { variant: "cards" | "detail" | "list" }) {
  if (variant === "detail") return <DetailLoading />;
  if (variant === "list") return <ListLoading />;
  return <CardsLoading />;
}

// Card grid — board-like views.
function CardsLoading() {
  return (
    <div className="grid-cards">
      {[0, 1, 2].map((i) => (
        <div key={i} className="card" style={{ padding: 18 }}>
          <Skeleton height={20} width="55%" />
          <div style={{ height: 12 }} />
          <Skeleton height={14} />
          <div style={{ height: 8 }} />
          <Skeleton height={14} width="70%" />
        </div>
      ))}
    </div>
  );
}

// Single tall page with a hero card + two columns — bounty detail / submit console.
function DetailLoading() {
  return (
    <div className="stack" style={{ gap: 20 }}>
      <Skeleton height={16} width={130} />
      <div className="card" style={{ padding: 24 }}>
        <div className="spread" style={{ flexWrap: "wrap", gap: 12 }}>
          <Skeleton height={20} width={150} />
          <Skeleton height={18} width={90} />
        </div>
        <div style={{ margin: "22px 0" }}>
          <Skeleton height={40} width="35%" />
        </div>
        <div className="fact-grid">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="statbadge" style={{ gap: 8 }}>
              <Skeleton height={11} width="45%" />
              <Skeleton height={15} width="80%" />
            </div>
          ))}
        </div>
      </div>
      <div className="detail-cols">
        {[0, 1].map((i) => (
          <div key={i} className="card" style={{ padding: 22 }}>
            <Skeleton height={17} width="40%" />
            <div style={{ height: 14 }} />
            <Skeleton height={13} />
            <div style={{ height: 10 }} />
            <Skeleton height={13} width="70%" />
            <div style={{ height: 10 }} />
            <Skeleton height={13} width="55%" />
          </div>
        ))}
      </div>
    </div>
  );
}

// Stacked rows — manage-style lists.
function ListLoading() {
  return (
    <div className="stack" style={{ gap: 14 }}>
      {[0, 1, 2].map((i) => (
        <div key={i} className="card" style={{ padding: 18 }}>
          <div className="spread" style={{ flexWrap: "wrap", gap: 10 }}>
            <Skeleton height={18} width="45%" />
            <Skeleton height={16} width={70} />
          </div>
          <div style={{ height: 14 }} />
          <Skeleton height={13} width="60%" />
        </div>
      ))}
    </div>
  );
}
