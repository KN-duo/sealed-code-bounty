import type { ReactNode } from "react";
import { AlertTriangle, Inbox, PlugZap, RotateCw } from "lucide-react";
import type { AsyncState } from "../../lib/async";
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
          ? "Couldn't reach the Solana cluster. If you're on localnet, start the validator, then retry."
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
  empty,
  emptyTitle = "Nothing here yet",
  emptyMessage,
  children,
}: {
  state: AsyncState<T>;
  onRetry?: () => void;
  loading?: ReactNode;
  empty?: ReactNode;
  emptyTitle?: string;
  emptyMessage?: string;
  children: (data: T) => ReactNode;
}) {
  switch (state.kind) {
    case "loading":
      return <>{loading ?? <DefaultLoading />}</>;
    case "empty":
      return <>{empty ?? <EmptyState title={emptyTitle} message={emptyMessage} />}</>;
    case "error":
      return <ErrorState message={state.message} onRetry={onRetry} />;
    case "success":
      return <>{children(state.data)}</>;
  }
}

function DefaultLoading() {
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
