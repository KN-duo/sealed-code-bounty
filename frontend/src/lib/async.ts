// One shape for every asynchronous view in the app. A view is always in exactly
// one of four states, so "loading forever" and "silent failure" are unrepresentable.

export type AsyncState<T> =
  | { kind: "loading" }
  | { kind: "empty" }
  | { kind: "error"; message: string }
  | { kind: "success"; data: T };

export const loading = <T>(): AsyncState<T> => ({ kind: "loading" });
export const empty = <T>(): AsyncState<T> => ({ kind: "empty" });
export const failure = <T>(message: string): AsyncState<T> => ({ kind: "error", message });
export const success = <T>(data: T): AsyncState<T> => ({ kind: "success", data });

// Turn a thrown value into a human-readable, specific message. Solana / fetch
// errors are notoriously opaque; this is the single place we translate them.
export function toMessage(err: unknown): string {
  if (err instanceof Error) {
    const m = err.message;
    if (m.includes("Failed to fetch") || m.includes("NetworkError") || m.includes("fetch failed")) {
      return "Could not reach the network. Is the service running?";
    }
    if (m.includes("ECONNREFUSED") || m.includes("Connection refused")) {
      return "Connection refused — the endpoint is offline.";
    }
    return m;
  }
  if (typeof err === "string") return err;
  return "An unexpected error occurred.";
}
