import { useCallback, useEffect, useState } from "react";
import type { DependencyList } from "react";
import type { AsyncState } from "../lib/async";
import { loading, empty, failure, success, toMessage } from "../lib/async";

// Runs an async fetcher and maps the result into an AsyncState<T>, with a
// `reload` for retry buttons. `isEmpty` distinguishes the empty state from a
// non-empty success (e.g. an empty array).
export function useAsync<T>(
  fetcher: () => Promise<T>,
  deps: DependencyList,
  isEmpty?: (data: T) => boolean,
): { state: AsyncState<T>; reload: () => void } {
  const [state, setState] = useState<AsyncState<T>>(loading);
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    let alive = true;
    setState(loading());
    fetcher()
      .then((data) => {
        if (!alive) return;
        setState(isEmpty && isEmpty(data) ? empty() : success(data));
      })
      .catch((err) => {
        if (!alive) return;
        setState(failure(toMessage(err)));
      });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  return { state, reload };
}
