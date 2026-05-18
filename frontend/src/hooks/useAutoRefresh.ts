import { useEffect, useRef } from "react";

export function useAutoRefresh(fn: () => void, enabled: boolean, intervalMs = 5000) {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => {
    if (!enabled) return;
    const id = setInterval(() => ref.current(), intervalMs);
    return () => clearInterval(id);
  }, [enabled, intervalMs]);
}
