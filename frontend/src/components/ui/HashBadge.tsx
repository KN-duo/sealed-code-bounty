import { useState } from "react";
import { Copy, Check } from "lucide-react";
import { truncate, copyToClipboard } from "../../lib/format";

// A machine value (hash, pubkey, commitment) shown truncated with one-click copy.
export function HashBadge({
  value,
  head = 6,
  tail = 6,
  title,
}: {
  value: string;
  head?: number;
  tail?: number;
  title?: string;
}) {
  const [copied, setCopied] = useState(false);

  async function onCopy() {
    const ok = await copyToClipboard(value);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    }
  }

  return (
    <button
      type="button"
      className="hashbadge"
      onClick={onCopy}
      title={title ?? `Copy ${value}`}
    >
      {truncate(value, head, tail)}
      {copied ? <Check size={12} color="var(--accent-green)" /> : <Copy size={12} />}
    </button>
  );
}
