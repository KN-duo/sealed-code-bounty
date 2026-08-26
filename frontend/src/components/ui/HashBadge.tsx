import { useState } from "react";
import { Copy, Check, ExternalLink } from "lucide-react";
import { truncate, copyToClipboard } from "../../lib/format";

// A machine value (hash, pubkey, commitment) shown truncated with one-click copy.
// An optional href renders an external-link affordance (e.g. Solana Explorer)
// next to the copy control; null/absent means no link.
export function HashBadge({
  value,
  head = 6,
  tail = 6,
  title,
  href,
}: {
  value: string;
  head?: number;
  tail?: number;
  title?: string;
  href?: string | null;
}) {
  const [copied, setCopied] = useState(false);

  async function onCopy() {
    const ok = await copyToClipboard(value);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    }
  }

  const badge = (
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

  if (!href) return badge;

  return (
    <span className="hashbadge-group">
      {badge}
      <a
        className="hashbadge-ext"
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        aria-label={`View ${truncate(value)} on Solana Explorer`}
        title="View on Solana Explorer"
      >
        <ExternalLink size={12} />
      </a>
    </span>
  );
}
