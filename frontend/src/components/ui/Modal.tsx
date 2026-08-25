import { useEffect } from "react";
import type { ReactNode } from "react";
import { X } from "lucide-react";
import { Card } from "./atoms";

export function Modal({
  open,
  title,
  onClose,
  children,
}: {
  open: boolean;
  title?: ReactNode;
  onClose: () => void;
  children: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <Card className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="spread" style={{ marginBottom: 16 }}>
          <h3>{title}</h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>
        {children}
      </Card>
    </div>
  );
}
