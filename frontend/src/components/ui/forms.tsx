import { useRef, useState } from "react";
import type { InputHTMLAttributes, ReactNode, TextareaHTMLAttributes } from "react";
import { AlertCircle, Upload, FileText } from "lucide-react";

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="field">
      <label>{label}</label>
      {children}
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  const { className = "", ...rest } = props;
  return <input className={`input ${className}`.trim()} {...rest} />;
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const { className = "", ...rest } = props;
  return <textarea className={`textarea ${className}`.trim()} {...rest} />;
}

// Drag-and-drop / click-to-pick file input. Reads the file as text and hands
// back its name + contents. Accepts an optional accept filter, an optional
// maxBytes cap, and an optional onError sink for read/size failures (rendered
// inside the zone itself when no sink is supplied).
export function FileDrop({
  accept,
  label = "Drop a file here or click to browse",
  loadedName,
  maxBytes,
  onFile,
  onError,
}: {
  accept?: string;
  label?: string;
  loadedName?: string | null;
  maxBytes?: number;
  onFile: (name: string, contents: string) => void;
  onError?: (message: string) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  function report(message: string) {
    setLocalError(message);
    onError?.(message);
  }

  function read(file: File) {
    setLocalError(null);
    if (maxBytes != null && file.size > maxBytes) {
      report(
        `"${file.name}" is ${file.size.toLocaleString()} bytes — larger than the ${maxBytes.toLocaleString()} byte limit.`,
      );
      return;
    }
    const reader = new FileReader();
    reader.onload = () => onFile(file.name, String(reader.result ?? ""));
    reader.onerror = () =>
      report(
        reader.error?.message
          ? `Could not read "${file.name}": ${reader.error.message}`
          : `Could not read "${file.name}".`,
      );
    reader.readAsText(file);
  }

  return (
    <div
      className={`filedrop ${dragging ? "filedrop-active" : ""} ${loadedName ? "filedrop-loaded" : ""}`.trim()}
      role="button"
      tabIndex={0}
      aria-label={accept ? `${label} — accepts ${accept}` : label}
      onClick={() => inputRef.current?.click()}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          inputRef.current?.click();
        }
      }}
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const file = e.dataTransfer.files[0];
        if (file) read(file);
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        style={{ display: "none" }}
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) read(file);
          e.target.value = "";
        }}
      />
      {loadedName ? (
        <div className="row" style={{ justifyContent: "center", color: "var(--accent-green)" }}>
          <FileText size={18} /> <span className="mono">{loadedName}</span>
        </div>
      ) : (
        <div className="stack" style={{ alignItems: "center", gap: 8 }}>
          <Upload size={22} className="dim" />
          <span className="dim">{label}</span>
        </div>
      )}
      {!onError && localError && (
        <div
          className="row"
          style={{ justifyContent: "center", gap: 6, marginTop: 10, color: "var(--accent-red)" }}
        >
          <AlertCircle size={14} /> <span>{localError}</span>
        </div>
      )}
    </div>
  );
}
