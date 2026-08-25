import type { ButtonHTMLAttributes, ReactNode } from "react";
import { Loader2 } from "lucide-react";

type Variant = "primary" | "default" | "danger" | "ghost";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: "sm" | "md";
  block?: boolean;
  loading?: boolean;
  children: ReactNode;
}

const VARIANT_CLASS: Record<Variant, string> = {
  primary: "btn-primary",
  default: "",
  danger: "btn-danger",
  ghost: "btn-ghost",
};

export function Button({
  variant = "default",
  size = "md",
  block = false,
  loading = false,
  children,
  className = "",
  disabled,
  ...rest
}: ButtonProps) {
  const classes = [
    "btn",
    VARIANT_CLASS[variant],
    size === "sm" ? "btn-sm" : "",
    block ? "btn-block" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <button className={classes} disabled={disabled || loading} {...rest}>
      {loading && <Loader2 size={15} className="spin" />}
      {children}
    </button>
  );
}
