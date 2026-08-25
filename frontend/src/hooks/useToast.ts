import { useContext } from "react";
import { ToastContext } from "../components/ui/toastContext";
import type { ToastApi } from "../components/ui/toastContext";

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}
