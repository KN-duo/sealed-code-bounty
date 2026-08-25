import "./polyfills";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./theme.css";
import App from "./App.tsx";
import { WalletContextProvider } from "./providers/WalletContextProvider";
import { ToastProvider } from "./components/ui/Toast";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <WalletContextProvider>
      <ToastProvider>
        <App />
      </ToastProvider>
    </WalletContextProvider>
  </StrictMode>,
);
