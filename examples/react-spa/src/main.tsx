import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { AuthProvider } from "react-oidc-context";
import App from "./App";
import { authConfig } from "./auth";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("The application root element is missing.");

createRoot(root).render(
  <StrictMode>
    <AuthProvider {...authConfig}>
      <App />
    </AuthProvider>
  </StrictMode>,
);
