import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { UiPrefsProvider } from "./components/UiPrefsProvider";
import { bootstrap as bootstrapAuth } from "./api/tokens";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 30_000, retry: 1 } },
});

// M-frontend-auth #10: on page load the access token lives only in
// memory and is therefore gone. The refresh cookie persists; try to
// mint a fresh access into memory before the router mounts. Either
// outcome is fine — `App` renders the login page when no access is
// set, otherwise the authenticated tree.
void bootstrapAuth().finally(() => {
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <UiPrefsProvider>
        <QueryClientProvider client={queryClient}>
          <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
            <App />
          </BrowserRouter>
        </QueryClientProvider>
      </UiPrefsProvider>
    </StrictMode>,
  );
});
