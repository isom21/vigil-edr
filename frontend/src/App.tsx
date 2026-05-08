import { Routes, Route, Navigate } from "react-router-dom";

export default function App() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DashboardPlaceholder />} />
      </Routes>
    </div>
  );
}

function DashboardPlaceholder() {
  return (
    <div className="container py-12">
      <h1 className="text-3xl font-bold">EDR Manager</h1>
      <p className="text-muted-foreground mt-2">
        M0 stub. Hosts / Rules / Alerts pages arrive in M1.
      </p>
    </div>
  );
}
