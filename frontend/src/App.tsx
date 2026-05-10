import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { RequireAuth } from "./components/RequireAuth";
import { AlertDetail } from "./pages/AlertDetail";
import { Alerts } from "./pages/Alerts";
import { Commands } from "./pages/Commands";
import { Dashboard } from "./pages/Dashboard";
import { Enrollment } from "./pages/Enrollment";
import { HostDetail } from "./pages/HostDetail";
import { Hosts } from "./pages/Hosts";
import { Login } from "./pages/Login";
import { RuleEdit } from "./pages/RuleEdit";
import { Rules } from "./pages/Rules";
import { Users } from "./pages/Users";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/*"
        element={
          <RequireAuth>
            <Layout>
              <Routes>
                <Route path="/" element={<Navigate to="/alerts" replace />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/hosts" element={<Hosts />} />
                <Route path="/hosts/:id" element={<HostDetail />} />
                <Route path="/rules" element={<Rules />} />
                <Route path="/rules/new" element={<RuleEdit />} />
                <Route path="/rules/:id" element={<RuleEdit />} />
                <Route path="/alerts" element={<Alerts />} />
                <Route path="/alerts/:id" element={<AlertDetail />} />
                <Route path="/commands" element={<Commands />} />
                <Route path="/enrollment" element={<Enrollment />} />
                <Route path="/users" element={<Users />} />
              </Routes>
            </Layout>
          </RequireAuth>
        }
      />
    </Routes>
  );
}
