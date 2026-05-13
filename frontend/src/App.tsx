import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { RequireAuth } from "./components/RequireAuth";
import { AlertDetail } from "./pages/AlertDetail";
import { Alerts } from "./pages/Alerts";
import { Audit } from "./pages/Audit";
import { Commands } from "./pages/Commands";
import { Dashboard } from "./pages/Dashboard";
import { Enrollment } from "./pages/Enrollment";
import { HostDetail } from "./pages/HostDetail";
import { Hosts } from "./pages/Hosts";
import { HostTerminal } from "./pages/HostTerminal";
import { IncidentDetail } from "./pages/IncidentDetail";
import { Incidents } from "./pages/Incidents";
import { Integrations } from "./pages/Integrations";
import { Intel } from "./pages/Intel";
import { JobDetail } from "./pages/JobDetail";
import { Jobs } from "./pages/Jobs";
import { Login } from "./pages/Login";
import { Quarantine } from "./pages/Quarantine";
import { RuleEdit } from "./pages/RuleEdit";
import { Rules } from "./pages/Rules";
import { SecuritySettings } from "./pages/SecuritySettings";
import { SequenceRules } from "./pages/SequenceRules";
import { SiemForwarders } from "./pages/SiemForwarders";
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
                <Route path="/hosts/:id/terminal" element={<HostTerminal />} />
                <Route path="/rules" element={<Rules />} />
                <Route path="/rules/new" element={<RuleEdit />} />
                <Route path="/rules/:id" element={<RuleEdit />} />
                <Route path="/sequence-rules" element={<SequenceRules />} />
                <Route path="/alerts" element={<Alerts />} />
                <Route path="/alerts/:id" element={<AlertDetail />} />
                <Route path="/incidents" element={<Incidents />} />
                <Route path="/incidents/:id" element={<IncidentDetail />} />
                <Route path="/commands" element={<Commands />} />
                <Route path="/jobs" element={<Jobs />} />
                <Route path="/jobs/:id" element={<JobDetail />} />
                <Route path="/quarantine" element={<Quarantine />} />
                <Route path="/audit" element={<Audit />} />
                <Route path="/enrollment" element={<Enrollment />} />
                <Route path="/intel" element={<Intel />} />
                <Route path="/integrations" element={<Integrations />} />
                <Route path="/siem" element={<SiemForwarders />} />
                <Route path="/users" element={<Users />} />
                <Route path="/settings/security" element={<SecuritySettings />} />
              </Routes>
            </Layout>
          </RequireAuth>
        }
      />
    </Routes>
  );
}
