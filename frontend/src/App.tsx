import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { RequireAuth } from "./components/RequireAuth";
import { AlertDetail } from "./pages/AlertDetail";
import { Alerts } from "./pages/Alerts";
import { Allowlist } from "./pages/Allowlist";
import { Archive } from "./pages/Archive";
import { Audit } from "./pages/Audit";
import { CaseDestinations } from "./pages/CaseDestinations";
import { Commands } from "./pages/Commands";
import { Dashboard } from "./pages/Dashboard";
import { DeviceControl } from "./pages/DeviceControl";
import { DashboardEdit } from "./pages/DashboardEdit";
import { Dashboards } from "./pages/Dashboards";
import { DnsBlock } from "./pages/DnsBlock";
import { Enrollment } from "./pages/Enrollment";
import { HostDetail } from "./pages/HostDetail";
import { Hosts } from "./pages/Hosts";
import { HostTerminal } from "./pages/HostTerminal";
import { Hunt } from "./pages/Hunt";
import { SavedHunts } from "./pages/SavedHunts";
import { IncidentDetail } from "./pages/IncidentDetail";
import { Incidents } from "./pages/Incidents";
import { Integrations } from "./pages/Integrations";
import { Intel } from "./pages/Intel";
import { JobDetail } from "./pages/JobDetail";
import { Jobs } from "./pages/Jobs";
import { Login } from "./pages/Login";
import { PlaybookRuns } from "./pages/PlaybookRuns";
import { Playbooks } from "./pages/Playbooks";
import { Quarantine } from "./pages/Quarantine";
import { RuleEdit } from "./pages/RuleEdit";
import { Rollouts } from "./pages/Rollouts";
import { Rules } from "./pages/Rules";
import { ScimTokens } from "./pages/ScimTokens";
import { SecuritySettings } from "./pages/SecuritySettings";
import { SequenceRules } from "./pages/SequenceRules";
import { SiemForwarders } from "./pages/SiemForwarders";
import { Tenants } from "./pages/Tenants";
import { Users } from "./pages/Users";
import { Vulnerabilities } from "./pages/Vulnerabilities";
import { WebhookDeliveries } from "./pages/WebhookDeliveries";
import { Webhooks } from "./pages/Webhooks";

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
                <Route path="/dashboards" element={<Dashboards />} />
                <Route path="/dashboards/:id" element={<DashboardEdit />} />
                <Route path="/hosts" element={<Hosts />} />
                <Route path="/hosts/:id" element={<HostDetail />} />
                <Route path="/hosts/:id/terminal" element={<HostTerminal />} />
                <Route path="/rules" element={<Rules />} />
                <Route path="/rules/new" element={<RuleEdit />} />
                <Route path="/rules/:id" element={<RuleEdit />} />
                <Route path="/sequence-rules" element={<SequenceRules />} />
                <Route path="/playbooks" element={<Playbooks />} />
                <Route path="/playbooks/:id/runs" element={<PlaybookRuns />} />
                <Route path="/alerts" element={<Alerts />} />
                <Route path="/alerts/:id" element={<AlertDetail />} />
                <Route path="/incidents" element={<Incidents />} />
                <Route path="/incidents/:id" element={<IncidentDetail />} />
                <Route path="/commands" element={<Commands />} />
                <Route path="/jobs" element={<Jobs />} />
                <Route path="/jobs/:id" element={<JobDetail />} />
                <Route path="/quarantine" element={<Quarantine />} />
                <Route path="/audit" element={<Audit />} />
                <Route path="/archive" element={<Archive />} />
                <Route path="/hunt" element={<Hunt />} />
                <Route path="/hunt/saved" element={<SavedHunts />} />
                <Route path="/enrollment" element={<Enrollment />} />
                <Route path="/rollouts" element={<Rollouts />} />
                <Route path="/intel" element={<Intel />} />
                <Route path="/integrations" element={<Integrations />} />
                <Route path="/siem" element={<SiemForwarders />} />
                <Route path="/case-destinations" element={<CaseDestinations />} />
                <Route path="/allowlist" element={<Allowlist />} />
                <Route path="/dns-blocks" element={<DnsBlock />} />
                <Route path="/device-control" element={<DeviceControl />} />
                <Route path="/users" element={<Users />} />
                <Route path="/scim-tokens" element={<ScimTokens />} />
                {/* Phase 3 #3.1: tenant CRUD. The page itself returns a
                    "super-admin only" placeholder for everyone else,
                    matching the backend's RequireSuperAdmin gate. */}
                <Route path="/tenants" element={<Tenants />} />
                <Route path="/vulnerabilities" element={<Vulnerabilities />} />
                <Route path="/webhooks" element={<Webhooks />} />
                <Route path="/webhooks/:id/deliveries" element={<WebhookDeliveries />} />
                <Route path="/settings/security" element={<SecuritySettings />} />
              </Routes>
            </Layout>
          </RequireAuth>
        }
      />
    </Routes>
  );
}
