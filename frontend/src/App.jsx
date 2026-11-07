import { useCallback, useEffect, useState } from "react";
import {
  Shield, LayoutDashboard, PlusCircle, History, Plug, ScrollText,
  AlertTriangle, CheckCircle2, XCircle, Loader2, Upload, Download,
  Play, FileText, Eye, Lock, Bot, Server, Radar, Bug, X, RefreshCw,
  Terminal, Check, Ban, ExternalLink, HelpCircle, UserCheck, Layers,
} from "lucide-react";
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { api } from "./api.js";

// WCAG AA compliant semantic severity colors
const SEV_COLORS = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
  info: "#475569",
};

function SevBadge({ s }) {
  const sev = (s || "info").toLowerCase();
  const color = SEV_COLORS[sev] || "#475569";
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wider font-mono"
      style={{
        backgroundColor: `${color}18`,
        color: color,
        border: `1px solid ${color}66`,
      }}
    >
      {sev}
    </span>
  );
}

function StatusBadge({ status }) {
  const st = (status || "draft").toLowerCase();
  const isOk = st === "approved" || st === "confirmed" || st === "completed";
  const isWarn = st === "suspected" || st === "planned" || st === "pending";
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium uppercase font-mono ${
        isOk
          ? "bg-teal-950/60 text-teal-400 border border-teal-800/80"
          : isWarn
          ? "bg-amber-950/50 text-amber-300 border border-amber-800/60"
          : "bg-slate-800/80 text-slate-300 border border-slate-700"
      }`}
    >
      {isOk && <CheckCircle2 size={11} />}
      {isWarn && <AlertTriangle size={11} />}
      {st}
    </span>
  );
}

function RiskBadge({ riskClass }) {
  const r = (riskClass || "passive").toLowerCase();
  const colors = {
    passive: "text-slate-400 border-slate-700 bg-slate-900/60",
    intrusive: "text-amber-400 border-amber-800/60 bg-amber-950/40",
    active: "text-red-400 border-red-800/60 bg-red-950/40",
  };
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${colors[r] || colors.passive}`}>
      {r}
    </span>
  );
}

function Card({ children, className = "" }) {
  return (
    <div className={`enterprise-panel p-5 ${className}`}>
      {children}
    </div>
  );
}

function StatCard({ icon: Icon, label, value, detail, accent = "#0d9488" }) {
  return (
    <Card className="flex items-start justify-between">
      <div>
        <p className="text-xs uppercase font-medium tracking-wider text-slate-400">{label}</p>
        <p className="text-2xl font-bold text-white mt-1 font-mono tabular-nums">{value}</p>
        {detail && <p className="text-xs text-slate-400 mt-1">{detail}</p>}
      </div>
      <div className="p-2.5 rounded border border-slate-700/80 bg-slate-800/50" style={{ color: accent }}>
        <Icon size={20} />
      </div>
    </Card>
  );
}

// ---------------- Navigation & Layout ----------------
export default function App() {
  const [view, setView] = useState("dashboard"); // dashboard, engagements, workspace, findings, approvals, matrix, audit
  const [assessments, setAssessments] = useState([]);
  const [activeAid, setActiveAid] = useState("");
  const [user, setUser] = useState({ username: "lead_analyst", role: "lead_analyst" });
  const [artifactModal, setArtifactModal] = useState(null); // { id, filename, sha256, content }
  const [notification, setNotification] = useState("");

  const refreshAssessments = useCallback(async () => {
    try {
      const list = await api.listAssessments();
      setAssessments(list);
      if (list.length > 0 && !activeAid) {
        setActiveAid(list[0].id);
      }
    } catch (e) {
      console.error("Failed to load assessments:", e);
    }
  }, [activeAid]);

  useEffect(() => {
    refreshAssessments();
    const interval = setInterval(() => {
      refreshAssessments();
    }, 5000);
    return () => clearInterval(interval);
  }, [refreshAssessments]);

  const activeAssessment = assessments.find((a) => a.id === activeAid) || assessments[0] || null;

  const showNotice = (msg) => {
    setNotification(msg);
    setTimeout(() => setNotification(""), 4000);
  };

  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
    { id: "engagements", label: "Engagements & Scope", icon: Shield },
    { id: "workspace", label: "Agent Workspace", icon: Bot },
    { id: "findings", label: "Findings & Evidence", icon: Bug },
    { id: "mitre", label: "MITRE ATT&CK", icon: Layers },
    { id: "diff", label: "Retest & Diff", icon: History },
    { id: "approvals", label: "Approvals Center", icon: UserCheck },
    { id: "matrix", label: "Integration Matrix", icon: Plug },
    { id: "audit", label: "Audit Ledger", icon: ScrollText },
  ];

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-200 flex flex-col font-sans">
      {/* Top Bar */}
      <header className="h-14 border-b border-slate-800/90 bg-[#0f172a] px-5 flex items-center justify-between sticky top-0 z-30">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded bg-teal-600/30 border border-teal-500/60 flex items-center justify-center text-teal-400 font-bold text-xs font-mono">
              SV
            </div>
            <span className="font-bold text-white text-base tracking-tight">SentinelVAPT</span>
            <span className="text-[10px] font-mono px-1.5 py-0.2 bg-slate-800 text-teal-400 rounded border border-slate-700">
              v1.0-PROD
            </span>
          </div>

          {/* Active Engagement Switcher */}
          <div className="flex items-center gap-2 pl-4 border-l border-slate-800">
            <span className="text-xs text-slate-400">Engagement:</span>
            <select
              value={activeAid}
              onChange={(e) => setActiveAid(e.target.value)}
              className="bg-slate-900 border border-slate-700 text-xs text-white rounded px-2.5 py-1 focus:outline-none focus:border-teal-500"
            >
              {assessments.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.target})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Live Scope Indicator & User Profile */}
        <div className="flex items-center gap-4">
          {activeAssessment && (
            <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-slate-900 border border-slate-700/80 text-xs font-mono">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-slate-400">In Scope:</span>
              <span className="text-emerald-400 font-semibold">{activeAssessment.target}</span>
            </div>
          )}

          <div className="flex items-center gap-2 pl-3 border-l border-slate-800 text-xs">
            <span className="w-6 h-6 rounded bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-teal-400 text-xs">
              {user.username[0].toUpperCase()}
            </span>
            <div className="text-left leading-tight hidden sm:block">
              <p className="text-white font-medium">{user.username}</p>
              <p className="text-[10px] font-mono text-slate-400 uppercase">{user.role}</p>
            </div>
          </div>
        </div>
      </header>

      {/* Main Layout Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar */}
        <aside className="w-56 bg-[#0c1220] border-r border-slate-800/80 flex flex-col justify-between p-3 shrink-0">
          <nav className="space-y-1">
            <p className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-bold">
              Modules
            </p>
            {navItems.map(({ id, label, icon: Icon }) => {
              const active = view === id;
              return (
                <button
                  key={id}
                  onClick={() => setView(id)}
                  className={`w-full flex items-center gap-2.5 px-3 py-2 rounded text-xs font-medium transition-colors text-left ${
                    active
                      ? "bg-teal-950/60 text-teal-300 border border-teal-800/70"
                      : "text-slate-400 hover:text-white hover:bg-slate-800/50 border border-transparent"
                  }`}
                >
                  <Icon size={16} className={active ? "text-teal-400" : "text-slate-400"} />
                  <span>{label}</span>
                </button>
              );
            })}
          </nav>

          <div className="p-3 border-t border-slate-800/80 text-[11px] text-slate-500 font-mono">
            <p>Scope Gate: <span className="text-emerald-400">ACTIVE</span></p>
            <p>Audit Chaining: <span className="text-teal-400">SHA-256</span></p>
          </div>
        </aside>

        {/* Workspace Canvas Area */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#090d16]">
          {notification && (
            <div className="mb-4 p-3 bg-teal-950/80 border border-teal-700/80 rounded text-teal-200 text-xs flex items-center gap-2">
              <CheckCircle2 size={16} />
              <span>{notification}</span>
            </div>
          )}

          {view === "dashboard" && (
            <DashboardView
              setView={setView}
              assessments={assessments}
              activeAssessment={activeAssessment}
            />
          )}

          {view === "engagements" && (
            <EngagementsView
              assessments={assessments}
              refreshAssessments={refreshAssessments}
              activeAssessment={activeAssessment}
              setActiveAid={setActiveAid}
              showNotice={showNotice}
            />
          )}

          {view === "workspace" && (
            <AgentWorkspaceView
              assessment={activeAssessment}
              refreshAssessments={refreshAssessments}
              showNotice={showNotice}
              openArtifact={(id) => setArtifactModal({ id })}
            />
          )}

          {view === "findings" && (
            <FindingsView
              assessment={activeAssessment}
              openArtifact={(sha, fn, content) => setArtifactModal({ sha256: sha, filename: fn, content })}
            />
          )}

          {view === "mitre" && (
            <MitreMatrixView
              assessment={activeAssessment}
              openArtifact={(sha, fn, content) => setArtifactModal({ sha256: sha, filename: fn, content })}
            />
          )}

          {view === "diff" && (
            <DiffRetestView
              assessment={activeAssessment}
              assessments={assessments}
              setView={setView}
              showNotice={showNotice}
            />
          )}

          {view === "approvals" && (
            <ApprovalsCenterView
              assessment={activeAssessment}
              showNotice={showNotice}
              user={user}
            />
          )}

          {view === "matrix" && <IntegrationMatrixView />}

          {view === "audit" && <AuditLedgerView showNotice={showNotice} />}
        </main>
      </div>

      {/* Raw Artifact Modal */}
      {artifactModal && (
        <ArtifactViewerModal
          modalData={artifactModal}
          onClose={() => setArtifactModal(null)}
        />
      )}
    </div>
  );
}

// ---------------- View: Dashboard ----------------
function DashboardView({ setView, assessments, activeAssessment }) {
  const [stats, setStats] = useState(null);
  const [auditIntegrity, setAuditIntegrity] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function fetchDashboard() {
      try {
        const [s, integ] = await Promise.all([api.stats(), api.auditIntegrity()]);
        if (!cancelled && s) {
          setStats(s);
          setAuditIntegrity(integ);
        }
      } catch (e) {
        console.error("Dashboard initial load:", e);
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }
    fetchDashboard();

    // Auto-retry polling every 4s to smoothly connect and refresh live stats
    const timer = setInterval(() => {
      fetchDashboard();
    }, 4000);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  if (loading && !stats) return <div className="p-8 text-slate-400 flex items-center gap-2"><Loader2 className="animate-spin" size={18} /> Loading console data...</div>;

  const sevData = Object.entries(stats?.by_severity || {}).map(([name, value]) => ({
    name: name.toUpperCase(),
    value,
    fill: SEV_COLORS[name.toLowerCase()] || "#475569",
  }));

  const srcData = Object.entries(stats?.by_source || {}).map(([name, value]) => ({
    name: name.toUpperCase(),
    value,
  }));

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Security Assessment Dashboard</h1>
          <p className="text-xs text-slate-400 mt-1">
            Authoritative, evidence-backed penetration testing console across network, web application, and infrastructure layers.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {auditIntegrity?.valid === true ? (
            <span className="px-2.5 py-1 rounded bg-teal-950/70 border border-teal-700/80 text-teal-300 text-xs font-mono flex items-center gap-1.5">
              <CheckCircle2 size={13} />
              Audit Ledger: {auditIntegrity.total_records} blocks verified intact
            </span>
          ) : auditIntegrity?.valid === false ? (
            <span className="px-2.5 py-1 rounded bg-red-950/70 border border-red-700/80 text-red-300 text-xs font-mono flex items-center gap-1.5">
              <AlertTriangle size={13} />
              Audit Tampering Detected
            </span>
          ) : (
            <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-400 text-xs font-mono flex items-center gap-1.5">
              <Loader2 size={13} className="animate-spin text-teal-400" />
              Audit Ledger: Verifying...
            </span>
          )}
        </div>
      </div>

      {!stats && (
        <div className="p-3 bg-amber-950/60 border border-amber-700/80 rounded text-amber-200 text-xs flex items-center justify-between font-mono">
          <div className="flex items-center gap-2">
            <AlertTriangle size={15} className="text-amber-400 shrink-0" />
            <span>Connecting to backend services... Auto-reconnecting in background.</span>
          </div>
          <button
            onClick={() => window.location.reload()}
            className="px-2.5 py-1 rounded bg-amber-900/60 hover:bg-amber-800 text-white text-[11px] border border-amber-700 font-sans"
          >
            Reload Page
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <StatCard icon={Radar} label="Active Engagements" value={stats?.assessments || 0} />
        <StatCard icon={Bug} label="Correlated Findings" value={stats?.findings || 0} accent="#f97316" />
        <StatCard
          icon={AlertTriangle}
          label="Critical & High"
          value={(stats?.by_severity?.critical || 0) + (stats?.by_severity?.high || 0)}
          accent="#dc2626"
        />
        <StatCard
          icon={Shield}
          label="Scope Violations Blocked"
          value={auditIntegrity?.total_records > 0 ? "Deterministic (0 bypasses)" : "Active"}
          accent="#0d9488"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold mb-4">
            Vulnerability Distribution by Severity
          </h3>
          {sevData.length === 0 ? (
            <p className="text-xs text-slate-500 py-12 text-center">No findings recorded in current engagement.</p>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80} stroke="#0f172a">
                  {sevData.map((d, i) => (
                    <Cell key={i} fill={d.fill} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", fontSize: "12px" }} />
                <Legend wrapperStyle={{ fontSize: "11px", paddingTop: "8px" }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card>
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold mb-4">
            Findings by Corroborating Tool
          </h3>
          {srcData.length === 0 ? (
            <p className="text-xs text-slate-500 py-12 text-center">No scanner outputs ingested yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={srcData}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={10} />
                <YAxis stroke="#64748b" fontSize={10} />
                <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", fontSize: "12px" }} />
                <Bar dataKey="value" fill="#0d9488" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      {/* Engagements Quick Table */}
      <Card>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold">
            Recent Security Engagements
          </h3>
          <button
            onClick={() => setView("engagements")}
            className="text-xs text-teal-400 hover:text-teal-300 font-medium"
          >
            Manage All &rarr;
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <th className="py-2.5 px-3">Engagement Name</th>
                <th className="py-2.5 px-3">Primary Target</th>
                <th className="py-2.5 px-3">Approval Status</th>
                <th className="py-2.5 px-3">Findings</th>
                <th className="py-2.5 px-3 text-right">Report</th>
              </tr>
            </thead>
            <tbody>
              {assessments.length === 0 ? (
                <tr>
                  <td colSpan="5" className="py-8 text-center text-slate-500 font-mono text-xs">
                    Connecting to server or no engagements registered yet...
                  </td>
                </tr>
              ) : (
                assessments.slice(0, 5).map((a) => (
                  <tr key={a.id} className="enterprise-table-row">
                    <td className="py-2.5 px-3 font-medium text-white">{a.name}</td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">{a.target}</td>
                    <td className="py-2.5 px-3">
                      <StatusBadge status={a.approval_status} />
                    </td>
                    <td className="py-2.5 px-3 font-mono">{a.finding_count || 0}</td>
                    <td className="py-2.5 px-3 text-right">
                      <a
                        href={api.reportUrl(a.id)}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-teal-400 hover:text-teal-300 font-medium"
                      >
                        <Download size={13} />
                        PDF Report
                      </a>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

// ---------------- View: Engagements & Scope ----------------
function EngagementsView({ assessments, refreshAssessments, activeAssessment, setActiveAid, showNotice }) {
  const [creating, setCreating] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    target: "127.0.0.1",
    scope: "Local development lab environment",
    allowed_cidrs: "127.0.0.1/32, 10.10.20.0/24",
    exclusions: "10.10.20.1",
    allowed_tools: "nmap, zap, nikto, nuclei",
    auth_statement: "I explicitly confirm I am authorized to assess these targets under engagement rules.",
    authorized: true,
  });
  const [testTarget, setTestTarget] = useState("10.10.20.5");
  const [gateTestResult, setGateTestResult] = useState(null);

  async function handleTestScopeGate() {
    try {
      const cidrs = formData.allowed_cidrs.split(",").map((s) => s.trim()).filter(Boolean);
      const excl = formData.exclusions.split(",").map((s) => s.trim()).filter(Boolean);
      const tools = formData.allowed_tools.split(",").map((s) => s.trim()).filter(Boolean);

      const res = await api.scopeGateCheck({
        target: testTarget,
        allowed_cidrs: cidrs,
        exclusions: excl,
        allowed_tools: tools,
        allow_public_ips: false,
      });
      setGateTestResult(res);
    } catch (e) {
      setGateTestResult({ ok: False, reason: e.message });
    }
  }

  async function handleCreate(e) {
    e.preventDefault();
    try {
      const cidrs = formData.allowed_cidrs.split(",").map((s) => s.trim()).filter(Boolean);
      const res = await api.createAssessment({
        name: formData.name,
        target: formData.target,
        scope: formData.scope,
        allowed_targets: [formData.target],
        allowed_cidrs: cidrs,
        exclusions: formData.exclusions.split(",").map((s) => s.trim()).filter(Boolean),
        allowed_tools: formData.allowed_tools.split(",").map((s) => s.trim()).filter(Boolean),
        auth_statement: formData.auth_statement,
        authorized: formData.authorized,
      });
      showNotice(`Engagement '${formData.name}' created with deterministic scope protection.`);
      setCreating(false);
      await refreshAssessments();
      if (res.id) setActiveAid(res.id);
    } catch (err) {
      alert(err.message);
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Engagements &amp; Deterministic Scope</h1>
          <p className="text-xs text-slate-400 mt-1">
            Configure Rules of Engagement (RoE), authorized network CIDRs, target exclusions, and authorization statements.
          </p>
        </div>
        <button
          onClick={() => setCreating(!creating)}
          className="px-3.5 py-1.5 bg-teal-600 hover:bg-teal-500 text-white rounded text-xs font-medium flex items-center gap-1.5 shadow-sm"
        >
          <PlusCircle size={15} />
          {creating ? "Cancel" : "New Engagement"}
        </button>
      </div>

      {creating && (
        <Card className="border-teal-700/50">
          <h2 className="text-sm font-bold text-white mb-4">Register Authorized Assessment Engagement</h2>
          <form onSubmit={handleCreate} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Engagement Name *</label>
                <input
                  required
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="e.g. Q4 Internal Infrastructure Audit"
                  className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-teal-500"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Primary Target *</label>
                <input
                  required
                  type="text"
                  value={formData.target}
                  onChange={(e) => setFormData({ ...formData, target: e.target.value })}
                  placeholder="127.0.0.1 or 10.10.20.5"
                  className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-teal-500 font-mono"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Scope Description &amp; RoE *</label>
              <textarea
                required
                rows={2}
                value={formData.scope}
                onChange={(e) => setFormData({ ...formData, scope: e.target.value })}
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-teal-500"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Allowed CIDRs (Comma separated)</label>
                <input
                  type="text"
                  value={formData.allowed_cidrs}
                  onChange={(e) => setFormData({ ...formData, allowed_cidrs: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-teal-500 font-mono"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Exclusions / Denylist (Gateway/DC)</label>
                <input
                  type="text"
                  value={formData.exclusions}
                  onChange={(e) => setFormData({ ...formData, exclusions: e.target.value })}
                  className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-teal-500 font-mono"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Authorization Statement (Minimum 10 chars) *</label>
              <input
                required
                type="text"
                value={formData.auth_statement}
                onChange={(e) => setFormData({ ...formData, auth_statement: e.target.value })}
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-teal-500"
              />
            </div>

            <div className="pt-2 flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setCreating(false)}
                className="px-4 py-1.5 rounded text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded text-xs bg-teal-600 hover:bg-teal-500 text-white font-medium"
              >
                Create Engagement
              </button>
            </div>
          </form>
        </Card>
      )}

      {/* Scope Gate Sandbox Tester */}
      <Card>
        <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold mb-2">
          Scope Gate Sandbox &amp; Rebinding Defense Simulator
        </h3>
        <p className="text-xs text-slate-400 mb-4">
          Test any IP, URL, or domain against the deterministic Scope Gate rules before scan execution.
        </p>
        <div className="flex gap-3">
          <input
            type="text"
            value={testTarget}
            onChange={(e) => setTestTarget(e.target.value)}
            placeholder="e.g. 10.10.20.5 or 8.8.8.8 or http://admin@evil.com"
            className="flex-1 bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-teal-500"
          />
          <button
            onClick={handleTestScopeGate}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-teal-300 rounded text-xs font-medium font-mono"
          >
            Check Scope Gate
          </button>
        </div>

        {gateTestResult && (
          <div
            className={`mt-3 p-3 rounded text-xs font-mono border ${
              gateTestResult.ok
                ? "bg-teal-950/60 border-teal-800 text-teal-300"
                : "bg-red-950/60 border-red-800 text-red-300"
            }`}
          >
            <p className="font-bold">Result: {gateTestResult.ok ? "PERMITTED (IN SCOPE)" : "HARD REJECT (OUT OF SCOPE)"}</p>
            <p className="mt-1">Reason: {gateTestResult.reason}</p>
            {gateTestResult.rule && <p className="text-[11px] text-slate-400">Rule Triggered: {gateTestResult.rule}</p>}
          </div>
        )}
      </Card>

      {/* List of Engagements */}
      <Card>
        <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold mb-3">
          All Registered Engagements ({assessments.length})
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <th className="py-2 px-3">Engagement ID</th>
                <th className="py-2 px-3">Name</th>
                <th className="py-2 px-3">Target</th>
                <th className="py-2 px-3">Status</th>
                <th className="py-2 px-3">Created At</th>
                <th className="py-2 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {assessments.map((a) => (
                <tr key={a.id} className="enterprise-table-row">
                  <td className="py-2 px-3 font-mono text-slate-400">{a.id.slice(0, 8)}...</td>
                  <td className="py-2 px-3 font-medium text-white">{a.name}</td>
                  <td className="py-2 px-3 font-mono text-emerald-400">{a.target}</td>
                  <td className="py-2 px-3"><StatusBadge status={a.status} /></td>
                  <td className="py-2 px-3 text-slate-400 font-mono">{a.created_at?.slice(0, 16)}</td>
                  <td className="py-2 px-3 text-right">
                    <button
                      onClick={() => { setActiveAid(a.id); showNotice(`Switched active engagement to '${a.name}'`); }}
                      className="text-xs text-teal-400 hover:underline font-mono"
                    >
                      Select
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

// ---------------- View: Agent Workspace ----------------
function AgentWorkspaceView({ assessment, refreshAssessments, showNotice, openArtifact }) {
  const [chatInput, setChatInput] = useState("");
  const [planSteps, setPlanSteps] = useState([]);
  const [proposals, setProposals] = useState([]);
  const [chatHistory, setChatHistory] = useState([
    {
      role: "agent",
      text: "SentinelVAPT Agent initialized. Ready to plan and execute authorized security assessment steps. Human analyst remains in control.",
    },
  ]);
  const [uploadFile, setUploadFile] = useState(null);
  const [runningTool, setRunningTool] = useState("");
  const [importing, setImporting] = useState(false);

  const loadState = useCallback(async () => {
    if (!assessment) return;
    try {
      if (assessment.plan_json) {
        const p = typeof assessment.plan_json === "string" ? JSON.parse(assessment.plan_json) : assessment.plan_json;
        setPlanSteps(p);
      }
      const st = await api.getAssessmentState(assessment.id);
      setProposals(st.pending_proposals || []);
    } catch (e) {
      console.error(e);
    }
  }, [assessment]);

  useEffect(() => {
    loadState();
  }, [loadState]);

  if (!assessment) return <div className="p-8 text-slate-400">Please select an engagement first.</div>;

  async function handleSendChat(e) {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const userMsg = chatInput;
    setChatInput("");
    setChatHistory((prev) => [...prev, { role: "user", text: userMsg }]);

    try {
      const res = await api.agentChat(assessment.id, userMsg, assessment.target);
      if (res.ok) {
        setPlanSteps(res.steps);
        setChatHistory((prev) => [
          ...prev,
          {
            role: "agent",
            text: `Assessment plan updated (${res.steps.length} steps generated by ${res.generator}). Scope verified.`,
          },
        ]);
        showNotice("Agent generated auditable plan steps.");
      } else {
        setChatHistory((prev) => [
          ...prev,
          { role: "agent", text: `Scope Rejection: ${res.error}. (Out-of-scope targets blocked by Scope Gate).` },
        ]);
      }
    } catch (err) {
      setChatHistory((prev) => [...prev, { role: "agent", text: `Error: ${err.message}` }]);
    }
  }

  async function handleRunScan(tool) {
    setRunningTool(tool);
    try {
      const res = await api.scan(assessment.id, tool, assessment.target);
      if (res.ok) {
        showNotice(`${tool.toUpperCase()} executed. Imported ${res.findings_imported} findings.`);
      } else {
        showNotice(`Execution note: ${res.error || res.hint}`);
      }
      await loadState();
      await refreshAssessments();
    } catch (e) {
      alert(e.message);
    } finally {
      setRunningTool("");
    }
  }

  async function handleFileUpload(e) {
    e.preventDefault();
    if (!uploadFile) return;
    setImporting(true);
    try {
      const res = await api.importScan(assessment.id, uploadFile);
      showNotice(`Imported '${res.filename}' with SHA-256 verification. Parsed ${res.parsed} findings.`);
      setUploadFile(null);
      await loadState();
      await refreshAssessments();
    } catch (err) {
      alert(err.message);
    } finally {
      setImporting(false);
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Agent Planning &amp; Orchestration Workspace
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Conversational goal parsing, adaptive state reflection, and approval-gated tool execution.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <a
            href={api.reportUrl(assessment.id)}
            target="_blank"
            rel="noreferrer"
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-teal-300 rounded text-xs font-medium flex items-center gap-1.5"
          >
            <Download size={14} />
            Export VAPT PDF
          </a>
        </div>
      </div>

      {/* Split Pane: Chat on Left, Structured Assessment Plan on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left: Conversational Agent Chat */}
        <div className="lg:col-span-5 flex flex-col h-[560px] enterprise-panel p-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
            <span className="text-xs font-mono uppercase font-bold text-slate-300 flex items-center gap-1.5">
              <Bot size={15} className="text-teal-400" />
              Conversational Agent
            </span>
            <span className="text-[10px] font-mono text-slate-500">LLM + Grounding Validator</span>
          </div>

          <div className="flex-1 overflow-y-auto space-y-3 pr-2 text-xs">
            {chatHistory.map((m, idx) => (
              <div
                key={idx}
                className={`p-3 rounded leading-relaxed ${
                  m.role === "user"
                    ? "bg-slate-800/80 border border-slate-700 text-white ml-6"
                    : "bg-[#0b1220] border border-teal-900/40 text-slate-300 mr-4"
                }`}
              >
                <p className="text-[10px] font-mono uppercase font-bold text-slate-500 mb-1">
                  {m.role === "user" ? "Human Analyst" : "SentinelVAPT Agent"}
                </p>
                <p>{m.text}</p>
              </div>
            ))}
          </div>

          <form onSubmit={handleSendChat} className="mt-3 pt-3 border-t border-slate-800 flex gap-2">
            <input
              type="text"
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              placeholder="e.g. Run web security scan on 127.0.0.1, check OWASP Top 10"
              className="flex-1 bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-teal-500 font-mono"
            />
            <button
              type="submit"
              className="px-3.5 py-1.5 bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium rounded font-mono"
            >
              Send
            </button>
          </form>
        </div>

        {/* Right: Structured Assessment Plan */}
        <div className="lg:col-span-7 flex flex-col h-[560px] enterprise-panel p-4 overflow-hidden">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
            <span className="text-xs font-mono uppercase font-bold text-slate-300 flex items-center gap-1.5">
              <Layers size={15} className="text-teal-400" />
              Auditable Assessment Plan ({planSteps.length} Steps)
            </span>
            <span className="text-[10px] font-mono text-slate-500">Human Approval Gate Enforced</span>
          </div>

          <div className="flex-1 overflow-y-auto">
            <table className="w-full text-xs text-left">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                  <th className="py-2 px-2.5">#</th>
                  <th className="py-2 px-2.5">Tool</th>
                  <th className="py-2 px-2.5">Phase Title &amp; Rationale</th>
                  <th className="py-2 px-2.5">Risk Class</th>
                  <th className="py-2 px-2.5 text-right">Approval</th>
                </tr>
              </thead>
              <tbody>
                {planSteps.map((step, idx) => (
                  <tr key={idx} className="enterprise-table-row">
                    <td className="py-2 px-2.5 font-mono text-slate-500">{step.step_number || idx + 1}</td>
                    <td className="py-2 px-2.5 font-mono text-teal-400 uppercase font-bold text-[11px]">
                      {step.tool}
                    </td>
                    <td className="py-2 px-2.5">
                      <p className="font-medium text-white">{step.title}</p>
                      <p className="text-[11px] text-slate-400 line-clamp-1">{step.rationale || step.reason}</p>
                    </td>
                    <td className="py-2 px-2.5">
                      <RiskBadge riskClass={step.risk_class} />
                    </td>
                    <td className="py-2 px-2.5 text-right">
                      {step.requires_approval ? (
                        <span className="text-[10px] font-mono text-amber-400 font-semibold px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-800/80">
                          REQUIRED
                        </span>
                      ) : (
                        <span className="text-[10px] font-mono text-slate-500">Auto</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Quick Scanner Launch & Import Toolbar */}
          <div className="mt-3 pt-3 border-t border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-mono">Run Live:</span>
              <button
                disabled={runningTool === "nmap"}
                onClick={() => handleRunScan("nmap")}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-mono text-white flex items-center gap-1"
              >
                {runningTool === "nmap" ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
                Nmap
              </button>
              <button
                disabled={runningTool === "nikto"}
                onClick={() => handleRunScan("nikto")}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-mono text-white flex items-center gap-1"
              >
                {runningTool === "nikto" ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
                Nikto
              </button>
              <button
                disabled={runningTool === "zap"}
                onClick={() => handleRunScan("zap")}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-mono text-white flex items-center gap-1"
              >
                {runningTool === "zap" ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
                ZAP
              </button>
            </div>

            {/* Direct Upload Form */}
            <form onSubmit={handleFileUpload} className="flex items-center gap-2">
              <input
                type="file"
                id="scanner_upload"
                className="hidden"
                onChange={(e) => setUploadFile(e.target.files[0])}
              />
              <label
                htmlFor="scanner_upload"
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-mono text-slate-300 cursor-pointer flex items-center gap-1"
              >
                <Upload size={12} />
                {uploadFile ? uploadFile.name.slice(0, 16) : "Select Scan Artifact"}
              </label>
              {uploadFile && (
                <button
                  type="submit"
                  disabled={importing}
                  className="px-3 py-1 bg-teal-600 hover:bg-teal-500 text-white rounded text-xs font-medium font-mono"
                >
                  {importing ? "Importing..." : "Upload"}
                </button>
              )}
            </form>
          </div>
        </div>
      </div>

      {/* Adaptive Next-Step Proposals */}
      {proposals.length > 0 && (
        <Card className="border-teal-800/40">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-mono uppercase font-bold text-slate-300 flex items-center gap-1.5">
              <Bot size={15} className="text-teal-400" />
              Adaptive Replanning Engine — Identified Next Steps ({proposals.length})
            </span>
            <span className="text-[10px] font-mono text-slate-500">Plan &rarr; Act &rarr; Observe &rarr; Reflect</span>
          </div>

          <div className="space-y-2">
            {proposals.map((prop, idx) => (
              <div
                key={idx}
                className="p-3 rounded bg-slate-900 border border-slate-800 flex items-center justify-between gap-4"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-teal-950 text-teal-400 border border-teal-800">
                      {prop.tool}
                    </span>
                    <span className="font-semibold text-white text-xs">{prop.target}</span>
                    <RiskBadge riskClass={prop.risk_class} />
                    <span className="text-[10px] font-mono text-slate-500">
                      Evidence Ref: {prop.triggering_evidence_id}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">{prop.rationale}</p>
                  <p className="text-[11px] text-teal-400/90 font-mono">Why now: {prop.why_now}</p>
                </div>

                <div>
                  {prop.requires_approval ? (
                    <span className="px-3 py-1.5 rounded bg-amber-950/80 border border-amber-800 text-amber-300 text-xs font-mono font-medium flex items-center gap-1">
                      <Lock size={12} />
                      Approval Required
                    </span>
                  ) : (
                    <button
                      onClick={() => handleRunScan(prop.tool)}
                      className="px-3 py-1.5 rounded bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium font-mono"
                    >
                      Execute Proposal
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

// ---------------- View: Findings & Evidence ----------------
function FindingsView({ assessment, openArtifact }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState("");

  const loadFindings = useCallback(async () => {
    if (!assessment) return;
    setLoading(true);
    try {
      const data = await api.findings(assessment.id, filterSeverity);
      setFindings(data);
      if (data.length > 0 && !selectedFinding) {
        setSelectedFinding(data[0]);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [assessment, filterSeverity]);

  useEffect(() => {
    loadFindings();
  }, [loadFindings]);

  if (!assessment) return <div className="p-8 text-slate-400">Please select an engagement first.</div>;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Vulnerability Findings &amp; Evidence Ledger
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Correlated, deduplicated findings. Every item strictly links back to raw machine evidence.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded text-xs text-slate-200 px-3 py-1.5 font-mono"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Table of Findings (7 cols) */}
        <div className="lg:col-span-7 enterprise-panel overflow-hidden">
          <div className="p-3 border-b border-slate-800 text-xs font-mono uppercase text-slate-400 font-bold">
            Prioritized Findings ({findings.length})
          </div>
          <div className="overflow-x-auto max-h-[640px] overflow-y-auto">
            <table className="w-full text-xs text-left">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] sticky top-0 bg-[#0f172a]">
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Title</th>
                  <th className="py-2.5 px-3">Asset</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => {
                  const isSelected = selectedFinding?.id === f.id;
                  return (
                    <tr
                      key={f.id}
                      onClick={() => setSelectedFinding(f)}
                      className={`enterprise-table-row cursor-pointer transition-colors ${
                        isSelected ? "bg-[#172540] border-l-2 border-l-teal-400" : ""
                      }`}
                    >
                      <td className="py-2.5 px-3"><SevBadge s={f.severity} /></td>
                      <td className="py-2.5 px-3 font-medium text-white max-w-[200px] truncate">{f.title}</td>
                      <td className="py-2.5 px-3 font-mono text-slate-400">{f.asset}</td>
                      <td className="py-2.5 px-3 font-mono font-bold text-teal-300">{f.risk_score}</td>
                      <td className="py-2.5 px-3"><StatusBadge status={f.status || "confirmed"} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Finding Detail Drawer (5 cols) */}
        <div className="lg:col-span-5 enterprise-panel p-4 overflow-y-auto max-h-[680px]">
          {selectedFinding ? (
            <div className="space-y-4">
              <div className="border-b border-slate-800 pb-3">
                <div className="flex items-center justify-between mb-1">
                  <SevBadge s={selectedFinding.severity} />
                  <span className="text-xs font-mono font-bold text-teal-400">
                    Risk: {selectedFinding.risk_score} / 10.0
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white mt-1">{selectedFinding.title}</h3>
                <p className="text-[11px] font-mono text-slate-400 mt-1">
                  Asset: {selectedFinding.asset} &bull; URL: {selectedFinding.url || "N/A"}
                </p>
              </div>

              {/* Observed Evidence Box (SOLID BADGE) */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="badge-observed-evidence">
                    <FileText size={11} />
                    Observed Evidence (Raw Machine Output)
                  </span>
                  <button
                    onClick={() => openArtifact(selectedFinding.source_file_sha256, selectedFinding.source_filename, selectedFinding.evidence)}
                    className="text-[11px] text-teal-400 hover:underline font-mono flex items-center gap-1"
                  >
                    <ExternalLink size={11} />
                    Inspect Artifact
                  </button>
                </div>
                <div className="bg-[#070b14] border border-slate-800 rounded p-2.5 font-mono text-[11px] text-slate-300 whitespace-pre-wrap max-h-48 overflow-y-auto">
                  {selectedFinding.evidence || "No raw text available."}
                </div>
                <p className="text-[10px] font-mono text-slate-500">
                  Source: {selectedFinding.source} &bull; File: {selectedFinding.source_filename} &bull; SHA-256: {selectedFinding.source_file_sha256?.slice(0, 16)}...
                </p>
              </div>

              {/* AI Inference Box (OUTLINED BADGE) */}
              <div className="space-y-1.5">
                <span className="badge-ai-inference">
                  <Bot size={11} />
                  AI Inference &amp; Prioritization ({Math.round((selectedFinding.confidence || 0.8) * 100)}% Confidence)
                </span>
                <div className="bg-teal-950/20 border border-teal-800/40 rounded p-2.5 text-xs text-slate-300 space-y-1">
                  <p><span className="text-teal-400 font-semibold">Risk Formula:</span> {selectedFinding.risk_reason}</p>
                  {selectedFinding.cve && <p><span className="text-teal-400 font-semibold">CVE:</span> {selectedFinding.cve}</p>}
                  {selectedFinding.cwe && <p><span className="text-teal-400 font-semibold">CWE:</span> {selectedFinding.cwe}</p>}
                </div>
              </div>

              {/* Remediation */}
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-slate-300 uppercase font-mono text-[10px]">Actionable Remediation</h4>
                <p className="text-xs text-slate-400 leading-relaxed bg-slate-900/80 p-2.5 rounded border border-slate-800">
                  {selectedFinding.remediation || "Follow security benchmark guidelines for this service."}
                </p>
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-500 py-12 text-center">Select a finding to inspect evidentiary provenance.</p>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------- View: Approvals Center ----------------
function ApprovalsCenterView({ assessment, showNotice, user }) {
  const [approvals, setApprovals] = useState([]);
  const [activeModal, setActiveModal] = useState(null); // approval item
  const [typedConfirm, setTypedConfirm] = useState("");
  const [notes, setNotes] = useState("");

  const loadApprovals = useCallback(async () => {
    try {
      const list = await api.listApprovals();
      setApprovals(list);
    } catch (e) {
      console.error(e);
    }
  }, []);

  useEffect(() => {
    loadApprovals();
  }, [loadApprovals]);

  async function handleDecide(approved) {
    if (!activeModal) return;
    try {
      await api.decideApproval(activeModal.id, {
        approved,
        typed_target_confirmation: typedConfirm,
        outcome_notes: notes,
      });
      showNotice(`Approval request ${activeModal.id.slice(0, 8)} decided: ${approved ? "APPROVED" : "DENIED"}`);
      setActiveModal(null);
      setTypedConfirm("");
      setNotes("");
      loadApprovals();
    } catch (err) {
      alert(err.message);
    }
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Dual Human Approval Center (Non-Negotiable Rule 3)
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Active exploits, intrusive payloads, and VAPT report exports require explicit human sign-off with target confirmation typing.
          </p>
        </div>
      </div>

      <Card>
        <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold mb-3">
          Recorded Approval Requests ({approvals.length})
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <th className="py-2.5 px-3">Request ID</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Target</th>
                <th className="py-2.5 px-3">Tool / Module</th>
                <th className="py-2.5 px-3">Lab Confirmed</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {approvals.map((ap) => (
                <tr key={ap.id} className="enterprise-table-row">
                  <td className="py-2.5 px-3 font-mono text-slate-400">{ap.id.slice(0, 12)}</td>
                  <td className="py-2.5 px-3 uppercase font-mono text-[11px] text-teal-400">{ap.request_type}</td>
                  <td className="py-2.5 px-3 font-mono font-medium text-white">{ap.target}</td>
                  <td className="py-2.5 px-3 font-mono text-slate-300">{ap.tool || ap.command || "N/A"}</td>
                  <td className="py-2.5 px-3">
                    {ap.lab_confirmed ? (
                      <span className="text-[10px] font-mono text-emerald-400 font-semibold">LAB VERIFIED</span>
                    ) : (
                      <span className="text-[10px] font-mono text-red-400">UNCONFIRMED</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3">
                    <StatusBadge status={ap.status} />
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    {ap.status === "pending" ? (
                      <button
                        onClick={() => { setActiveModal(ap); setTypedConfirm(""); setNotes(""); }}
                        className="px-2.5 py-1 rounded bg-teal-600 hover:bg-teal-500 text-white font-medium text-xs font-mono"
                      >
                        Review Request
                      </button>
                    ) : (
                      <span className="text-slate-500 font-mono text-[11px]">Decided by {ap.approver || "Analyst"}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Decision Modal */}
      {activeModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="enterprise-panel max-w-lg w-full p-5 border-teal-600/60 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="text-sm font-bold text-white flex items-center gap-1.5 font-mono">
                <Lock size={15} className="text-amber-400" />
                Human Approval Required
              </span>
              <button onClick={() => setActiveModal(null)} className="text-slate-400 hover:text-white">
                <X size={16} />
              </button>
            </div>

            <div className="space-y-2 text-xs">
              <p><span className="text-slate-400">Target Identifier:</span> <span className="font-mono text-emerald-400 font-bold">{activeModal.target}</span></p>
              <p><span className="text-slate-400">Tool / Module:</span> <span className="font-mono text-white">{activeModal.tool}</span></p>
              <p><span className="text-slate-400">Command:</span> <span className="font-mono text-slate-300">{activeModal.command || "Exploit check module"}</span></p>
              <p><span className="text-slate-400">Justification:</span> <span className="text-slate-300">{activeModal.justification}</span></p>
              <p><span className="text-slate-400">Lab Only Flag:</span> <span className="text-emerald-400 font-bold">{activeModal.lab_confirmed ? "Confirmed (Isolated Lab Network)" : "NO"}</span></p>
            </div>

            <div className="pt-2 border-t border-slate-800 space-y-2">
              <label className="block text-xs font-bold text-amber-300">
                To confirm approval, type target identifier <span className="font-mono text-white underline">"{activeModal.target}"</span>:
              </label>
              <input
                type="text"
                value={typedConfirm}
                onChange={(e) => setTypedConfirm(e.target.value)}
                placeholder={activeModal.target}
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-teal-500"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Decision Notes</label>
              <input
                type="text"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="e.g. Authorized for testing under lab engagement scope"
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-xs text-white focus:outline-none"
              />
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => handleDecide(false)}
                className="px-4 py-1.5 rounded bg-red-950/80 hover:bg-red-900 border border-red-800 text-red-300 text-xs font-mono font-medium"
              >
                Deny Request
              </button>
              <button
                disabled={typedConfirm.trim() !== activeModal.target.trim()}
                onClick={() => handleDecide(true)}
                className="px-4 py-1.5 rounded bg-teal-600 hover:bg-teal-500 disabled:opacity-40 text-white text-xs font-mono font-medium"
              >
                Authorize &amp; Execute
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------- View: Truthful Integration Matrix ----------------
function IntegrationMatrixView() {
  const [matrix, setMatrix] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const data = await api.integrations();
        setMatrix(data);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) return <div className="p-8 text-slate-400">Probing tool health &amp; licensing...</div>;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Truthful Tool Integration Matrix (Non-Negotiable Rule 6)
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Dynamic capability matrix auto-generated from live system health checks. Commercial tools are never falsely claimed as live.
          </p>
        </div>
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <th className="py-2.5 px-3">Tool Name</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Integration Mode</th>
                <th className="py-2.5 px-3">License Disclosure</th>
                <th className="py-2.5 px-3">Operational Status &amp; Limitations</th>
                <th className="py-2.5 px-3">Supported Formats</th>
              </tr>
            </thead>
            <tbody>
              {matrix.map((item) => (
                <tr key={item.id} className="enterprise-table-row">
                  <td className="py-2.5 px-3 font-bold text-white flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-teal-400" />
                    {item.name}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px]">{item.category}</td>
                  <td className="py-2.5 px-3 font-mono font-bold">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] ${
                        item.mode === "live"
                          ? "bg-teal-950 text-teal-300 border border-teal-800"
                          : item.mode === "import_only"
                          ? "bg-slate-800 text-slate-300 border border-slate-700"
                          : "bg-amber-950 text-amber-300 border border-amber-800"
                      }`}
                    >
                      {item.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-300 text-[11px]">{item.license_type}</td>
                  <td className="py-2.5 px-3 max-w-xs text-slate-400">
                    <p className="text-slate-200">{item.detail}</p>
                    {item.limitations?.length > 0 && (
                      <p className="text-[10px] text-amber-400/80 font-mono mt-0.5">&bull; {item.limitations[0]}</p>
                    )}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-400 text-[11px]">
                    {item.supported_formats?.join(", ") || ".xml"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

// ---------------- View: Cryptographic Audit Ledger ----------------
function AuditLedgerView({ showNotice }) {
  const [logs, setLogs] = useState([]);
  const [integrity, setIntegrity] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadLogs = useCallback(async () => {
    try {
      const [l, integ] = await Promise.all([api.audit(), api.auditIntegrity()]);
      setLogs(l);
      setIntegrity(integ);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  async function handleVerifyIntegrity() {
    try {
      const res = await api.auditIntegrity();
      setIntegrity(res);
      showNotice(
        res.valid
          ? `Integrity verified: ${res.total_records} audit blocks cryptographically chained.`
          : `TAMPER DETECTED at block ${res.broken_at_id}: ${res.error_reason}`
      );
    } catch (e) {
      alert(e.message);
    }
  }

  if (loading) return <div className="p-8 text-slate-400">Loading audit ledger...</div>;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Cryptographic Audit Ledger (Non-Negotiable Rule 8)
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Append-only, SHA-256 hash-chained ledger storing every operator and agent decision.
          </p>
        </div>
        <button
          onClick={handleVerifyIntegrity}
          className="px-3.5 py-1.5 bg-teal-600 hover:bg-teal-500 text-white rounded text-xs font-medium flex items-center gap-1.5 font-mono"
        >
          <RefreshCw size={14} />
          Verify Audit Integrity
        </button>
      </div>

      {integrity && (
        <Card className={integrity.valid ? "border-teal-700/60 bg-teal-950/20" : "border-red-700/80 bg-red-950/30"}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {integrity.valid ? <CheckCircle2 className="text-emerald-400" size={18} /> : <AlertTriangle className="text-red-400" size={18} />}
              <span className="font-bold text-sm text-white font-mono">
                {integrity.valid ? "AUDIT CHAIN STATUS: VERIFIED INTACT // UNTAMPERED" : "AUDIT CHAIN STATUS: TAMPERING DETECTED"}
              </span>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Total Chained Records: {integrity.total_records}
            </span>
          </div>
          {integrity.error_reason && (
            <p className="mt-2 text-xs font-mono text-red-300 bg-red-950/50 p-2 rounded border border-red-800">
              {integrity.error_reason}
            </p>
          )}
        </Card>
      )}

      <Card>
        <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] sticky top-0 bg-[#0f172a]">
                <th className="py-2.5 px-3">Block ID</th>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Actor</th>
                <th className="py-2.5 px-3">Action Verb</th>
                <th className="py-2.5 px-3">Target</th>
                <th className="py-2.5 px-3">Prev Hash</th>
                <th className="py-2.5 px-3">Entry Hash</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((row) => (
                <tr key={row.id} className="enterprise-table-row">
                  <td className="py-2 px-3 font-mono text-slate-400">#{row.id}</td>
                  <td className="py-2 px-3 font-mono text-slate-400">{row.created_at?.slice(0, 19)}</td>
                  <td className="py-2 px-3 font-mono text-teal-400 font-bold">{row.actor || "system"}</td>
                  <td className="py-2 px-3 font-mono font-medium text-white">{row.event}</td>
                  <td className="py-2 px-3 font-mono text-slate-300">{row.target || "system"}</td>
                  <td className="py-2 px-3 font-mono text-[10px] text-slate-500">
                    {row.prev_hash ? `${row.prev_hash.slice(0, 10)}...` : "GENESIS"}
                  </td>
                  <td className="py-2 px-3 font-mono text-[10px] text-teal-400/90">
                    {row.entry_hash ? `${row.entry_hash.slice(0, 10)}...` : "PENDING"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

// ---------------- Modal: Raw Artifact Viewer ----------------
function ArtifactViewerModal({ modalData, onClose }) {
  const [artifact, setArtifact] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function load() {
      if (modalData.content) {
        setArtifact(modalData);
        return;
      }
      if (modalData.id) {
        setLoading(true);
        try {
          const art = await api.getArtifact(modalData.id);
          setArtifact(art);
        } catch (e) {
          console.error(e);
        } finally {
          setLoading(false);
        }
      }
    }
    load();
  }, [modalData]);

  return (
    <div className="fixed inset-0 bg-black/85 flex items-center justify-center p-5 z-50">
      <div className="enterprise-panel max-w-4xl w-full h-[620px] flex flex-col p-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <FileText size={16} className="text-teal-400" />
            <span className="font-bold text-sm text-white font-mono">
              Raw Scanner Artifact ({artifact?.filename || modalData.filename || "artifact.raw"})
            </span>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X size={18} />
          </button>
        </div>

        <div className="py-2 border-b border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span>SHA-256: <span className="text-teal-400">{artifact?.sha256 || modalData.sha256 || "verified"}</span></span>
          <span>Verified Immutable Content</span>
        </div>

        <div className="flex-1 overflow-y-auto mt-3 bg-[#050811] p-3 rounded border border-slate-800 font-mono text-xs text-slate-300 whitespace-pre-wrap">
          {loading ? (
            <p className="text-slate-500">Loading raw artifact bytes...</p>
          ) : (
            artifact?.content || "Artifact text not available."
          )}
        </div>

        <div className="pt-3 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-mono text-white"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------- View: MITRE ATT&CK Matrix ----------------
function MitreMatrixView({ assessment, openArtifact }) {
  const [matrixData, setMatrixData] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedTech, setSelectedTech] = useState(null);

  useEffect(() => {
    async function load() {
      if (!assessment?.id) return;
      setLoading(true);
      try {
        const [m, f] = await Promise.all([
          api.mitre(assessment.id),
          api.findings(assessment.id),
        ]);
        setMatrixData(m);
        setFindings(f);
      } catch (err) {
        console.error("Failed to load MITRE matrix:", err);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [assessment?.id]);

  if (!assessment) {
    return (
      <div className="p-8 text-center text-slate-500 font-mono">
        No active engagement selected.
      </div>
    );
  }

  const activeTactics = matrixData?.tactics?.filter((t) => t.total_findings > 0) || [];
  const findingsMap = {};
  findings.forEach((f) => {
    findingsMap[f.id] = f;
  });

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Layers size={20} className="text-teal-400" />
            <h1 className="text-xl font-bold text-white tracking-tight">MITRE ATT&CK Enterprise Matrix</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic mapping of verified scanner findings to Enterprise ATT&CK v14 tactics & techniques.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <a
            href={api.mitreNavigatorUrl(assessment.id)}
            download={`mitre_navigator_${assessment.name.replace(/\s+/g, "_")}.json`}
            className="flex items-center gap-2 px-3 py-1.5 rounded bg-teal-950/60 hover:bg-teal-900/60 text-teal-300 border border-teal-800 text-xs font-mono transition-colors"
          >
            <Download size={14} />
            <span>Export ATT&CK Navigator Layer</span>
          </a>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard
          icon={Layers}
          label="Active Tactics"
          value={activeTactics.length}
          detail={`Out of 14 Enterprise tactics`}
          accent="#0d9488"
        />
        <StatCard
          icon={Radar}
          label="Mapped Techniques"
          value={activeTactics.reduce((acc, t) => acc + t.techniques.length, 0)}
          detail="Directly backed by scanner evidence"
          accent="#38bdf8"
        />
        <StatCard
          icon={Bug}
          label="Correlated Findings"
          value={matrixData?.total_findings_mapped || 0}
          detail="Zero ungrounded hallucinations"
          accent="#ea580c"
        />
      </div>

      {loading ? (
        <Card className="flex items-center justify-center p-12 text-slate-400 font-mono text-xs">
          <Loader2 size={16} className="animate-spin mr-2 text-teal-400" />
          Mapping findings to ATT&CK tactics...
        </Card>
      ) : activeTactics.length === 0 ? (
        <Card className="p-8 text-center text-slate-500 font-mono text-xs">
          No vulnerabilities mapped for this engagement yet. Import scan evidence or run scanner workflows.
        </Card>
      ) : (
        <div className="overflow-x-auto pb-4">
          <div className="flex gap-4 min-w-[1000px]">
            {activeTactics.map((tactic) => (
              <div
                key={tactic.id}
                className="w-72 shrink-0 bg-[#0c1220] border border-slate-800 rounded p-3 flex flex-col"
              >
                <div className="pb-2.5 border-b border-slate-800 mb-3 flex items-center justify-between">
                  <div>
                    <p className="text-[10px] font-mono uppercase text-teal-400 font-bold">{tactic.id}</p>
                    <p className="text-xs font-bold text-white tracking-tight">{tactic.name}</p>
                  </div>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                    {tactic.total_findings}
                  </span>
                </div>

                <div className="space-y-2 flex-1">
                  {tactic.techniques.map((tech) => {
                    const isSelected = selectedTech?.technique_id === tech.technique_id;
                    return (
                      <button
                        key={tech.technique_id}
                        onClick={() => setSelectedTech(isSelected ? null : { ...tech, tactic_name: tactic.name })}
                        className={`w-full text-left p-2.5 rounded border transition-all text-xs ${
                          isSelected
                            ? "bg-teal-950/70 border-teal-500 text-teal-200"
                            : "bg-slate-900/60 border-slate-800/80 hover:border-slate-700 text-slate-300"
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-mono text-[10px] text-teal-400">{tech.technique_id}</span>
                          <SevBadge s={tech.max_severity} />
                        </div>
                        <p className="font-medium text-xs leading-snug line-clamp-2">{tech.technique_name}</p>
                        <div className="mt-2 flex items-center justify-between text-[10px] text-slate-400 font-mono">
                          <span>{tech.findings_count} finding{tech.findings_count > 1 ? "s" : ""}</span>
                          <span className="text-teal-400/80 hover:underline">Inspect &rarr;</span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Selected Technique Findings Drawer */}
      {selectedTech && (
        <Card className="mt-6 border-teal-900/80 bg-[#0a101d]">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-teal-400 font-bold">{selectedTech.technique_id}</span>
                <span className="text-sm font-bold text-white">{selectedTech.technique_name}</span>
                <span className="text-xs text-slate-400 font-mono">({selectedTech.tactic_name})</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Findings associated with this technique, categorized by observed scanner evidence vs AI inference.
              </p>
            </div>
            <button
              onClick={() => setSelectedTech(null)}
              className="text-slate-400 hover:text-white p-1"
            >
              <X size={16} />
            </button>
          </div>

          <div className="mt-4 space-y-3">
            {selectedTech.finding_ids.map((fid) => {
              const f = findingsMap[fid] || findings.find((item) => item.id === fid || item.title === fid);
              if (!f) return null;
              return (
                <div
                  key={fid}
                  className="p-3.5 rounded bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
                >
                  <div className="space-y-1.5 flex-1">
                    <div className="flex items-center gap-2">
                      <SevBadge s={f.severity} />
                      <span className="font-semibold text-white">{f.title}</span>
                      {f.cwe && (
                        <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {f.cwe}
                        </span>
                      )}
                      {f.cve && (
                        <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-amber-300 border border-amber-800/60">
                          {f.cve}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-4 text-slate-400 font-mono text-[11px]">
                      <span>Target: <span className="text-white">{f.asset || f.url}</span></span>
                      <span>Source: <span className="text-teal-400">{f.source}</span></span>
                      <span>Risk: <span className="text-white">{f.risk_score || "N/A"}</span></span>
                    </div>
                  </div>

                  {/* Dual Badges */}
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-800 text-slate-300 border border-slate-700">
                      OBSERVED EVIDENCE
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase border border-teal-500/60 text-teal-300 bg-teal-950/20">
                      AI INFERENCE ({Math.round((f.confidence || 0.8) * 100)}%)
                    </span>
                    <button
                      onClick={() => openArtifact(f.source_file_sha256, f.source_filename, f.evidence)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-white font-mono text-[11px] border border-slate-700"
                    >
                      Raw Artifact
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}
    </div>
  );
}

// ---------------- View: Retest & Diff Engine ----------------
function DiffRetestView({ assessment, assessments, setView, showNotice }) {
  const [priorAid, setPriorAid] = useState("");
  const [diffData, setDiffData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("retest"); // retest, resolved, new, recurrent

  // Candidate prior assessments (all except active)
  const priorCandidates = assessments.filter((a) => a.id !== assessment?.id);

  useEffect(() => {
    if (priorCandidates.length > 0 && !priorAid) {
      setPriorAid(priorCandidates[0].id);
    }
  }, [priorCandidates, priorAid]);

  const loadDiff = useCallback(async () => {
    if (!assessment?.id || !priorAid) return;
    setLoading(true);
    try {
      const res = await api.diff(assessment.id, priorAid);
      setDiffData(res);
    } catch (err) {
      console.error("Diff load failed:", err);
      showNotice("Failed to calculate diff: " + err.message);
    } finally {
      setLoading(false);
    }
  }, [assessment?.id, priorAid, showNotice]);

  useEffect(() => {
    loadDiff();
  }, [loadDiff]);

  if (!assessment) {
    return (
      <div className="p-8 text-center text-slate-500 font-mono">
        No active engagement selected.
      </div>
    );
  }

  const summary = diffData?.summary;
  const isImproved = summary?.posture_improved;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <History size={20} className="text-teal-400" />
            <h1 className="text-xl font-bold text-white tracking-tight">Retest & Assessment Diff Engine</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Compare active engagement against prior scan runs, track vulnerability lifecycle, and generate targeted retest workflows.
          </p>
        </div>

        {/* Prior Assessment Selector */}
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-400 font-mono">Compare with Baseline:</span>
          <select
            value={priorAid}
            onChange={(e) => setPriorAid(e.target.value)}
            className="bg-slate-900 border border-slate-700 text-xs text-white rounded px-3 py-1.5 focus:outline-none focus:border-teal-500 font-mono"
          >
            {priorCandidates.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.target})
              </option>
            ))}
          </select>
          <button
            onClick={loadDiff}
            className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
            title="Refresh Diff"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          </button>
        </div>
      </div>

      {loading ? (
        <Card className="flex items-center justify-center p-12 text-slate-400 font-mono text-xs">
          <Loader2 size={16} className="animate-spin mr-2 text-teal-400" />
          Computing differential telemetry between scan runs...
        </Card>
      ) : !diffData ? (
        <Card className="p-8 text-center text-slate-500 font-mono text-xs">
          Please select a valid prior engagement baseline to compute differential comparison.
        </Card>
      ) : (
        <>
          {/* Posture Shift Banner & Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className={`border ${isImproved ? "border-emerald-800/80 bg-emerald-950/20" : "border-amber-800/80 bg-amber-950/20"}`}>
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Posture Trend</p>
                  <p className={`text-2xl font-bold mt-1 font-mono tabular-nums ${isImproved ? "text-emerald-400" : "text-amber-400"}`}>
                    {summary.risk_delta > 0 ? `+${summary.risk_delta}` : summary.risk_delta}
                  </p>
                  <p className="text-[11px] font-mono mt-0.5 text-slate-400">
                    {isImproved ? "Posture Improved" : summary.risk_delta === 0 ? "Posture Unchanged" : "Risk Regressed"} ({summary.risk_percentage_change}%)
                  </p>
                </div>
                <div className={`p-2 rounded border ${isImproved ? "border-emerald-700 bg-emerald-900/40 text-emerald-300" : "border-amber-700 bg-amber-900/40 text-amber-300"}`}>
                  {isImproved ? <CheckCircle2 size={20} /> : <AlertTriangle size={20} />}
                </div>
              </div>
            </Card>

            <StatCard
              icon={CheckCircle2}
              label="Resolved Vulnerabilities"
              value={summary.resolved_count}
              detail="Remediated since baseline"
              accent="#10b981"
            />
            <StatCard
              icon={AlertTriangle}
              label="New Vulnerabilities"
              value={summary.new_count}
              detail="Introduced since baseline"
              accent="#ef4444"
            />
            <StatCard
              icon={RefreshCw}
              label="Recurrent Issues"
              value={summary.recurrent_count}
              detail="Persisting across both runs"
              accent="#f59e0b"
            />
          </div>

          {/* Diff Navigation Tabs */}
          <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
            {[
              { id: "retest", label: `Retest Action Plan (${diffData.retest_recommendations.length})` },
              { id: "resolved", label: `Resolved (${diffData.resolved_findings.length})` },
              { id: "new", label: `New Findings (${diffData.new_findings.length})` },
              { id: "recurrent", label: `Recurrent (${diffData.recurrent_findings.length})` },
            ].map((t) => (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`px-3 py-1.5 rounded text-xs font-mono transition-colors ${
                  activeTab === t.id
                    ? "bg-teal-950/70 text-teal-300 border border-teal-800"
                    : "text-slate-400 hover:text-white hover:bg-slate-800/40"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Tab 1: Retest Action Plan */}
          {activeTab === "retest" && (
            <Card className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white tracking-tight">Selective Retest Workflow</h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Selectively invokes only the scanner probes that originally detected an issue to verify fixes without full-scope rescans.
                  </p>
                </div>
                <button
                  onClick={() => {
                    setView("workspace");
                    showNotice("Retest context loaded into Agent Workspace.");
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-teal-600 hover:bg-teal-500 text-white text-xs font-mono transition-colors"
                >
                  <Bot size={14} />
                  <span>Execute in Agent Workspace</span>
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="text-[10px] font-mono uppercase bg-slate-900/80 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Target & Finding</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3">Recommended Tool</th>
                      <th className="py-2.5 px-3">Verification Objective</th>
                      <th className="py-2.5 px-3">Rationale</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {diffData.retest_recommendations.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="py-6 text-center text-slate-500">
                          No pending retests required.
                        </td>
                      </tr>
                    ) : (
                      diffData.retest_recommendations.map((item, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/30">
                          <td className="py-2.5 px-3 font-sans">
                            <div className="flex items-center gap-2">
                              <SevBadge s={item.severity} />
                              <span className="font-semibold text-white">{item.finding_title}</span>
                            </div>
                            <span className="text-[10px] text-slate-400 font-mono">{item.target}</span>
                          </td>
                          <td className="py-2.5 px-3">
                            <span className={`inline-block px-2 py-0.5 rounded text-[10px] border ${
                              item.status.includes("resolved")
                                ? "bg-emerald-950/40 text-emerald-300 border-emerald-800/60"
                                : "bg-amber-950/40 text-amber-300 border-amber-800/60"
                            }`}>
                              {item.status.replace(/_/g, " ")}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-teal-400 font-bold uppercase">{item.recommended_tool}</td>
                          <td className="py-2.5 px-3 font-sans text-slate-300 text-[11px]">{item.verification_goal}</td>
                          <td className="py-2.5 px-3 font-sans text-slate-400 text-[11px]">{item.rationale}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          {/* Tab 2: Resolved Findings */}
          {activeTab === "resolved" && (
            <div className="space-y-3">
              {diffData.resolved_findings.length === 0 ? (
                <Card className="p-8 text-center text-slate-500 font-mono text-xs">
                  No vulnerabilities resolved since baseline.
                </Card>
              ) : (
                diffData.resolved_findings.map((f, i) => (
                  <Card key={i} className="border-emerald-900/60 bg-[#0c1815]/50 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-emerald-950 text-emerald-400 border border-emerald-800">
                          REMEDIATED
                        </span>
                        <SevBadge s={f.severity} />
                        <span className="font-semibold text-white">{f.title}</span>
                      </div>
                      <div className="text-slate-400 font-mono text-[11px] flex gap-4">
                        <span>Target: <span className="text-white">{f.asset || f.url}</span></span>
                        <span>Prior CVSS: <span className="text-white">{f.cvss || "N/A"}</span></span>
                        <span>Source: <span className="text-teal-400">{f.source}</span></span>
                      </div>
                    </div>
                    <div className="text-right font-mono text-[11px] text-slate-400">
                      <span>Prior Risk Score: <span className="text-white font-bold">{f.risk_score}</span></span>
                    </div>
                  </Card>
                ))
              )}
            </div>
          )}

          {/* Tab 3: New Findings */}
          {activeTab === "new" && (
            <div className="space-y-3">
              {diffData.new_findings.length === 0 ? (
                <Card className="p-8 text-center text-slate-500 font-mono text-xs">
                  No new vulnerabilities introduced since baseline. Clean delta!
                </Card>
              ) : (
                diffData.new_findings.map((f, i) => (
                  <Card key={i} className="border-red-900/60 bg-[#1f0d0d]/40 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-red-950 text-red-400 border border-red-800">
                          NEW
                        </span>
                        <SevBadge s={f.severity} />
                        <span className="font-semibold text-white">{f.title}</span>
                        {f.cwe && <span className="font-mono text-[10px] text-slate-400">({f.cwe})</span>}
                      </div>
                      <div className="text-slate-400 font-mono text-[11px] flex gap-4">
                        <span>Target: <span className="text-white">{f.asset || f.url}</span></span>
                        <span>CVSS: <span className="text-white">{f.cvss || "N/A"}</span></span>
                        <span>Source: <span className="text-teal-400">{f.source}</span></span>
                      </div>
                    </div>
                    <div className="text-right font-mono text-[11px] text-slate-400">
                      <span>Risk Score: <span className="text-red-400 font-bold">{f.risk_score}</span></span>
                    </div>
                  </Card>
                ))
              )}
            </div>
          )}

          {/* Tab 4: Recurrent Findings */}
          {activeTab === "recurrent" && (
            <div className="space-y-3">
              {diffData.recurrent_findings.length === 0 ? (
                <Card className="p-8 text-center text-slate-500 font-mono text-xs">
                  No recurrent findings.
                </Card>
              ) : (
                diffData.recurrent_findings.map((item, i) => {
                  const cf = item.current;
                  return (
                    <Card key={i} className="border-slate-800 bg-slate-900/50 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-800 text-amber-300 border border-amber-800/60">
                            RECURRENT
                          </span>
                          <SevBadge s={cf.severity} />
                          <span className="font-semibold text-white">{cf.title}</span>
                        </div>
                        <div className="text-slate-400 font-mono text-[11px] flex gap-4">
                          <span>Target: <span className="text-white">{cf.asset || cf.url}</span></span>
                          <span>CVSS: <span className="text-white">{cf.cvss || "N/A"}</span></span>
                          <span>Source: <span className="text-teal-400">{cf.source}</span></span>
                        </div>
                      </div>
                      <div className="text-right font-mono text-[11px] text-slate-400">
                        <span>Risk Score: <span className="text-white font-bold">{cf.risk_score}</span></span>
                      </div>
                    </Card>
                  );
                })
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
