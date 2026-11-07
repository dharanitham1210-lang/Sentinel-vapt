// Base API URL: configured via VITE_API_URL in production (Vercel)
// In local development, falls back to "" (same-origin / Vite dev proxy)
const rawBase = import.meta.env.VITE_API_URL || "";
const B = rawBase.trim().replace(/\/+$/, "");

export const API_BASE_URL = B;
export const WS_BASE_URL = B
  ? B.replace(/^http:/, "ws:").replace(/^https:/, "wss:")
  : (typeof window !== "undefined" && window.location.protocol === "https:"
      ? `wss://${window.location.host}`
      : `ws://${typeof window !== "undefined" ? window.location.host : "localhost:8000"}`);

function getAuthHeaders() {
  const token = localStorage.getItem("sentinel_token");
  const headers = { "Content-Type": "application/json" };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

async function handle(res) {
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const j = await res.json();
      msg = j.detail || j.message || msg;
    } catch {
      /* non-JSON */
    }
    throw new Error(msg);
  }
  return res.json();
}

export const api = {
  // Auth
  async login(username, password) {
    const res = await handle(
      await fetch(`${B}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      })
    );
    if (res.token) {
      localStorage.setItem("sentinel_token", res.token);
      localStorage.setItem("sentinel_user", JSON.stringify(res.user));
    }
    return res;
  },
  async me() {
    return handle(await fetch(`${B}/api/auth/me`, { headers: getAuthHeaders() }));
  },
  logout() {
    localStorage.removeItem("sentinel_token");
    localStorage.removeItem("sentinel_user");
  },

  // Dashboard & Health
  async health() {
    return handle(await fetch(`${B}/api/health`));
  },
  async stats() {
    return handle(await fetch(`${B}/api/dashboard/stats`));
  },
  async integrations() {
    return handle(await fetch(`${B}/api/integrations/matrix`));
  },

  // Audit Ledger & Integrity
  async audit(assessmentId = "") {
    const q = assessmentId ? `?assessment_id=${assessmentId}` : "";
    return handle(await fetch(`${B}/api/audit${q}`));
  },
  async auditIntegrity() {
    return handle(await fetch(`${B}/api/audit/integrity`));
  },

  // Scope Gate
  async scopeGateCheck(payload) {
    return handle(
      await fetch(`${B}/api/scope/gate-check`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(payload),
      })
    );
  },
  async validateScope(payload) {
    return handle(
      await fetch(`${B}/api/assessments/validate-scope`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })
    );
  },

  // Engagements
  async listAssessments() {
    return handle(await fetch(`${B}/api/assessments`));
  },
  async getAssessment(id) {
    return handle(await fetch(`${B}/api/assessments/${id}`));
  },
  async createAssessment(payload) {
    return handle(
      await fetch(`${B}/api/assessments`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(payload),
      })
    );
  },

  // Agent Planning, Chat & State
  async plan(payload) {
    return handle(
      await fetch(`${B}/api/assessments/plan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })
    );
  },
  async agentChat(id, message, target = "") {
    return handle(
      await fetch(`${B}/api/assessments/${id}/chat`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ message, target }),
      })
    );
  },
  async getAssessmentState(id) {
    return handle(await fetch(`${B}/api/assessments/${id}/state`));
  },

  // Findings & Artifacts
  async findings(id, severity = "") {
    const q = severity ? `?severity=${severity}` : "";
    return handle(await fetch(`${B}/api/assessments/${id}/findings${q}`));
  },
  async getFinding(id) {
    return handle(await fetch(`${B}/api/findings/${id}`));
  },
  async getArtifact(artifactId) {
    return handle(await fetch(`${B}/api/artifacts/${artifactId}`));
  },

  // Approvals Center
  async listApprovals(assessmentId = "") {
    const q = assessmentId ? `?assessment_id=${assessmentId}` : "";
    return handle(await fetch(`${B}/api/approvals${q}`));
  },
  async createApproval(payload) {
    return handle(
      await fetch(`${B}/api/approvals`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(payload),
      })
    );
  },
  async decideApproval(approvalId, payload) {
    return handle(
      await fetch(`${B}/api/approvals/${approvalId}/decide`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify(payload),
      })
    );
  },
  async approve(id, approved, note = "") {
    return handle(
      await fetch(`${B}/api/assessments/${id}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approved, note }),
      })
    );
  },

  // Scanners & Imports
  async importScan(id, file) {
    const fd = new FormData();
    fd.append("file", file);
    return handle(await fetch(`${B}/api/assessments/${id}/import`, { method: "POST", body: fd }));
  },
  async scan(id, tool, target) {
    return handle(
      await fetch(`${B}/api/assessments/${id}/scan`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ tool, target }),
      })
    );
  },
  async scans(id) {
    return handle(await fetch(`${B}/api/assessments/${id}/scans`));
  },
  reportUrl(id) {
    return `${B}/api/assessments/${id}/report`;
  },

  // MITRE ATT&CK Matrix & Navigator
  async mitre(id) {
    return handle(await fetch(`${B}/api/assessments/${id}/mitre`));
  },
  mitreNavigatorUrl(id) {
    return `${B}/api/assessments/${id}/mitre/navigator`;
  },

  // Assessment Diff & Retest Engine
  async diff(id, priorId) {
    return handle(await fetch(`${B}/api/assessments/${id}/diff/${priorId}`));
  },

  // Realtime Events (SSE)
  subscribeEvents(onMessage, onError) {
    const sseUrl = `${B}/api/realtime/events`;
    const eventSource = new EventSource(sseUrl);
    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onMessage && onMessage(data);
      } catch (err) {
        onMessage && onMessage({ raw: event.data });
      }
    };
    eventSource.onerror = (err) => {
      onError && onError(err);
    };
    return () => eventSource.close();
  },
};
