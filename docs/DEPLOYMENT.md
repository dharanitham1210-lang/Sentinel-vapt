# SentinelVAPT — Free-Tier Cloud Deployment Guide

This guide details the complete, production-grade cloud deployment architecture for **SentinelVAPT**:
- **Frontend:** Hosted on **Vercel** (Global Edge CDN, automatic HTTPS, zero-config SPA routing).
- **Backend:** Hosted on **Render** as a **Docker Web Service** (Python 3.12-slim, non-root `appuser`, preinstalled `nmap` and `nikto`).
- **Database:** Hosted on **Neon Serverless PostgreSQL** (`sslmode=require`, connection retry handling scale-to-zero cold starts).
- **Storage:** Database-backed content-addressed artifact store (`STORAGE_BACKEND=database`), persisting SHA-256 evidence across container restarts without a paid disk.
- **Authorized Lab Target:** **OWASP Juice Shop** deployed as an independent free web service owned by the assessor.

---

## 1. System Architecture

```mermaid
graph TD
    User([Security Analyst / Client]) -->|HTTPS / WSS| Vercel[Vercel Global Edge CDN<br/>React + Vite Frontend<br/><i>sentinelvapt.vercel.app</i>]
    Vercel -->|REST API / SSE Events| Render[Render Docker Web Service<br/>FastAPI Backend :8000<br/>Non-Root appuser + Nmap + Nikto<br/><i>sentinelvapt-api.onrender.com</i>]
    
    subgraph Data Tier
        Render -->|psycopg / sslmode=require| Neon[(Neon Serverless Postgres<br/>Scale-to-Zero Compute<br/>Audits, Findings, Artifacts)]
    end

    subgraph Authorized Cloud Assessment Target
        Render -->|TCP Connect Scan / HTTP Probes| JuiceShop[OWASP Juice Shop<br/>Free Cloud Lab Instance<br/><i>juice-shop-lab.onrender.com</i>]
    end

    subgraph Deterministic Safety Controls
        ScopeGate{Scope Gate<br/>Deterministic Allowlist}
        ApprovalGate{Dual Human<br/>Approval Gate}
        Render --> ScopeGate
        ScopeGate --> ApprovalGate
    end
```

---

## 2. Environment Variables Specification

| Variable | Target Service | Required? | Example / Value | Description |
|---|---|---|---|---|
| `DATABASE_URL` | Render (Backend) | **Yes** | `postgresql://user:pass@ep-cool-db.us-east-2.aws.neon.tech/neondb?sslmode=require` | Neon Postgres connection URI. Must include `sslmode=require`. |
| `SECRET_KEY` | Render (Backend) | **Yes** | `a9f4c3d8e2b1076f8a4e9c1d3b5a7f2e` | 32+ character random secret for signing session tokens and approval hashes. |
| `ALLOWED_ORIGINS` | Render (Backend) | **Yes** | `https://sentinelvapt.vercel.app` | Comma-separated allowlist of frontend URLs permitted by CORS. |
| `CLOUD_MODE` | Render (Backend) | **Yes** | `true` | Enforces cloud safety: disables live Metasploit, forces non-root connect scans, blocks unlisted loopbacks. |
| `STORAGE_BACKEND` | Render (Backend) | **Yes** | `database` | Stores raw scanner artifacts directly in Neon Postgres with SHA-256 verification. |
| `ADMIN_EMAIL` | Render (Backend) | **Yes** | `lead@security-firm.com` | Initial administrator account email/username. |
| `ADMIN_PASSWORD` | Render (Backend) | **Yes** | `Str0ngP@ssw0rd!2026` | Initial administrator password (hashed via scrypt on startup). |
| `LLM_API_KEY` | Render (Backend) | Optional | `sk-...` | Optional OpenAI or compatible API key for natural language reasoning. |
| `LLM_BASE_URL` | Render (Backend) | Optional | `https://api.openai.com/v1` | Base URL for LLM provider. |
| `LLM_MODEL` | Render (Backend) | Optional | `gpt-4o-mini` | Model identifier for grounding validator. |
| `VITE_API_URL` | Vercel (Frontend) | **Yes** | `https://sentinelvapt-backend.onrender.com` | Public HTTPS URL of the live Render backend (no trailing slash). |

---

## 3. Step-by-Step Deployment Order

Follow this exact sequential order to prevent circular dependency issues:

```
[Step 1: Neon DB] ──► [Step 2: Render Backend] ──► [Step 3: Vercel Frontend] ──► [Step 4: Connect & Sync]
```

### Step 1: Provision Neon Serverless PostgreSQL
1. Sign up or log in at [console.neon.tech](https://console.neon.tech/).
2. Click **Create Project**:
   - **Project Name:** `sentinelvapt-db`
   - **Postgres Version:** `16` (or latest)
   - **Region:** Choose the region closest to your Render location (e.g., `US East (Ohio)`).
3. On the project dashboard, locate the **Connection Details** box.
4. Select **Connection String** and ensure **Pooled connection** or direct connection is displayed with `sslmode=require`.
5. Copy the connection URI:
   ```
   postgresql://<username>:<password>@<ep-name>.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```
6. Save this string securely for Step 2.

---

### Step 2: Deploy Backend on Render (Docker Web Service)
1. Push this repository to your GitHub account.
2. Log in to [dashboard.render.com](https://dashboard.render.com/).
3. Click **New +** → **Blueprint** (or **Web Service**).
   - If using **Blueprint**: Render will read [`render.yaml`](../render.yaml) automatically and prompt only for values marked `sync: false`.
   - If using manual **Web Service**:
     - **Name:** `sentinelvapt-backend`
     - **Region:** Same region as Neon (e.g., `Ohio (US East)`).
     - **Branch:** `main`
     - **Runtime:** `Docker`
     - **Dockerfile Path:** `./backend/Dockerfile`
     - **Docker Context:** `./backend`
     - **Instance Type:** `Free`
4. Set the **Environment Variables**:
   - `DATABASE_URL` = `<your-neon-connection-string>`
   - `SECRET_KEY` = `<generate-32-character-random-hex>` (e.g. `openssl rand -hex 16`)
   - `ALLOWED_ORIGINS` = `*` *(temporarily allow all; we will restrict this to your Vercel URL in Step 4)*
   - `CLOUD_MODE` = `true`
   - `STORAGE_BACKEND` = `database`
   - `ADMIN_EMAIL` = `admin@sentinelvapt.io`
   - `ADMIN_PASSWORD` = `<your-secure-password>`
5. Click **Create Web Service**.
6. Wait for the build to complete. The logs will display:
   ```
   INFO: Application startup complete.
   INFO: Uvicorn running on http://0.0.0.0:8000
   ```
7. Verify by opening in your browser:
   `https://<your-render-service>.onrender.com/health`
   *(Should return: `{"status":"healthy","version":"1.0.0","cloud_mode":true,"database":"postgres"}`)*
8. Copy your Render backend URL (e.g. `https://sentinelvapt-backend.onrender.com`).

---

### Step 3: Deploy Frontend on Vercel
1. Log in to [vercel.com](https://vercel.com/) and click **Add New...** → **Project**.
2. Select your `SentinelVAPT` GitHub repository and click **Import**.
3. Configure Project Settings:
   - **Framework Preset:** `Vite`
   - **Root Directory:** `./` *(or `frontend`)*
   - **Build Command:** `npm run build`
   - **Output Directory:** `frontend/dist` *(or `dist` if root was set to `frontend`)*
4. Under **Environment Variables**, add:
   - **Key:** `VITE_API_URL`
   - **Value:** `https://<your-render-service>.onrender.com` *(from Step 2, no trailing slash)*
5. Click **Deploy**.
6. When deployment finishes, copy your live Vercel domain (e.g., `https://sentinelvapt.vercel.app`).

---

### Step 4: Finalize CORS Security
1. Return to [dashboard.render.com](https://dashboard.render.com/) → `sentinelvapt-backend` → **Environment**.
2. Update `ALLOWED_ORIGINS` to your exact Vercel production domain:
   ```
   ALLOWED_ORIGINS=https://sentinelvapt.vercel.app
   ```
3. Click **Save Changes**. Render will automatically restart the backend with the locked-down CORS origin.

---

## 4. Deploying the Authorized Cloud Lab Target (OWASP Juice Shop)

> [!IMPORTANT]
> **Strict Rules of Engagement:**
> In accordance with cybersecurity ethics and cloud provider Terms of Service:
> - You may **ONLY** run security scans against infrastructure you own or have explicit written authorization to test.
> - **Never** scan Render, Vercel, Neon, or third-party infrastructure.
> - **127.0.0.1 in the cloud refers to the backend container itself**, not your local computer.

### How to Deploy Your Own Juice Shop Lab Instance:
1. In [dashboard.render.com](https://dashboard.render.com/), click **New +** → **Web Service** → **Deploy an existing image**.
2. **Image URL:** `bkimminich/juice-shop:latest`
3. **Name:** `sentinel-lab-juiceshop`
4. **Instance Type:** `Free`
5. Click **Create Web Service**.
6. Once deployed, note your private lab target URL:
   `https://sentinel-lab-juiceshop.onrender.com`

### Registering the Lab Target in Scope Gate:
1. Open your live SentinelVAPT console on Vercel.
2. Go to **Engagements & Scope** → **Create Engagement**.
3. Fill in:
   - **Target Host:** `sentinel-lab-juiceshop.onrender.com`
   - **Allowed Hostnames:** `sentinel-lab-juiceshop.onrender.com`
   - **Authorization Statement:** `"I own and operate this Juice Shop instance for authorized security assessment."`
4. The Scope Gate validates the target, rejects unauthorized targets, and allows scanning against your lab application only.

---

## 5. Free-Tier Characteristics, Limits & Cold Starts

1. **Render Free Tier Spin-Down (Cold Start):**
   - Free Render web services sleep after 15 minutes of inactivity.
   - The first HTTP request after sleeping takes **30–50 seconds** to start the container.
   - **Pro-Tip for Demos:** Ping your backend (`curl https://<backend>.onrender.com/health`) 2 minutes before presenting so it is warm and instantaneous.
   - The frontend console includes an automatic status indicator that notifies users when the backend is warming up.

2. **Neon Free Tier Limits:**
   - 0.5 GB storage (ample for thousands of assessments, findings, and artifacts).
   - Compute suspends after 5 minutes of idle time. The backend's connection retry loop handles this automatically with zero user impact.

3. **Vercel Free Tier Limits:**
   - 100 GB monthly bandwidth, unlimited deployments.

---

## 6. Rollback & Disaster Recovery Strategy

If an update breaks production or causes schema conflicts:
1. **Frontend Rollback:** In the Vercel Dashboard, go to **Deployments**, locate the last known healthy deployment, click **...** → **Promote to Production** (instantaneous 0-second rollback).
2. **Backend Rollback:** In the Render Dashboard, go to **Events** → select previous successful deploy → click **Rollback to this deploy**.
3. **Database Recovery:** Neon provides point-in-time branch recovery. In the Neon Console, you can create a branch at any timestamp within the last 24 hours without downtime.

