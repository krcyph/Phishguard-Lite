<div align="center">

# 🛡️ PhishGuard Lite

### Phishing URL Risk Checker

[![Next.js](https://img.shields.io/badge/Next.js-16.4-black?style=flat-square&logo=next.js)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
[![Express](https://img.shields.io/badge/Express-4.19-000000?style=flat-square&logo=express)](https://expressjs.com/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=flat-square&logo=node.js)](https://nodejs.org/)

> **B.Tech CSE — Semester 5 — Advanced Web Technologies Practical**
>
> A full-stack phishing URL risk checker built with Next.js and Express.  
> Analyses URLs using 10 rule-based heuristics and returns a trust score with plain-English explanations.  
> **The submitted URL is never fetched or visited.**

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Environment Variables](#-environment-variables)
- [How the Scoring Works](#-how-the-scoring-works)
- [API Reference](#-api-reference)
- [Production Builds](#-production-builds)
- [Deployment](#-deployment)
- [Disclaimer](#-disclaimer)

---

## 🔍 Overview

PhishGuard Lite is a full-stack web application that analyses a submitted URL against a set of **rule-based heuristic checks** and returns a plain-English risk assessment — **Likely Trustworthy**, **Medium Risk**, or **High Risk / Likely Phishing**.

No external threat-intelligence APIs are used. No database. The URL you submit is never fetched or resolved — all checks operate purely on the URL string itself.

---

## ✨ Features

### 🔎 10 Heuristic Detection Rules

| # | Rule | Severity | Score Deduction |
|---|------|----------|----------------|
| — | No HTTPS (HTTP used) | ⚠️ Warning | −25 |
| 1 | Raw IP address as hostname | 🔴 Danger | −45 |
| 2 | Homoglyph / lookalike domain (e.g. `g00gle.com`) | 🔴 Danger | −50 |
| 3 | Trusted brand impersonated in subdomain (e.g. `paypal.evil.com`) | 🔴 Danger | −35 |
| 4 | Excessive subdomains (> 4 labels) | ⚠️ Warning | −20 |
| 5 | Suspicious keywords in path/query (≥ 2 matches) | ⚠️ Warning | −15 |
| 6 | Deceptive / obfuscating characters (`@`, `%00`, `%09`, etc.) | 🔴 Danger | −30 |
| 7 | Multiple hyphens in registered domain (≥ 2) | ⚠️ Warning | −15 |
| 8 | URL shortener detected (`bit.ly`, `tinyurl.com`, etc.) | ⚠️ Warning | −20 |
| 9 | Unusually long URL (> 100 chars) | ⚠️ / 🔴 | −10 or −20 |
| 10 | Double file extension in path (e.g. `.pdf.html`) | ⚠️ Warning | −15 |

### 🎨 UI / UX

- **Dark cybersecurity-themed interface** — zero external CSS libraries, pure CSS with CSS custom properties
- **Trust score bar** — colour-coded green → orange → red based on score
- **Risk badge** — `Likely Trustworthy` / `Medium Risk` / `High Risk — Likely Phishing`
- **Per-flag detail cards** — each detected indicator has its own icon, label, and plain-English explanation
- **Fully responsive** — works on mobile and desktop
- **Loading spinner** and inline validation on empty submit
- **"Clear & Check Another URL"** button to reset state without a page reload

---

## 🛠 Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Frontend Framework | Next.js (Pages Router) | 16.4 |
| UI Library | React | 19 |
| Language | TypeScript | 5.5 |
| Backend Framework | Express | 4.19 |
| Runtime | Node.js | 18+ |
| Styling | Plain CSS (CSS custom properties, no libraries) | — |
| Package Manager | npm | — |
| Backend Dev Server | ts-node-dev (auto-restart) | 2.0 |

---

## 🏗 Architecture

The project is split into **two independently deployable services** that live in the same repository:

```
Browser  ──POST /api/analyze──►  Express Backend (port 4000)
         ◄──── JSON result ──────  Rule Engine (analyzer.ts)
```

| Service | Technology | Deployment Target |
|---------|-----------|-------------------|
| **Frontend** | Next.js + TypeScript | Vercel (project root) |
| **Backend** | Express + TypeScript | Render (`backend/` folder) |

The frontend communicates with the backend over HTTP using the `NEXT_PUBLIC_API_URL` environment variable. During local development it falls back to `http://localhost:4000`.

**CORS** is locked to the `FRONTEND_URL` env variable in production. Any `localhost` origin is automatically allowed in development.

---

## 📁 Project Structure

```
PhishGuard/
├── src/                              # Next.js frontend source
│   ├── pages/
│   │   ├── _app.tsx                  # App wrapper — imports global CSS
│   │   └── index.tsx                 # Main UI page (form + result panel)
│   ├── styles/
│   │   └── globals.css               # All application styles (dark theme)
│   └── types/
│       └── analysis.ts               # Shared TypeScript types (frontend)
│
├── backend/                          # Express backend source
│   ├── src/
│   │   ├── index.ts                  # Express server entry point + routes
│   │   ├── analyzer.ts               # URL analysis rule engine (10 rules)
│   │   └── types/
│   │       └── analysis.ts           # TypeScript types (mirrors frontend)
│   ├── package.json                  # Backend dependencies (express, cors)
│   └── tsconfig.json                 # Backend TypeScript config
│
├── .env.example                      # Frontend env variable template
├── .env.local                        # Frontend env (git-ignored)
├── .gitignore
├── next.config.js                    # Next.js config (reactStrictMode: true)
├── next-env.d.ts
├── package.json                      # Frontend dependencies
├── tsconfig.json                     # Frontend TypeScript config
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- **Node.js 18+** — [download](https://nodejs.org/)
- **npm 9+** (bundled with Node.js)

---

### Step 1 — Clone the repository

```bash
git clone https://github.com/your-username/PhishGuard.git
cd PhishGuard
```

---

### Step 2 — Start the Backend (Express on port 4000)

```bash
# Navigate to the backend folder
cd backend

# Install dependencies
npm install

# Start in development mode (auto-restarts on file changes)
npm run dev
```

The backend will be available at **`http://localhost:4000`**.

Verify it is running:

```bash
curl http://localhost:4000
# → { "status": "ok", "message": "PhishGuard backend is running." }
```

---

### Step 3 — Start the Frontend (Next.js on port 3000)

Open a **new terminal** in the project root.

```bash
# From the project root
npm install

# Copy the env template (already points to localhost:4000)
copy .env.example .env.local     # Windows
# cp .env.example .env.local     # macOS / Linux

# Start the Next.js dev server
npm run dev
```

Open **[http://localhost:3000](http://localhost:3000)** in your browser.

> **Note:** `.env.local` is already pre-configured with `NEXT_PUBLIC_API_URL=http://localhost:4000`, so no edits are needed for local development.

---

## ⚙️ Environment Variables

### Frontend — `.env.local` (project root)

| Variable | Required in Prod? | Default (dev) | Description |
|----------|------------------|---------------|-------------|
| `NEXT_PUBLIC_API_URL` | ✅ Yes | `http://localhost:4000` | Base URL of the deployed backend (no trailing `/`) |

```env
# .env.local
NEXT_PUBLIC_API_URL=https://phishguard-api.onrender.com
```

### Backend — environment (set via Render dashboard or local `.env`)

| Variable | Required in Prod? | Default | Description |
|----------|------------------|---------|-------------|
| `PORT` | Set by Render | `4000` | Port the Express server listens on |
| `FRONTEND_URL` | ✅ Yes | _(none)_ | Vercel frontend origin for CORS (no trailing `/`) |

```env
# Backend .env (Render dashboard or local file)
FRONTEND_URL=https://phishguard.vercel.app
```

---

## 🧮 How the Scoring Works

The analyzer uses a **trust-score** model (higher = safer):

```
Start:  100 points  (fully trusted)
         ↓
Deduct points for each suspicious signal found
         ↓
Clamp result to 0–100
         ↓
Classify:
  score > 70   →  🟢  Likely Trustworthy
  score 40–70  →  🟡  Medium Risk
  score < 40   →  🔴  High Risk — Likely Phishing
```

The score is returned in the API response for full transparency so the frontend can render the colour-coded bar.

---

## 📡 API Reference

### `GET /`

Health-check endpoint.

**Response `200`:**
```json
{ "status": "ok", "message": "PhishGuard backend is running." }
```

---

### `POST /api/analyze`

Analyses a URL string and returns a full risk assessment.

**Request body:**
```json
{ "url": "http://paypal-secure-login.attacker.com/verify?account=1" }
```

**Validation rules:**
- `url` must be a non-empty string
- Maximum length: **2048 characters**
- Must be parseable as a valid URL (scheme is auto-prepended if missing)

**Success response `200`:**
```json
{
  "url": "http://paypal-secure-login.attacker.com/verify?account=1",
  "riskLevel": "high",
  "score": 15,
  "flags": [
    {
      "label": "No HTTPS",
      "detail": "The URL uses plain HTTP instead of HTTPS...",
      "severity": "warning"
    },
    {
      "label": "Brand \"paypal\" impersonated in subdomain",
      "detail": "\"paypal\" appears in the subdomain but the real registered domain is \"attacker.com\"...",
      "severity": "danger"
    },
    {
      "label": "Suspicious keywords in URL path",
      "detail": "The URL path/query contains multiple sensitive keywords: \"verify\", \"account\"...",
      "severity": "warning"
    }
  ],
  "summary": "3 suspicious indicators were detected — overall assessment: High Risk — Likely Phishing. Review the details below."
}
```

**Error responses:**

| Status | Condition | Body |
|--------|-----------|------|
| `400` | Missing or empty `url` field | `{ "error": "A URL string is required." }` |
| `400` | URL exceeds 2048 characters | `{ "error": "URL is too long (max 2048 characters)." }` |
| `400` | Unparseable URL | `{ "error": "The value you entered does not appear to be a valid URL..." }` |
| `405` | Wrong HTTP method | `{ "error": "Method Not Allowed. Use POST." }` |
| `500` | Unexpected server error | `{ "error": "An internal error occurred during analysis." }` |

---

## 📦 Production Builds

### Backend

```bash
cd backend
npm run build    # Compiles TypeScript → dist/
npm start        # Runs dist/index.js with Node
```

### Frontend

```bash
# From project root
npm run build    # Next.js production build → .next/
npm start        # Starts the Next.js production server
```

### Type-checking (both services)

```bash
# Frontend (project root)
npm run type-check

# Backend
cd backend
npm run type-check
```

---

---

## ⚠️ Disclaimer

PhishGuard Lite applies **simple rule-based heuristics** and **cannot definitively identify phishing websites**. It is an educational tool built for a university practical and does not replace professional security software or browser-level phishing protection. Always exercise caution when visiting unfamiliar URLs.

---

<div align="center">

Made with ❤️ for **B.Tech CSE — Semester 5 — Advanced Web Technologies**

</div>
