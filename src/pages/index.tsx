import React, { useState } from "react";
import Head from "next/head";
import type { AnalysisResult, AnalyzeErrorResponse } from "@/types/analysis";


type PageState = "idle" | "loading" | "result" | "error";


function RiskBadge({ level }: { level: "trustworthy" | "medium" | "high" }) {
  const labels = {
    trustworthy: "Likely Trustworthy",
    medium: "Medium Risk",
    high: "High Risk — Likely Phishing",
  };
  return (
    <span className={`risk-badge risk-badge--${level}`} aria-label={labels[level]}>
      {labels[level]}
    </span>
  );
}

function ScoreBar({ score }: { score: number }) {
  // Score is now a TRUST score: high = good (green), low = bad (red)
  const capped = Math.min(Math.max(score, 0), 100);
  const colour = capped > 70 ? "#27ae60" : capped >= 40 ? "#e67e22" : "#c0392b";
  return (
    <div className="score-bar-wrapper" aria-label={`Trust score: ${score}/100`}>
      <div
        className="score-bar-fill"
        style={{ width: `${capped}%`, backgroundColor: colour }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function Home() {
  const [urlInput, setUrlInput] = useState("");
  const [pageState, setPageState] = useState<PageState>("idle");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [clientError, setClientError] = useState("");

  // ── Form validation & submission ─────────────────────────────────────────
  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setClientError("");
    setErrorMessage("");
    setResult(null);

    const trimmed = urlInput.trim();
    if (trimmed.length === 0) {
      setClientError("Please enter a URL before clicking Analyze.");
      return;
    }

    setPageState("loading");

    // Use the separate backend URL in production (set via NEXT_PUBLIC_API_URL).
    // Falls back to the local backend at port 4000 during development.
    const apiBase =
      process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";

    try {
      const response = await fetch(`${apiBase}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: trimmed }),
      });

      const data: AnalysisResult | AnalyzeErrorResponse = await response.json();

      if (!response.ok || "error" in data) {
        const msg = "error" in data ? data.error : "An unexpected error occurred.";
        setErrorMessage(msg);
        setPageState("error");
        return;
      }

      setResult(data as AnalysisResult);
      setPageState("result");
    } catch {
      setErrorMessage("Could not reach the analysis service. Please try again.");
      setPageState("error");
    }
  }

  // ── Reset ─────────────────────────────────────────────────────────────────
  function handleClear() {
    setUrlInput("");
    setPageState("idle");
    setResult(null);
    setErrorMessage("");
    setClientError("");
  }

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <>
      <Head>
        <title>PhishGuard Lite — Phishing URL Risk Checker</title>
        <meta
          name="description"
          content="An educational rule-based phishing URL risk checker built with Next.js and TypeScript."
        />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </Head>

      <div className="page-wrapper">
        {/* ── Header ─────────────────────────────────────────────────── */}
        <header className="header">
          <div className="header-icon" aria-hidden="true">🛡</div>
          <h1 className="header-title">PhishGuard Lite</h1>
          <p className="header-subtitle">Phishing URL Risk Checker</p>
          <p className="header-intro">
            Enter any website URL below to run a rule-based security analysis.
            PhishGuard Lite checks for common phishing indicators — such as
            missing HTTPS, suspicious subdomains, and obfuscated characters —
            and returns a risk assessment with plain-English explanations.
          </p>
        </header>

        {/* ── Main card ──────────────────────────────────────────────── */}
        <main className="card" aria-label="URL analysis form">
          <form onSubmit={handleSubmit} noValidate>
            <label htmlFor="url-input" className="input-label">
              Website URL
            </label>
            <div className="input-row">
              <input
                id="url-input"
                type="url"
                className={`url-input${clientError ? " url-input--error" : ""}`}
                placeholder="https://example.com"
                value={urlInput}
                onChange={(e) => {
                  setUrlInput(e.target.value);
                  if (clientError) setClientError("");
                }}
                disabled={pageState === "loading"}
                autoComplete="off"
                spellCheck={false}
                aria-describedby={clientError ? "client-error" : undefined}
              />
              <button
                type="submit"
                className="btn btn--primary"
                disabled={pageState === "loading"}
              >
                {pageState === "loading" ? "Analyzing…" : "Analyze URL"}
              </button>
            </div>

            {clientError && (
              <p id="client-error" className="inline-error" role="alert">
                {clientError}
              </p>
            )}
          </form>

          {/* ── Loading indicator ─────────────────────────────────── */}
          {pageState === "loading" && (
            <div className="status-box status-box--info" role="status">
              <span className="spinner" aria-hidden="true" /> Running analysis…
            </div>
          )}

          {/* ── Error from API ────────────────────────────────────── */}
          {pageState === "error" && (
            <div className="status-box status-box--danger" role="alert">
              <strong>Error:</strong> {errorMessage}
              <button className="btn btn--ghost btn--sm" onClick={handleClear}>
                Try again
              </button>
            </div>
          )}

          {/* ── Result panel ──────────────────────────────────────── */}
          {pageState === "result" && result && (
            <section className="result-panel" aria-label="Analysis results">
              {/* Risk header */}
              <div className={`result-header result-header--${result.riskLevel}`}>
                <div className="result-header-left">
                  <p className="result-url" title={result.url}>
                    {result.url.length > 72
                      ? result.url.slice(0, 69) + "…"
                      : result.url}
                  </p>
                  <RiskBadge level={result.riskLevel} />
                </div>
                <div className="result-score-col">
                  <span className="result-score-label">Trust score</span>
                  <span className="result-score-value">{result.score}</span>
                  <ScoreBar score={result.score} />
                </div>
              </div>

              {/* Summary */}
              <p className="result-summary">{result.summary}</p>

              {/* Flags */}
              {result.flags.length > 0 ? (
                <ul className="flag-list" aria-label="Detected risk indicators">
                  {result.flags.map((flag, i) => (
                    <li key={i} className={`flag-item flag-item--${flag.severity}`}>
                      <div className="flag-header">
                        <span className="flag-icon" aria-hidden="true">
                          {flag.severity === "danger"
                            ? "⚠"
                            : flag.severity === "warning"
                            ? "▲"
                            : "ℹ"}
                        </span>
                        <strong className="flag-label">{flag.label}</strong>
                      </div>
                      <p className="flag-detail">{flag.detail}</p>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="no-flags">
                  ✓ No suspicious indicators detected.
                </p>
              )}

              {/* Clear button */}
              <div className="result-actions">
                <button className="btn btn--secondary" onClick={handleClear}>
                  Clear &amp; Check Another URL
                </button>
              </div>
            </section>
          )}
        </main>

        {/* ── Footer / disclaimer ────────────────────────────────────── */}
        <footer className="footer">
          <p className="disclaimer">
            <strong>Disclaimer:</strong> PhishGuard Lite is an educational
            tool that applies rule-based heuristics. It <em>cannot</em>{" "}
            definitively identify phishing websites and does not replace
            professional security software. Always exercise caution when
            visiting unfamiliar URLs.
          </p>
        </footer>
      </div>
    </>
  );
}
