/**
 * Shared TypeScript types for PhishGuard Lite backend.
 * Mirrors src/types/analysis.ts in the frontend.
 */

/** Trust-based risk levels.
 *  trustworthy = score > 70  (likely safe)
 *  medium      = score 40-70 (some suspicious signals)
 *  high        = score < 40  (strongly suspicious / likely phishing)
 */
export type RiskLevel = "trustworthy" | "medium" | "high";

export interface AnalysisFlag {
  /** Short label shown in the UI */
  label: string;
  /** Detailed explanation shown below the label */
  detail: string;
  /** Severity of this individual flag */
  severity: "info" | "warning" | "danger";
}

export interface AnalysisResult {
  /** The URL that was analyzed */
  url: string;
  /** Overall computed risk level */
  riskLevel: RiskLevel;
  /** Numeric score used to derive the risk level (for transparency) */
  score: number;
  /** List of rule findings */
  flags: AnalysisFlag[];
  /** Human-readable summary sentence */
  summary: string;
}

export interface AnalyzeRequestBody {
  url: string;
}

export interface AnalyzeErrorResponse {
  error: string;
}

export type AnalyzeResponse = AnalysisResult | AnalyzeErrorResponse;
