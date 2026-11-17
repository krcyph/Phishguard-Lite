/**
 * PhishGuard Lite — Express Backend Server
 *
 * Endpoints:
 *   GET  /           — health check
 *   POST /api/analyze — URL risk analysis
 *
 * Environment variables:
 *   PORT             — port to listen on (default 4000; Render sets this automatically)
 *   FRONTEND_URL     — allowed CORS origin (e.g. https://phishguard.vercel.app)
 */

import express, { Request, Response } from "express";
import cors from "cors";
import { analyzeUrl, isValidUrl } from "./analyzer";
import type { AnalysisResult, AnalyzeErrorResponse } from "./types/analysis";

const app = express();

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------
// In production, only allow the Vercel frontend origin.
// In development, allow any localhost origin for convenience.
// ---------------------------------------------------------------------------

const allowedOrigins: (string | RegExp)[] = [
  /^http:\/\/localhost(:\d+)?$/,
];

if (process.env.FRONTEND_URL) {
  allowedOrigins.push(process.env.FRONTEND_URL);
}

const corsOptions: cors.CorsOptions = {
  origin: allowedOrigins,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  optionsSuccessStatus: 204, // some legacy browsers choke on 204
  preflightContinue: false,  // let cors() respond to OPTIONS, not the next handler
};

// Handle preflight (OPTIONS) requests for every route first, before any middleware
// that might reject or transform the request (e.g. body-parser, auth checks).
app.options("*", cors(corsOptions));

// Apply CORS headers to all other requests.
app.use(cors(corsOptions));

// ---------------------------------------------------------------------------
// Body parser
// ---------------------------------------------------------------------------

app.use(express.json());

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/**
 * GET /
 * Health-check endpoint — confirms the backend is running.
 */
app.get("/", (_req: Request, res: Response) => {
  res.json({ status: "ok", message: "PhishGuard backend is running." });
});

/**
 * POST /api/analyze
 * Accepts { url: string } and returns an AnalysisResult.
 */
app.post(
  "/api/analyze",
  (req: Request, res: Response<AnalysisResult | AnalyzeErrorResponse>) => {
    if (req.method !== "POST") {
      res.setHeader("Allow", ["POST"]);
      res.status(405).json({ error: "Method Not Allowed. Use POST." });
      return;
    }

    const { url } = req.body as { url?: unknown };

    // ── Input validation ───────────────────────────────────────────────────
    if (!url || typeof url !== "string") {
      res.status(400).json({ error: "A URL string is required." });
      return;
    }

    const trimmed = url.trim();

    if (trimmed.length === 0) {
      res.status(400).json({ error: "URL must not be empty." });
      return;
    }

    if (trimmed.length > 2048) {
      res
        .status(400)
        .json({ error: "URL is too long (max 2048 characters)." });
      return;
    }

    // Add scheme for parsing if missing
    const forParsing =
      trimmed.startsWith("http://") || trimmed.startsWith("https://")
        ? trimmed
        : `http://${trimmed}`;

    if (!isValidUrl(forParsing)) {
      res.status(400).json({
        error:
          "The value you entered does not appear to be a valid URL. Please include a scheme (https://) and a valid hostname.",
      });
      return;
    }

    // ── Run analysis ───────────────────────────────────────────────────────
    try {
      const result = analyzeUrl(trimmed);
      res.status(200).json(result);
    } catch (err) {
      console.error("[analyze] Unexpected error:", err);
      res
        .status(500)
        .json({ error: "An internal error occurred during analysis." });
    }
  }
);

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------

const PORT = process.env.PORT ?? 4000;

app.listen(PORT, () => {
  console.log(`PhishGuard backend listening on port ${PORT}`);
});

export default app;
