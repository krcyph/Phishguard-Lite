/**
 * URL analysis engine — rule-based heuristic checks.
 *
 * The submitted URL is never fetched or visited.
 * All checks operate purely on the URL string structure.
 */

import type { AnalysisFlag, AnalysisResult, RiskLevel } from "./types/analysis";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Returns true if the string is a syntactically valid URL. */
export function isValidUrl(raw: string): boolean {
  try {
    new URL(raw);
    return true;
  } catch {
    return false;
  }
}

/** Returns true if the hostname is a raw IPv4 address. */
function isIpAddress(hostname: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

/**
 * Well-known brands whose name appearing in a *subdomain* (not the registered
 * domain itself) is a strong phishing signal.
 */
const TRUSTED_BRANDS = [
  "paypal", "google", "amazon", "apple", "microsoft", "facebook",
  "instagram", "twitter", "netflix", "ebay", "wellsfargo",
  "chase", "citibank", "hsbc", "dropbox", "linkedin", "youtube",
];

/** Suspicious keywords that appear in many phishing URL paths / queries. */
const SUSPICIOUS_KEYWORDS = [
  "login", "signin", "verify", "account", "update", "secure",
  "banking", "confirm", "password", "credential", "auth", "support",
  "service", "recover", "unlock", "alert", "billing", "invoice",
];

/** Characters / patterns used to obfuscate or redirect. */
const DECEPTIVE_CHARS = ["@", "%00", "%09", "%0a", "0x"];

/**
 * Homoglyph map: digits / symbols that visually resemble letters.
 * Used to detect lookalike domains such as g00gle.com or paypa1.com.
 */
const HOMOGLYPH_MAP: Record<string, string> = {
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "6": "g",
  "7": "t",
  "8": "b",
  "@": "a",
  "vv": "w",
  "rn": "m",
};

/**
 * Replaces homoglyphs in a string and returns the normalised version.
 * e.g. "g00gle" → "google"
 */
function normaliseHomoglyphs(str: string): string {
  let result = str;
  for (const [glyph, letter] of Object.entries(HOMOGLYPH_MAP)) {
    result = result.split(glyph).join(letter);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Trust-score rule engine
// ---------------------------------------------------------------------------
//
// Score starts at 100 (fully trusted).
// Suspicious signals DEDUCT points.
//
// Final thresholds:
//   score > 70  → "trustworthy"  (Likely Trustworthy)
//   score 40–70 → "medium"       (Medium Risk)
//   score < 40  → "high"         (High Risk / Likely Phishing)
//
// ---------------------------------------------------------------------------

export function analyzeUrl(raw: string): AnalysisResult {
  const flags: AnalysisFlag[] = [];
  let score = 100; // start fully trusted — deduct as we find problems

  // ── Normalise input ──────────────────────────────────────────────────────
  const trimmed = raw.trim();

  // Add scheme if missing so URL() can parse it
  const withScheme =
    trimmed.startsWith("http://") || trimmed.startsWith("https://")
      ? trimmed
      : `http://${trimmed}`;

  const parsed = new URL(withScheme); // guaranteed to succeed after isValidUrl
  const hostname = parsed.hostname.toLowerCase();
  const fullUrl = trimmed.toLowerCase();
  const domainParts = hostname.split(".");
  const registeredDomainLabel = domainParts.slice(-2)[0] ?? "";

  // ── Positive signal 1 — HTTPS ────────────────────────────────────────────
  if (parsed.protocol !== "https:") {
    score -= 25;
    flags.push({
      label: "No HTTPS",
      detail:
        "The URL uses plain HTTP instead of HTTPS. Legitimate websites use an encrypted connection. Sending data over HTTP can be intercepted.",
      severity: "warning",
    });
  }

  // ── Rule 1 — IP address instead of domain name ──────────────────────────
  if (isIpAddress(hostname)) {
    score -= 45;
    flags.push({
      label: "Raw IP address used as hostname",
      detail:
        "The URL uses a raw IPv4 address instead of a domain name. Phishing pages often do this to avoid registering a recognisable domain that could be reported or blocked.",
      severity: "danger",
    });
  }

  // ── Rule 2 — Homoglyph / lookalike domain ───────────────────────────────
  const normalisedLabel = normaliseHomoglyphs(registeredDomainLabel);
  const isHomoglyph = TRUSTED_BRANDS.some(
    (brand) =>
      normalisedLabel.includes(brand) &&
      !registeredDomainLabel.includes(brand)
  );
  if (isHomoglyph) {
    const matchedBrand = TRUSTED_BRANDS.find(
      (b) =>
        normalisedLabel.includes(b) && !registeredDomainLabel.includes(b)
    )!;
    score -= 50;
    flags.push({
      label: `Homoglyph / lookalike domain detected ("${registeredDomainLabel}")`,
      detail: `The domain "${hostname}" uses characters that visually resemble "${matchedBrand}" (e.g. the digit 0 for the letter o, or 1 for l). This is a classic phishing technique to trick users into thinking they are on a legitimate website.`,
      severity: "danger",
    });
  }

  // ── Rule 3 — Trusted brand name impersonated in subdomain ───────────────
  for (const brand of TRUSTED_BRANDS) {
    if (hostname.includes(brand)) {
      const registeredDomain = domainParts.slice(-2).join(".");
      if (!registeredDomain.includes(brand)) {
        score -= 35;
        flags.push({
          label: `Brand "${brand}" impersonated in subdomain`,
          detail: `"${brand}" appears in the subdomain but the real registered domain is "${registeredDomain}". Phishing sites use this trick to make a fake URL look like a trusted brand (e.g. google.attacker.com).`,
          severity: "danger",
        });
        break;
      }
    }
  }

  // ── Rule 4 — Excessive subdomains ───────────────────────────────────────
  if (domainParts.length > 4) {
    score -= 20;
    flags.push({
      label: "Excessive subdomains",
      detail: `The hostname "${hostname}" has ${domainParts.length} labels. Phishing URLs often chain many subdomains to bury the real registered domain at the end (e.g. paypal.secure.login.attacker.com).`,
      severity: "warning",
    });
  }

  // ── Rule 5 — Suspicious keywords in path / query ────────────────────────
  const pathAndQuery = (parsed.pathname + parsed.search).toLowerCase();
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter((kw) =>
    pathAndQuery.includes(kw)
  );
  if (foundKeywords.length >= 2) {
    score -= 15;
    flags.push({
      label: "Suspicious keywords in URL path",
      detail: `The URL path/query contains multiple sensitive keywords: "${foundKeywords.slice(0, 4).join('", "')}". Their combination is common in credential-harvesting pages.`,
      severity: "warning",
    });
  }

  // ── Rule 6 — Deceptive / obfuscating characters ─────────────────────────
  const foundChars = DECEPTIVE_CHARS.filter((ch) => fullUrl.includes(ch));
  if (foundChars.length > 0) {
    score -= 30;
    flags.push({
      label: "Deceptive or obfuscating characters",
      detail: `The URL contains characters used for obfuscation: "${foundChars.join('", "')}". For example, an "@" sign in a URL causes browsers to ignore everything before it, silently redirecting to a different host.`,
      severity: "danger",
    });
  }

  // ── Rule 7 — Multiple hyphens in registered domain ──────────────────────
  const hyphenCount = (registeredDomainLabel.match(/-/g) ?? []).length;
  if (hyphenCount >= 2) {
    score -= 15;
    flags.push({
      label: "Multiple hyphens in domain name",
      detail: `The domain "${hostname}" contains ${hyphenCount} hyphens. Phishing domains use hyphens to combine a brand name with other words to appear legitimate (e.g. secure-paypal-login.com).`,
      severity: "warning",
    });
  }

  // ── Rule 8 — URL shortener ───────────────────────────────────────────────
  const SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "shorturl.at",
  ];
  if (SHORTENERS.some((s) => hostname.endsWith(s))) {
    score -= 20;
    flags.push({
      label: "URL shortener detected",
      detail:
        "The URL passes through a link-shortening service, hiding the real destination. URL shorteners are frequently used in phishing campaigns to bypass email and browser filters.",
      severity: "warning",
    });
  }

  // ── Rule 9 — Unusually long URL ──────────────────────────────────────────
  if (trimmed.length > 100) {
    const deduction = trimmed.length > 150 ? 20 : 10;
    score -= deduction;
    flags.push({
      label: "Unusually long URL",
      detail: `The URL is ${trimmed.length} characters long. Very long URLs are sometimes used to hide the true destination by appending confusing parameters or path segments.`,
      severity: trimmed.length > 150 ? "danger" : "warning",
    });
  }

  // ── Rule 10 — Double file extension in path ──────────────────────────────
  if (/\.\w{2,4}\.\w{2,4}($|\?)/.test(parsed.pathname)) {
    score -= 15;
    flags.push({
      label: "Double file extension in path",
      detail:
        "The URL path contains a double file extension (e.g. document.pdf.html). This technique disguises the real file type to trick users into opening malicious files.",
      severity: "warning",
    });
  }

  // ── Clamp score to 0–100 ─────────────────────────────────────────────────
  score = Math.max(0, Math.min(100, score));

  // ── Derive risk level ────────────────────────────────────────────────────
  let riskLevel: RiskLevel;
  if (score > 70) {
    riskLevel = "trustworthy";
  } else if (score >= 40) {
    riskLevel = "medium";
  } else {
    riskLevel = "high";
  }

  // ── Summary ──────────────────────────────────────────────────────────────
  const riskLabel =
    riskLevel === "trustworthy"
      ? "Likely Trustworthy"
      : riskLevel === "medium"
      ? "Medium Risk"
      : "High Risk — Likely Phishing";

  const summary =
    flags.length === 0
      ? "No suspicious indicators were detected. This URL appears likely trustworthy, but always verify before entering personal information."
      : `${flags.length} suspicious indicator${flags.length > 1 ? "s were" : " was"} detected — overall assessment: ${riskLabel}. Review the details below.`;

  return {
    url: trimmed,
    riskLevel,
    score,
    flags,
    summary,
  };
}
