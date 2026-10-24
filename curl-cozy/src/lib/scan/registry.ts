import type { CheckId, ScanPlan } from "./types";
export type ScanImpact = "passive" | "light" | "medium" | "intrusive";
export interface ScanPolicy {
  maxImpact: ScanImpact;
  allowIntrusive: boolean;
  includeExperimental: boolean;
  maxDurationMs: number;
  requestTimeoutMs: number;
}
export interface CheckMetadata {
  id: CheckId | string;
  name: string;
  impact: ScanImpact;
  status: "implemented" | "experimental" | "planned";
  execution: "manual" | "automatic" | "both";
  category: string;
  requirements: string;
  verification: string;
}
const entry = (
  id: CheckMetadata["id"],
  name: string,
  impact: ScanImpact,
  category: string,
  requirements: string,
  verification: string,
  status: CheckMetadata["status"] = "implemented",
  execution: CheckMetadata["execution"] = "manual",
): CheckMetadata => ({ id, name, impact, category, requirements, verification, status, execution });
export const checkRegistry: readonly CheckMetadata[] = [
  entry("host-header", "Host header injection", "medium", "Headers", "Stable response and dedicated pinned host-override sender", "Two independent host markers in redirect/HTML absolute URLs, unused-header controls and restored original", "experimental"),
  entry(
    "parameter-hints",
    "Literal parameter-name discovery",
    "passive",
    "Discovery",
    "Captured HTML or script",
    "Literal hints only; no requests sent",
  ),
  entry(
    "hidden-parameters",
    "Hidden parameter and header discovery",
    "intrusive",
    "Discovery",
    "Stable successful baseline",
    "Named input repeats a differential; random-name control and original restoration; not a vulnerability",
  ),
  entry(
    "business-negative",
    "Numeric bounds and persistence",
    "intrusive",
    "Business logic",
    "Automatically detected numeric scalar (any field name); successful JSON baselines",
    "Negative, zero, large, fractional and boundary probes; optional independent GET read-back; original-value and invalid-number controls",
  ),
  entry(
    "business-dates",
    "Past and malformed dates",
    "intrusive",
    "Business logic",
    "Automatically detected ISO date value; successful JSON baselines",
    "Two successful malformed/past probes and original-value control; past dates only for future baseline",
  ),
  entry(
    "jwt-jwk",
    "JWT embedded jwk trust",
    "medium",
    "JWT",
    "Protected RS256 Bearer JWT; Web Crypto",
    "Attacker-key token acceptance with denied missing-source and wrong-signature controls",
    "experimental",
  ),
  entry(
    "jwt-jku",
    "JWT remote jku trust",
    "medium",
    "OAST",
    "Protected RS256 Bearer JWT; reachable key-hosting collector",
    "Signed-token acceptance plus HTTP key-fetch correlation; no callback-only auth findings",
    "experimental",
  ),
  entry(
    "jwt-x5u",
    "JWT remote x5u certificate trust",
    "medium",
    "OAST",
    "Protected RS256 Bearer JWT; reachable certificate-hosting collector",
    "Signed-token acceptance plus HTTP certificate-fetch correlation and signature controls",
    "experimental",
  ),
  entry(
    "jwt-kid",
    "JWT kid key-lookup injection",
    "intrusive",
    "JWT",
    "Protected HS256/384/512 JWT",
    "Null-file and SQL literal key-selection probes; repeated signature-checked acceptance, missing-key controls and restore",
    "experimental",
  ),
  entry(
    "jwt-confusion",
    "JWT RSA/HMAC algorithm confusion",
    "medium",
    "JWT",
    "Signed RS256/384/512 Bearer JWT; matching RSA SPKI/PKCS#1 public key, certificate or same-origin JWKS discovery; Web Crypto",
    "Original signature verified locally; repeated HMAC-token acceptance with denied anonymous, malformed, RSA-signature and wrong-key controls",
    "experimental",
  ),
  entry(
    "cors-trust",
    "CORS null and hostname validation bypass",
    "light",
    "CORS",
    "Stable successful nonempty baselines",
    "Credentialed reflection with two probes, unrelated-origin denial and original restoration; browser review required",
    "experimental",
  ),
  entry(
    "nosql-operators",
    "NoSQL JSON operator interpretation",
    "medium",
    "Injection",
    "Selected JSON string; stable successful JSON data baselines",
    "Two exact/nonmatching regex pairs and scalar restoration; query DSL and impact require review",
    "experimental",
  ),
  entry(
    "jwt-weak-secret",
    "JWT weak HMAC signing secret (local)",
    "passive",
    "JWT",
    "Captured Bearer JWT using HS256/384/512; Web Crypto",
    "Local signature verification against a bounded common-key dictionary; no network requests",
  ),
  entry(
    "nosql-injection",
    "NoSQL parser differential",
    "medium",
    "Injection",
    "Selected query, form or JSON parameter; stable successful baselines",
    "Repeated database-specific errors absent from benign and restored controls; not confirmed data access",
    "experimental",
  ),
  entry(
    "403-bypass",
    "Automatic 403 header bypass audit",
    "medium",
    "Access control",
    "New captured API returning 403; stable denial; same endpoint/method/body",
    "Repeated successful JSON mutation, denied negative control and original denial restore; impact requires review",
    "experimental",
    "automatic",
  ),
  entry(
    "dependency-audit",
    "Vulnerable JavaScript dependencies (OSV)",
    "passive",
    "Dependencies",
    "Captured JS; explicit exact-version banner; internet access to OSV (package/version only)",
    "Exact npm version advisory match; runtime and exploitability require review",
    "experimental",
  ),
  entry(
    "jwt-signature",
    "JWT signature verification",
    "medium",
    "JWT",
    "Signed Bearer JWT; successful stable baseline",
    "Repeated invalid/absent signatures and none/None/NONE/nOnE variants, isolated JWT and denied anonymous/malformed controls",
    "experimental",
  ),
  entry(
    "graphql-introspection",
    "GraphQL schema introspection",
    "light",
    "GraphQL",
    "Captured GraphQL GET/POST operation",
    "Repeated bounded read-only introspection and unknown-field control",
  ),
  entry(
    "graphql-batching",
    "GraphQL batch operation policy",
    "light",
    "GraphQL",
    "GraphQL POST",
    "Two read-only operations; repeat and single-operation control",
  ),
  entry(
    "http-framing",
    "HTTP/1 ambiguous request framing",
    "intrusive",
    "Protocol",
    "GET endpoint; dedicated raw connection engine; no credentials sent",
    "Fresh connections; CL/TE and conflicting CL probes with repeated ordinary/chunked controls; not confirmed smuggling",
    "experimental",
  ),
  entry(
    "dom-interaction",
    "DOM XSS (input and event interaction)",
    "medium",
    "Browser",
    "Chrome/Chromium; HTML snapshot; bounded synthetic input, mouseover, focus and click events",
    "Script audit, independent executions and identical interaction controls",
    "experimental",
  ),
  entry(
    "oast-ssrf",
    "Blind SSRF (OAST HTTP/DNS)",
    "medium",
    "OAST",
    "Reachable self-hosted collector; selected query/JSON parameter",
    "Two independent correlated callbacks and an unsubmitted control; external interaction only",
    "experimental",
  ),
  entry(
    "oast-xxe",
    "Blind XXE (OAST HTTP/DNS)",
    "medium",
    "OAST",
    "Reachable self-hosted collector; XML body without existing DTD or signature",
    "External parameter-entity requests; independent callbacks and an unsubmitted control",
    "experimental",
  ),
  entry(
    "browser-xss",
    "Reflected and DOM XSS (browser validation)",
    "medium",
    "Browser",
    "Installed Chrome/Chromium; selected query/JSON parameter; HTML response up to 256 KB",
    "Two independent execution callbacks and plain/original controls; network-isolated response snapshot",
    "experimental",
  ),
  entry(
    "dom-xss",
    "DOM XSS (script audit and browser validation)",
    "medium",
    "Browser",
    "Installed Chrome/Chromium; HTML and captured scripts; same-origin or Target Scope script URLs",
    "AST source/sink audit, benign marker, context-selected query/fragment payloads and independent execution controls",
    "experimental",
  ),
  entry(
    "xml-injection-body",
    "XML body parser differential",
    "medium",
    "XML",
    "XML Content-Type and body; stable successful baselines",
    "Repeated XML parser errors and controls",
    "experimental",
  ),
  entry(
    "xml-entity-body",
    "XML body internal entity processing",
    "medium",
    "XML",
    "XML Content-Type and body; stable successful baselines",
    "Two bounded internal entities; does not establish XXE",
    "experimental",
  ),
  entry(
    "xxe-body",
    "XML body XXE local-file entities",
    "intrusive",
    "XML",
    "XML Content-Type and body; stable successful baselines",
    "Repeated file signatures; escaped and missing-file controls",
    "experimental",
  ),

  entry(
    "command-injection",
    "OS command injection (POSIX)",
    "intrusive",
    "Injection",
    "Selected parameter; stable successful baselines",
    "Two split printf outputs, plain controls and original restore",
    "experimental",
  ),
  entry(
    "code-injection",
    "Server-side code arithmetic",
    "intrusive",
    "Injection",
    "Selected parameter; stable successful baselines",
    "Two products and non-evaluating controls; runtime not proven",
    "experimental",
  ),
  entry(
    "el-injection",
    "Expression language arithmetic",
    "medium",
    "Injection",
    "Selected parameter; stable successful baselines",
    "Dollar/hash expression products; negative and original controls",
    "experimental",
  ),
  entry(
    "ldap-injection",
    "LDAP parser differential",
    "medium",
    "Injection",
    "Selected parameter; stable successful baselines",
    "Repeated LDAP-specific errors absent from controls",
    "experimental",
  ),
  entry(
    "xpath-injection",
    "XPath parser differential",
    "medium",
    "Injection",
    "Selected parameter; stable successful baselines",
    "Repeated XPath-specific errors absent from controls",
    "experimental",
  ),
  entry(
    "xml-injection",
    "XML parser differential",
    "medium",
    "XML",
    "Selected XML-bearing parameter; stable successful baselines",
    "Repeated XML parser errors absent from controls",
    "experimental",
  ),
  entry(
    "xml-entity",
    "XML internal entity processing",
    "medium",
    "XML",
    "Selected XML-bearing parameter; stable successful baselines",
    "Two bounded split entities; does not establish XXE",
    "experimental",
  ),
  entry(
    "xxe",
    "XXE local-file entities",
    "intrusive",
    "XML",
    "Selected XML-bearing parameter; stable successful baselines",
    "Repeated local-file signatures; escaped and missing-file controls",
    "experimental",
  ),

  entry(
    "sql-boolean",
    "SQL boolean differential",
    "medium",
    "Injection",
    "Stable successful baselines; selected parameters",
    "Repeated true/false pairs and original controls",
    "experimental",
  ),
  entry(
    "sql-time",
    "SQL timing differential (MySQL)",
    "intrusive",
    "Injection",
    "Stable low-jitter baselines; selected parameters; sufficient timeout",
    "Two bounded 2-second delays, zero-delay and original controls",
    "experimental",
  ),
  entry(
    "header-injection",
    "Response header injection",
    "medium",
    "Headers",
    "Selected parameters",
    "Two CRLF response-header markers and plain-text controls",
    "experimental",
  ),
  entry(
    "auth-access",
    "Anonymous and invalid-credential access",
    "medium",
    "Authentication",
    "Stable successful authenticated response",
    "Repeated anonymous, invalid-token and restored-original comparisons",
    "experimental",
  ),
  entry(
    "referer-access",
    "Referer-dependent access",
    "medium",
    "Access control",
    "Stable denied baseline",
    "Candidate, negative and restored-denial controls",
    "experimental",
  ),
  entry(
    "client-ip",
    "Client IP header trust",
    "medium",
    "Access control",
    "Stable denied baseline; X-Real-IP / X-Client-IP",
    "Repeated denied-to-success change and negative controls",
    "experimental",
  ),
  entry(
    "url-override",
    "URL override header routing",
    "medium",
    "Routing",
    "Stable baseline; X-Original-URL / X-Rewrite-URL",
    "Current-path, repeated missing-path and restored controls",
    "experimental",
  ),
  entry(
    "http-methods",
    "OPTIONS and TRACE",
    "medium",
    "Methods",
    "Selected endpoint; credentials stripped",
    "Allow advertisement and repeated TRACE marker reflection; no PUT writes",
  ),

  entry(
    "cookie-flags",
    "Cookie flags",
    "passive",
    "Cookies",
    "Separate Set-Cookie fields",
    "Direct attribute observation",
  ),
  entry(
    "error-disclosure",
    "Error disclosure",
    "passive",
    "Disclosure",
    "Response text",
    "Signature; contextual review",
  ),
  entry(
    "security-headers",
    "Response headers",
    "passive",
    "Headers",
    "Successful HTML response",
    "Direct header observation",
  ),
  entry(
    "passive-audit",
    "Headers, transport and disclosure audit",
    "passive",
    "Configuration",
    "Captured response",
    "Configuration observations",
  ),
  entry(
    "cookie-audit",
    "Cookie scope and prefix audit",
    "passive",
    "Cookies",
    "Separate Set-Cookie fields",
    "Attribute and scope observation",
  ),
  entry(
    "disclosure-audit",
    "Sensitive data and technology audit",
    "passive",
    "Disclosure",
    "Captured request/response",
    "Bounded signatures; masked excerpts",
  ),
  entry(
    "policy-audit",
    "CSP, MIME and transport policy audit",
    "passive",
    "Headers",
    "Captured response",
    "Directive and content observations",
  ),
  entry(
    "reflection",
    "Input reflection",
    "medium",
    "Input",
    "Selected parameters",
    "Two independent reflected markers",
  ),
  entry(
    "input-errors",
    "Input error handling",
    "medium",
    "Input",
    "Stable baselines; selected parameters",
    "Malformed, repeat and original controls",
  ),
  entry(
    "cors",
    "CORS origin handling",
    "light",
    "CORS",
    "Successful baselines",
    "Two origins; browser review required",
    "implemented",
    "both",
  ),
  entry(
    "sql-injection",
    "SQL error, quote-repair and boolean differentials",
    "medium",
    "Injection",
    "Stable baselines; selected parameters",
    "Repeated SQL errors, quote repair or true/false groups; original controls",
    "experimental",
  ),
  entry(
    "ssti",
    "Template arithmetic",
    "medium",
    "Injection",
    "Stable baselines; selected parameters",
    "Two arithmetic probes with invalid-expression controls",
    "experimental",
  ),
  entry(
    "path-traversal",
    "File path traversal",
    "intrusive",
    "File access",
    "Stable baselines; selected parameters",
    "Repeated file signatures and missing-file control",
    "experimental",
  ),
  entry(
    "open-redirect",
    "Open redirect",
    "light",
    "Navigation",
    "Selected parameters",
    "Two Location destinations; never followed",
  ),
  entry(
    "noauthen",
    "Anonymous API response",
    "medium",
    "Authentication",
    "New proxy API capture",
    "HTTP 200 without common credentials; review required",
    "experimental",
    "automatic",
  ),
  entry(
    "js-endpoints",
    "JavaScript endpoint discovery",
    "passive",
    "Discovery",
    "New JavaScript response",
    "Literal extraction; URLs not fetched",
    "implemented",
    "automatic",
  ),
  entry(
    "js-secrets",
    "JavaScript credential discovery",
    "passive",
    "Disclosure",
    "New JavaScript response",
    "Masked literal signatures; no credential validation",
    "experimental",
    "automatic",
  ),
  entry(
    "browser-analysis",
    "Full browser taint and interaction analysis",
    "medium",
    "Browser",
    "Full taint propagation, event exploration and stateful browser workflows",
    "End-to-end taint and interaction evidence",
    "planned",
  ),
  entry(
    "stored-analysis",
    "Stored and second-order injection",
    "intrusive",
    "Workflow",
    "Stateful flows and cleanup",
    "Create, trigger, observe and restore",
    "planned",
  ),
  entry(
    "oast-analysis",
    "Extended OAST workflows and delayed callbacks",
    "medium",
    "OAST",
    "Persistent background correlation, external collector providers and longer callback windows",
    "Workflow-aware callback attribution",
    "planned",
  ),
  entry(
    "protocol-analysis",
    "Cross-request smuggling, HTTP/2 desync and cache poisoning",
    "intrusive",
    "Protocol",
    "Raw HTTP/connection engine",
    "Connection-level controls",
    "planned",
  ),
  entry(
    "jwt-analysis",
    "Extended JWT key and algorithm attacks",
    "medium",
    "JWT",
    "Additional algorithms, key stores and key-source attack contexts",
    "Modified-token acceptance controls",
    "planned",
  ),
  entry(
    "graphql-analysis",
    "GraphQL authorization and resource-limit attacks",
    "light",
    "GraphQL",
    "Account-aware field authorization and controlled complexity testing",
    "Introspection and operation controls",
    "planned",
  ),
  entry(
    "dependency-analysis",
    "Extended bundle dependency identification",
    "passive",
    "Dependencies",
    "Source-map/lockfile attribution and libraries without explicit banners",
    "Exact version and advisory match",
    "planned",
  ),
];
export const defaultScanPolicy: Readonly<ScanPolicy> = {
  maxImpact: "medium",
  allowIntrusive: false,
  includeExperimental: true,
  maxDurationMs: 300000,
  requestTimeoutMs: 15000,
};
const rank: Record<ScanImpact, number> = { passive: 0, light: 1, medium: 2, intrusive: 3 };
export function metadata(id: string): CheckMetadata {
  const found = checkRegistry.find((item) => item.id === id);
  if (!found) throw Error(`Missing scan registry entry: ${id}`);
  return found;
}
export function policyReason(id: string, policy: ScanPolicy): string | undefined {
  const item = metadata(id);
  if (item.status === "planned") return "Check is not implemented.";
  if (item.status === "experimental" && !policy.includeExperimental)
    return "Experimental checks are disabled by policy.";
  if (rank[item.impact] > rank[policy.maxImpact]) return "Check exceeds the policy impact limit.";
  if (item.impact === "intrusive" && !policy.allowIntrusive)
    return "Intrusive checks require explicit policy opt-in.";
  return undefined;
}
export function validatePolicy(policy: ScanPolicy) {
  if (
    !policy ||
    !Object.hasOwn(rank, policy.maxImpact) ||
    typeof policy.allowIntrusive !== "boolean" ||
    typeof policy.includeExperimental !== "boolean" ||
    !Number.isInteger(policy.maxDurationMs) ||
    policy.maxDurationMs < 1000 ||
    policy.maxDurationMs > 3600000 ||
    !Number.isInteger(policy.requestTimeoutMs) ||
    policy.requestTimeoutMs < 1000 ||
    policy.requestTimeoutMs > 30000
  )
    throw Error("Invalid scan policy limits.");
}
export type ScanPreset = "passive" | "balanced" | "comprehensive";
export function presetPolicy(preset: ScanPreset): ScanPolicy {
  return {
    ...defaultScanPolicy,
    maxImpact: preset === "passive" ? "passive" : preset === "balanced" ? "light" : "medium",
    includeExperimental: preset === "comprehensive",
  };
}
export function presetChecks(mode: ScanPlan["mode"], policy: ScanPolicy): CheckId[] {
  return checkRegistry
    .filter(
      (item) =>
        item.execution !== "automatic" &&
        !policyReason(item.id, policy) &&
        (mode === "both" || (mode === "passive") === (item.impact === "passive")),
    )
    .sort((a, b) => Number(a.impact !== "passive") - Number(b.impact !== "passive"))
    .map((item) => item.id as CheckId);
}
