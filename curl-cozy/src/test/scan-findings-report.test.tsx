import { fireEvent, render, screen, within } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import type { Finding, ScanEvidence, ScanRun } from "../lib/scan";
import { newScanPlan } from "../lib/scan";
import {
  ScanFindingsReport,
  scanRequestRaw,
  scanResponseRaw,
} from "../components/scan-findings-report";
vi.mock("../components/request-menu", () => ({
  RequestMenu: ({ children }: { children: import("react").ReactNode }) => children,
}));
const request = {
  method: "GET",
  url: "http://localhost:8088/products?category=",
  headers: { Accept: "text/html" },
  body: "",
};
const evidence = (id: string, url: string, status: number): ScanEvidence => ({
  id,
  label: id === "base" ? "Baseline 1" : "SQL single quote",
  timestamp: "2026-10-18T00:00:00Z",
  request: { ...request, url },
  response: {
    status,
    responseHeaders: { "content-type": "text/plain" },
    responseBody: status === 500 ? "internal server error" : "normal",
  },
  setCookies: [],
  duration: 12,
  size: 22,
  truncated: false,
});
const finding = (id: string): Finding => ({
  id,
  fingerprint: id,
  checkId: "sql-injection",
  title: `SQL finding ${id}`,
  severity: "medium",
  confidence: "medium",
  status: "needs_review",
  parameter: { kind: "query", name: "category", occurrence: 0 },
  evidenceIds: ["base", "probe"],
  summary: `Summary ${id}`,
  verification: { method: "quote repair", outcome: "inconclusive", reason: "Needs review" },
  excerpts: [],
  remediation: "Use parameterized SQL",
});
function run(): ScanRun {
  return {
    version: 1,
    id: "run",
    startedAt: "2026-10-18T00:00:00Z",
    status: "completed",
    message: "done",
    plan: newScanPlan(request),
    sent: 2,
    bytes: 500,
    baselineStable: true,
    baselineIds: ["base"],
    evidence: [evidence("base", request.url, 200), evidence("probe", request.url + "%27", 500)],
    findings: [finding("a"), finding("b")],
    checks: [],
  };
}
it("selects findings and exposes raw probe response, payload, baseline comparison and truncation", () => {
  const data = run();
  render(<ScanFindingsReport run={data} filter="all" focusFinding="b" />);
  expect(screen.getByRole("button", { name: "SQL finding b" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  expect(screen.getByText("Summary b")).toBeInTheDocument();
  fireEvent.mouseDown(screen.getByRole("tab", { name: "Response 2" }), {
    button: 0,
    ctrlKey: false,
  });
  expect(within(screen.getByLabelText("Finding inspector")).getByText('"\'"')).toBeInTheDocument();
  expect(screen.getByText(/500 · 12 ms/)).toBeInTheDocument();
  expect(
    Array.from(document.querySelectorAll('[data-response-changed="true"]')).some((line) =>
      line.textContent?.includes("internal server error"),
    ),
  ).toBe(true);
  fireEvent.mouseDown(screen.getByRole("tab", { name: "Request 2" }), {
    button: 0,
    ctrlKey: false,
  });
  expect(document.querySelector("[data-evidence-payload]")).toHaveTextContent("%27");
  fireEvent.mouseDown(screen.getByRole("tab", { name: "Response 2" }), {
    button: 0,
    ctrlKey: false,
  });
  expect(screen.getByRole("button", { name: /Compare baseline/ })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Toggle response search" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "SQL finding a" }));
  expect(screen.getByText("Summary a")).toBeInTheDocument();
  expect(screen.getByRole("tab", { name: "Advisory" })).toHaveAttribute("data-state", "active");
});
it("raw views contain the HTTP request line, body, status and separate cookie fields", () => {
  const e = evidence("probe", request.url + "%27", 500);
  e.request = { ...e.request, method: "POST", body: '{"email":"probe"}' };
  e.setCookies = ["a=1; HttpOnly", "b=2; Secure"];
  expect(scanRequestRaw(e)).toContain("POST /products?category=%27 HTTP/1.1\r\n");
  expect(scanRequestRaw(e)).toContain('Host: localhost:8088\r\n\r\n{"email":"probe"}');
  expect(scanResponseRaw(e)).toContain("HTTP/1.1 500 Internal Server Error");
  expect(scanResponseRaw(e)).toContain("Set-Cookie: a=1; HttpOnly\r\nSet-Cookie: b=2; Secure");
});
it("shows filtered empty results and handles missing response evidence", () => {
  const data = run();
  render(<ScanFindingsReport run={data} filter="verified" focusFinding="" />);
  expect(screen.getByText("No findings match this filter.")).toBeInTheDocument();
  const e = data.evidence[1]!;
  delete e.response;
  e.error = "Connection failed";
  expect(scanResponseRaw(e)).toBe("Connection failed");
});

it("highlights the CSP evidence header even when the response is the baseline", () => {
  const data = run();
  data.findings = [finding("csp")];
  const f = data.findings[0]!;
  delete f.parameter;
  f.evidenceIds = ["base"];
  f.excerpts = ["Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline'"];
  data.evidence[0]!.response!.responseHeaders["Content-Security-Policy"] =
    "default-src 'self'; style-src 'unsafe-inline'";
  render(<ScanFindingsReport run={data} filter="all" focusFinding="csp" />);
  fireEvent.mouseDown(screen.getByRole("tab", { name: "Response 1" }), {
    button: 0,
    ctrlKey: false,
  });
  expect(document.querySelector("[data-evidence-payload]")).toHaveTextContent(
    "Content-Security-Policy:",
  );
});
it("shows browser callback, sink and CSP evidence alongside the HTTP exchange", () => {
  const data = run();
  data.evidence[1]!.browser = [
    {
      executed: true,
      marker: "slurpBrowserMarker12345",
      url: request.url + "#payload",
      sinks: ["innerHTML"],
      cspViolations: ["Refused a secondary inline script"],
      blockedRequests: 3,
      browser: "Chrome/fixture",
      requestedScripts: ["https://app.test/lazy.js"],
    },
  ];
  render(<ScanFindingsReport run={data} filter="all" focusFinding="a" />);
  fireEvent.mouseDown(screen.getByRole("tab", { name: "Browser 2" }), {
    button: 0,
    ctrlKey: false,
  });
  expect(screen.getByText(/Payload callback executed/)).toBeInTheDocument();
  expect(screen.getByText(/innerHTML/)).toBeInTheDocument();
  expect(screen.getByText(/Refused a secondary inline script/)).toBeInTheDocument();
  expect(screen.getByText(/slurpBrowserMarker12345/)).toBeInTheDocument();
  expect(screen.getByText("https://app.test/lazy.js")).toBeInTheDocument();
});
it("shows correlated OAST callbacks beside their probe request", () => {
  const data = run();
  data.evidence[1]!.oast = [
    {
      id: "probe1",
      url: "http://oast.test/slurp-oast/probe1",
      dnsName: "probe1.oast.test",
      expiresAt: "2026-10-19T00:10:00Z",
      events: [
        {
          protocol: "http",
          timestamp: "2026-10-19T00:00:00Z",
          peer: "192.0.2.10",
          detail: "GET /slurp-oast/probe1",
        },
      ],
    },
  ];
  render(<ScanFindingsReport run={data} filter="all" focusFinding="a" />);
  fireEvent.mouseDown(screen.getByRole("tab", { name: "OAST 2" }), { button: 0, ctrlKey: false });
  expect(screen.getByText("http://oast.test/slurp-oast/probe1")).toBeInTheDocument();
  expect(screen.getByText(/GET \/slurp-oast\/probe1/)).toBeInTheDocument();
  expect(screen.getByText(/192.0.2.10/)).toBeInTheDocument();
});

it("shows the discovered endpoint instead of labeling every finding with the crawl seed", () => {
  const r = run();
  r.findings = [
    {
      ...finding("discovered"),
      endpoint: "http://localhost:8088/discovered",
      method: "GET",
      baselineId: "base",
    },
  ];
  render(<ScanFindingsReport run={r} filter="all" focusFinding="" />);
  expect(
    within(screen.getByRole("table", { name: "Scan findings" })).getByText("/discovered"),
  ).toBeInTheDocument();
});
