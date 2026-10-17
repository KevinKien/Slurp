# Endpoint scan engine

Right-click a request in HTTP History, Replay or Intercept and select **Scan**. The Scan dashboard shows live tasks and saved findings. The selected request opens in a configuration dialog; task and finding details open separately so the dashboard stays focused on monitoring. Choose passive or active checks, then review verification details and request/response evidence. Captured History responses default to passive inspection. Requests without an observed response default to active mode with sending disabled until explicitly selected. The sidebar Scan entry also provides saved run history.

## Execution

`src/lib/scan` is independent of React and receives a sender, workspace guard and optional persistence adapter. `ScanProvider` is mounted inside `AuthProfilesProvider` at the app root. UI components call `useScan()` to start, pause, resume or stop a run and retry saving. Navigation preserves execution. Changing workspace stops further scheduling and prevents late cookie commits. An in-flight request still completes and is captured under its original workspace.

Execution is sequential in version 1. Global request starts obey `rate` (1–20/second) and `delay` (0–60,000 ms). Plans allow up to 100 requests, 10 explicitly selected query/JSON scalar parameters, 2–3 baseline samples and 500 KB configuration. Only the selected endpoint origin, pathname and method can be probed. There is no crawling, redirect following, shell execution, external callback infrastructure or automatic retry of HTTP requests.

Active scans use the existing Replay sender unchanged: public HTTPS only, current timeouts, response-size limits and no redirects. Profile credentials and variables resolve once before the run. Response cookies can update the selected profile jar; subsequent requests in this version continue using the original credential snapshot for consistent comparisons. Replay scripts are not executed.

## Passive inspection

```ts
import { newScanPlan } from '@/lib/scan';

const plan = newScanPlan(capturedRequest);
plan.observed = {
  response: {
    status: captured.status,
    responseHeaders: captured.responseHeaders,
    responseBody: captured.responseBody,
  },
  // Supply original, separate Set-Cookie fields when available.
  // Flattened traffic headers cannot reliably preserve cookie boundaries.
  setCookies: capturedSetCookies,
};
scan.start(plan); // useScan(); does not send HTTP requests or apply another profile
```

Passive inspection requires an existing response and rejects active checks. Missing cookie flags are factual configuration observations, with cookie values redacted in finding excerpts. They do not establish account compromise. Cookie expiration fields are never split on commas; cookie inspection is inconclusive if only collapsed Set-Cookie is available. Explicit cookie deletion (`Max-Age <= 0`) is ignored.

## Active scan

```ts
import { newScanPlan } from '@/lib/scan';

const plan = newScanPlan(request);
plan.mode = 'active';
plan.allowSending = true; // caller explicitly chooses to send/repeat this endpoint
plan.checks = ['reflection', 'input-errors', 'cors'];
plan.parameters = [
  { kind: 'query', name: 'search', occurrence: 0 },
  // Or: { kind: 'json', pointer: '/account/name' }
];
plan.maxRequests = 20;
plan.diffOptions.ignoredPaths = ['requestId', 'timestamp'];
scan.start(plan, profileId);
```

Repeated requests can change application state, including when an endpoint uses GET. The Scan UI shows the selected endpoint, checks and request budget, and requires an explicit sending checkbox before setting `allowSending`. No request is sent merely by importing this module or mounting the provider.

Query mutations preserve unselected raw query segments and target an explicit zero-based duplicate occurrence. JSON mutations use RFC 6901 pointers and own-property checks, including escaped keys and array elements. JSON object formatting is reserialized, so body signatures may need adjustment outside the scanner. Form, multipart and arbitrary header-parameter mutations are not implemented yet; CORS checks specifically vary Origin.

## Built-in checks and interpretation

| Check ID | Behavior | Interpretation |
| --- | --- | --- |
| `cookie-flags` | Observe separate Set-Cookie fields for missing Secure/HttpOnly; skip explicit deletion | Verified configuration fact when evidence is complete, low severity; cookie purpose still matters |
| `security-headers` | Inspect successful HTML responses for `X-Content-Type-Options: nosniff` | Informational configuration observation; API JSON responses are excluded |
| `error-disclosure` | Match selected stack-trace/database error signatures | Suspected; documentation or example text may match |
| `reflection` | Send two distinct alphanumeric markers; inspect baseline and cross-marker controls | Verify reflection only, never label it XSS |
| `input-errors` | Require stable successful baselines, change input to quote characters, repeat an error and send original-value control | Needs review; reproducible error behavior does not prove injection |
| `cors` | Send two unrelated Origin headers and inspect exact credentialed origin reflection | Needs browser verification; no automatic claim of data theft |

Baseline stability compares successful transport responses by status and normalized body. The configured ignored JSON paths handle known dynamic fields; the engine does not guess and hide arbitrary changes. A failed baseline prevents active checks. Dynamic baselines make input-error testing inconclusive. Error responses, stop/budget limits and skipped checks remain visible and never count as a clean scan.

Findings separate severity, confidence and status. `verified` means that the stated finding was verified using the specified method, not that a broader exploit was demonstrated. Each finding references evidence IDs and records verification outcome/reason, bounded excerpts and remediation. CORS remains `needs_review`; error signatures remain `suspected`. Evidence truncation downgrades automatic configuration/reflection verification. `false_positive` is reserved in the model for future human triage; this engine does not automatically dismiss a finding or implement a triage UI.

## Evidence and lifecycle

The engine stores actual request snapshots, response previews (32,000 characters), bounded headers and separate cookies, full returned size, duration and a SHA-256 of returned UTF-8 response text where browser crypto is available. Hashes do not represent original binary response bytes. A scan has an 8 MB evidence budget; space is reserved before each send. Sensitive request/response data is retained in local evidence even though cookie values are redacted in finding excerpts.

Execution must remain in an open browser. Closing/reloading interrupts it; there is no automatic resume or backend execution daemon. Only finished runs are persisted. Evidence from an unfinished run is held in browser memory and can be lost on reload. Temporary sessions keep results in memory; the root adapter retains three recent runs per workspace. Saved run history has explicit deletion and no automatic expiration.

Saving is separate from HTTP execution. A failed save exposes `persistenceError` / provider `error`. `retrySave()` writes the same immutable run and does not resend requests. The provider blocks another scan while evidence is pending. Evidence getters/callbacks return snapshots so consumers cannot mutate the engine's internal record.

## Local backend API

- `GET /api/workspaces/:id/scan-runs?offset=0`: 50 summaries per page.
- `GET /api/workspaces/:id/scan-runs/:run`: full saved run.
- `PUT /api/workspaces/:id/scan-runs/:run`: save an immutable finished version-1 run, up to 12 MB. Identical retries are accepted; changed evidence is rejected.
- `DELETE /api/workspaces/:id/scan-runs/:run`: delete a run in this workspace.

Workspace deletion also deletes scan history. The API validates evidence references and rejects a verified finding without confirmed verification and high confidence. These are local storage APIs, not an independent verifier: supplied evidence is not replayed by the backend.

## Adding checks

Add a `ScanCheck` to `scanChecks` in `checks.ts` and extend the `CheckId` union and backend allowlist. Declare whether it sends probes and whether it runs per selected parameter. Use the provided `probe()` so endpoint guards, rate limits, request counts, pause/stop and evidence capture apply. A check must return an inconclusive outcome when its verification preconditions fail. Add detector and verifier fixtures, including negative controls, before exposing it in the UI.

Dashboard findings use `GET /api/workspaces/:id/scan-findings?offset=0&q=&status=&severity=` (100 findings per page), with workspace-scoped search and filters. Full request/response evidence loads only when a saved task is opened.
