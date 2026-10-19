# Endpoint scan engine

Right-click a request in HTTP History, Replay or Intercept and select **Scan passive** or **Scan active**, then choose a saved scan profile. Create or edit profiles to choose checks. Passive audits an existing response or automatically fetches one response at scan start; active requires sending consent. Dashboard lists tasks, findings and evidence. The engine also accepts Both mode for programmatic plans with captured responses.

## Automatic capture audit

New completed proxy captures are audited in the Rust backend after History storage. This runs while Slurp is running, even when the Dashboard is closed; existing History is not backfilled. Target Scope applies. Pause/resume automatic auditing from Dashboard. The switch is global, enabled by default and resets on restart. Separate bounded queues skip excess work under load; skipped/save-error counters are visible.

API candidates are identified by JSON/GraphQL content types, API paths or recognized credential headers. The existing NoAuthen/CORS audit sends up to two probes are sent sequentially, at most two request starts per second, using the shared HTTP(S) Replay sender (including localhost/LAN, DNS pinning, timeouts, response limits and no redirects). The original method and body are retained, so requests can change application state. One probe removes common authorization, API-key and cookie headers and token query parameters. HTTP 200 creates a **NoAuthen** finding requiring review; public endpoints and login/error pages can return 200 intentionally. Body credentials and custom authentication are not removed. The other probe sets `Origin: https://evil.com` and reports wildcard or matching Access-Control-Allow-Origin. Browser exploitability and credential/preflight rules still need verification.

Successful JavaScript responses (`.js`, `.mjs`, `.cjs` or JavaScript MIME) are analyzed passively for endpoint literals and suspected usernames/passwords, API keys, tokens and private keys. Findings show candidate URLs, method hints when available, source History ID, line and byte column. Credential excerpts are masked; original captured source and local evidence can still contain secrets. Search Dashboard findings by endpoint or credential type. Values are not validated against external services.

Analysis is bounded to 2 MB of UTF-8 identity-encoded source, 20,000 literals, 8 KB per literal and 400 findings per source. Limits make empty categories inconclusive. Unsupported compressed/binary captures are skipped. This is literal analysis, not a full JavaScript AST: comments, concatenated/obfuscated code and runtime-generated values may be missed. Relative URLs are candidates resolved against the script URL; the application base URL may differ. No JavaScript execution, crawling, source-map discovery or discovered-endpoint fetching is performed.

The independent Rust implementation takes design inspiration from [PortSwigger js-link-finder](https://github.com/PortSwigger/js-link-finder) and [PortSwigger js-miner](https://github.com/PortSwigger/js-miner); it does not embed or provide all features of those Burp extensions.

Completed automatic runs use the original workspace. Temporary workspace results live in backend memory and disappear when Slurp stops. Only new proxy captures trigger analysis; probes do not re-enter History or recursively scan themselves. Runtime status/control: authenticated `GET /api/scan/automatic` and `PUT /api/scan/automatic` with `{ "enabled": false }`.

## Manual scan modes and supported checks

The request context menu offers separate **Scan passive** and **Scan active** actions. Passive inspects the captured request/response, fetching the original request once at scan start only if no response exists. Active sends profile-selected probes after sending opt-in. The engine retains Both mode for programmatic or legacy plans; it combines observed passive evidence and fresh active baselines and requires a captured response. Select parameters explicitly for parameter-based probes before starting. There is no total request-count limit; duration, rate and evidence limits remain.

Additional passive audit observations include missing CSP, framing restrictions and HTTPS HSTS on HTML, missing Content-Type, HTTP resource references in HTTPS HTML, URL credentials, cleartext credential submission, private-key PEM markers, directory-index headings and OpenAPI signatures. These are contextual observations, not proof of compromise. Cookie and existing error/header checks remain separate.

Additional active checks:

| Check | Controls and limits |
| --- | --- |
| SQL error differential | Stable baselines, benign marker, repeated quote probe, original-request control; reports suspected injection only for new repeatable database-error signatures |
| Template arithmetic | Two distinct marked arithmetic expressions and invalid syntax controls; supports `{{a*b}}` syntax only; reflected expressions are not findings |
| Path traversal | Repeated Unix/Windows traversal values, system-file signature and missing-file control; mutates selected query/JSON parameters only |
| Open redirect | Two unique `.invalid` destinations must control redirect Location; redirects are never followed |

This is not parity with Burp Scanner's issue catalog. Stored XSS, full browser taint tracking, request smuggling/desync, external OAST providers and persistent delayed-callback workflows, second-order injection, GraphQL authorization/complexity attacks, extended JWT key attacks, cache poisoning and denial-of-service checks are not implemented. Reflected input alone is not reported as XSS. Unsupported checks are not offered as working detectors.

## HTTP active checks (phase 3)

| Check ID | Implemented behavior | Verification limits |
| --- | --- | --- |
| `sql-boolean` | Numeric/quoted AND predicates, true/false/false/true ordering and original-value control | Requires stable successful baselines, repeatable matching true responses and distinct matching false responses; application logic may mimic SQL |
| `sql-time` | MySQL SLEEP(0)/SLEEP(2)/SLEEP(2)/SLEEP(0), then original control | Intrusive opt-in; two bounded delays, low-jitter controls and stable content; timeout is inconclusive, never evidence of SQLi |
| `header-injection` | Two unique CRLF parameter markers and plain-text controls | Requires actual response-header values; body reflection does not qualify |
| `auth-access` | Remove common header/query credentials, invalid Bearer token, repeated anonymous and restored original | Anonymous status/body must match stable successful baseline; public endpoints and body/custom auth still require review |
| `referer-access` | Same-origin Referer, untrusted-origin control, repeat and original | Requires denied baseline and controlled denied-to-success behavior; not proof of access to sensitive data |
| `client-ip` | X-Real-IP and X-Client-IP loopback versus documentation-address controls | Requires denied baseline; Forwarded/X-Forwarded-* remain filtered by the shared sender and are not tested |
| `url-override` | X-Original-URL/X-Rewrite-URL current path versus repeated unique missing path | Reports routing influence only, never claims authorization bypass |
| `http-methods` | OPTIONS Allow and two credential-free TRACE marker requests | PUT advertisement is informational; no PUT write is attempted; TRACE needs a request-line/diagnostic-header echo |

The existing SQL error differential remains separate. Traversal adds percent-literal and nested-percent payload values; the parameter encoder applies normal wire encoding, so these exercise additional decode layers. Each successful finding still needs repeated file signatures absent from controls. Redirect checks try absolute and protocol-relative `.invalid` destinations and inspect Location without following it. CORS also reports wildcard policies as reviewable low-severity observations; wildcard with credentials does not imply browser-readable authenticated data.

All new input/header candidates remain needs_review. No timeouts, HTTP 200 alone, arbitrary header-dependent differences or reflected text alone are treated as confirmed vulnerabilities. Cross-account authorization/BOLA requires account/flow context and is not inferred by these generic checks. Generic header probes use the selected method/path; only the method-policy module may switch to OPTIONS/TRACE on the same origin/path. CONNECT remains unsupported. Anonymous, Referer/client-IP and method diagnostic responses do not update the selected profile cookie jar; baseline requests retain the normal sender behavior.

Scans continue through all selected checks without a total request-count limit. Duration or evidence limits can still stop a run; review skipped/inconclusive results. Time-based probing is currently MySQL-specific, and only the listed traversal, redirect and header forms are implemented. No raw HTTP, OAST, stored or browser execution engine is added by this phase.

## Registry, policy and coverage

`src/lib/scan/registry.ts` is the check metadata catalog. Each executable check has a unique ID, impact (`passive`, `light`, `medium`, `intrusive`), maturity (`implemented`, `experimental`, `planned`), execution location, prerequisites and verification description. Planned rows are descriptive modules, never executable checkboxes. Coverage counts modules rather than claiming parity with every Burp issue variant. Backend automatic-only checks are identified separately.

Manual configuration uses reusable browser-local scan profiles. Each profile selects checks for one mode; policy is derived from those selections. Selecting an explicitly labeled intrusive check enables the required intrusive policy, and experimental checks remain labeled. Built-in active defaults exclude intrusive probes. The engine rechecks policy for all plans, records blocked checks as skipped, and sends no baselines when every check is blocked. Sending consent remains necessary. Policy snapshots are saved with runs; old plans without policy use default limits. Internal preset helpers remain available for programmatic plans.

Policies bound wall-clock scan duration (1–3,600 seconds, including pauses) and per-request timeout (1–30 seconds). Effective request timeout is the minimum of the app sender setting, policy timeout and remaining duration. No new request starts with less than one second remaining (the sender minimum). An in-flight request can finish after the scheduling deadline; scans do not claim server-side cancellation. Existing sequential rate/evidence budgets and pause/stop remain enforced. Passive check implementations receive a sender that rejects network calls, even in Both mode. Automatic capture audits retain their separate backend control and limits; manual profiles do not configure them.

Dashboard's Scan coverage table lists metadata, prerequisites and verification. When a run is selected it summarizes completed/skipped/inconclusive result rows and separates JavaScript endpoint discoveries from other findings. Result rows can include multiple parameters for a single module.

## Expanded passive modules

- `cookie-audit`: parent-domain scope, duplicate name/domain/path identity, missing explicit SameSite, SameSite=None without Secure, invalid __Host-/__Secure- attributes and password-like cookie names. Separate Set-Cookie fields are required; collapsed fields are never split on commas. Max-Age deletion and expired Expires cookies are ignored. At most 100 cookie fields and 100 findings are processed/retained per module.
- `disclosure-audit`: database URI signatures, password-like response fields, literal submitted-password reflection, email/private IPv4 patterns, contextual SSN patterns, Luhn-valid card candidates, server-source markers, Java serialization prefixes, private asymmetric JWK parameters, GraphQL syntax and technology headers. Sensitive excerpts are masked. No credential or advisory lookup is performed; public examples, synthetic identifiers and test cards can match.
- `policy-audit`: script CSP fallback and selected unsafe/broad tokens, missing object/base restrictions, missing HTML charset, selected MIME inconsistencies and invalid/zero HSTS max-age. Duplicate CSP directives honor the first occurrence. Combined policies are inconclusive instead of inferring their intersection. Nonces/hashes, meta policies and full browser enforcement require review.

Body inspection is bounded to 256,000 characters per new module; evidence previews remain 32,000 characters. Truncation or analysis limits produce inconclusive results. Findings remain needs_review and do not assert exploitability. Full local evidence and History can contain sensitive data despite masked excerpts. Extended dependency attribution, TLS certificate inspection and full DOM analysis remain planned; technology headers do not establish vulnerable versions.

## Manual execution

`src/lib/scan` is independent of React and receives a sender, workspace guard and optional persistence adapter. `ScanProvider` is mounted inside `AuthProfilesProvider` at the app root. UI components call `useScan()` to start, pause, resume or stop a run and retry saving. Navigation preserves execution. Changing workspace stops further scheduling and prevents late cookie commits. An in-flight request still completes and is captured under its original workspace.

Execution is sequential in version 1. Global request starts obey `rate` (1–20/second) and `delay` (0–60,000 ms). Plans allow 10 explicitly selected query/JSON scalar parameters, 2–3 baseline samples and 500 KB configuration. Only the selected endpoint origin and pathname can be probed. The original method is retained except for explicit OPTIONS/TRACE method-policy diagnostics. There is no crawling, redirect following, local shell execution or automatic retry of HTTP requests. Opt-in OAST uses the separate callback collector described below. Intrusive command probes can invoke a bounded printf command on the target when input is vulnerable.

Active scans use the existing Replay sender unchanged: HTTP(S), including localhost and LAN, current timeouts, response-size limits and no redirects. Profile credentials and variables resolve once before the run. Response cookies can update the selected profile jar; subsequent requests in this version continue using the original credential snapshot for consistent comparisons. Replay scripts are not executed.

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

Passive inspection rejects active checks; it uses an existing response or fetches one original response at scan start. Missing cookie flags are factual configuration observations, with cookie values redacted in finding excerpts. They do not establish account compromise. Cookie expiration fields are never split on commas; cookie inspection is inconclusive if only collapsed Set-Cookie is available. Explicit cookie deletion (`Max-Age <= 0`) is ignored.

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
plan.diffOptions.ignoredPaths = ['requestId', 'timestamp'];
scan.start(plan, profileId);
```

Repeated requests can change application state, including when an endpoint uses GET. The Scan UI shows the selected endpoint, checks and execution settings, and requires an explicit sending checkbox before setting `allowSending`. No request is sent merely by importing this module or mounting the provider.

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

Manual scan execution must remain in an open browser. Closing/reloading interrupts it; manual runs have no automatic resume. Only finished runs are persisted. Evidence from an unfinished run is held in browser memory and can be lost on reload. Temporary sessions keep results in memory; the root adapter retains three recent runs per workspace. Saved run history has explicit deletion and no automatic expiration.

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

## Scan profiles

Right-click an HTTP request in History, Replay or Intercept and choose **Scan passive** or **Scan active**. Passive scanning uses a captured response when available; otherwise it automatically sends the original request once when started. Active scanning uses the shared HTTP sender and requires sending consent.

Select a **Scan profile** in the scan dialog. Use **Create profile** or **Edit profile** to name the profile and select its checks, then **Save profile**. Only checks for the selected scan mode appear. Profiles persist in this browser and are shared across workspaces; they contain check selections, not credentials or captured traffic. Authentication profiles remain separate.

Selecting an intrusive check explicitly enables its required policy; experimental checks are labeled. The default active profile excludes intrusive checks. Choose request parameters for parameter-based checks, and expand **Advanced request settings** only when adjusting budgets or comparison options. Duration/evidence limits, sender restrictions and sending consent still apply. Planned checks are not executable.

## Specialized injection checks (phase 4)

All new checks are experimental manual active modules. Add them through **Edit profile** or **Create profile**. They require stable successful, untruncated baselines and inspect at most 256,000 response characters. Oversized, failed or truncated evidence remains inconclusive. Findings require contextual review and are not labeled confirmed exploitation.

| Check | Probe and verification | Impact |
| --- | --- | --- |
| OS command injection | Two unique POSIX printf outputs constructed from split strings, plain controls and original restoration; separator and substitution contexts | Intrusive |
| Server-side code injection | Python-like print, PHP-like echo and JavaScript-like String arithmetic; two products, quoted non-evaluating controls and original restoration | Intrusive |
| Expression language | Dollar/hash arithmetic with two products, quoted controls and original restoration | Medium |
| LDAP / XPath / XML injection | Repeated technology-specific parser errors absent from benign and original controls; generic errors or denial statuses do not establish injection | Medium |
| XML internal entities | Two bounded, nonrecursive split entities versus escaped-entity controls | Medium |
| XXE | Repeated /etc/passwd or Windows win.ini signatures absent from escaped-entity, missing-file and original controls | Intrusive |

The parameter variants mutate explicitly selected query/JSON scalar values. XML body variants instead require an XML media type (including application/soap+xml), an XML-looking body and no parameter selection; they replace the whole body with a small diagnostic XML document and retain the original URL, method and headers. Existing SOAP schemas and nested encodings may reject these documents. Form, multipart, XML node selection and arbitrary code contexts are not covered.

Internal entity processing alone is not reported as XXE. LDAP/XPath/XML errors establish only an input-related parser error, not an authentication bypass. Arithmetic evaluation can be an intentional calculator/template feature; the engine does not prove an arbitrary runtime. These in-band command probes are limited to POSIX printf; Windows command execution, blind/timing execution and recursive entity expansion are not implemented. External HTTP/DNS callbacks are handled by the separate OAST checks described below. XXE excerpts omit file contents; local request/response evidence can still contain them. No file write, network callback or local command execution is performed by these analyzers.

All checks share the existing rate, timeout and evidence limits; there is no total request-count cap. Plans allow 1–40 unique checks, but selecting many modules or parameters can exhaust a run before all checks execute. Review skipped and inconclusive rows and split large profiles into focused scans. Existing browser profiles are preserved; new checks can be added by editing a profile.

## SQL quote-repair comparison

The existing `sql-injection` check now also handles database errors hidden behind generic server-error pages. When error signatures do not match, it sends single/doubled/doubled/single quote suffixes to the selected scalar and restores the original request. A finding requires two single-quote server failures, two doubled-quote successful responses matching stable successful baselines, and an original control restoring that baseline. Status and normalized body comparisons honor the configured diff options. The selected named HTML input value is masked for comparison so reflected filter values do not hide the signal; all other response content remains significant. Uniform errors, denied responses or changed original controls do not satisfy this rule.

The result remains a possible SQL injection requiring review: syntax-sensitive application validation can mimic quote repair. The check ID is unchanged, so existing profiles containing `sql-injection` use the new comparison. Query and JSON scalar inputs are supported; it does not automatically cover second-order queries or ORDER BY extraction.

Automatic JavaScript reports suppress already-reported endpoint/method pairs within a workspace, including legacy endpoint reports. New credential fingerprints hash the unmasked value to distinguish rotated values without exposing them in fingerprints. Duplicate-only captures create no new report; captures with new findings save only those findings. Existing reports remain immutable, and another workspace has independent results. Deduplication follows retained reports, so deleting reports permits rediscovery.


### Numeric boolean fallback and evidence viewer

Both `sql-injection` and `sql-boolean` can use repeated numeric OR predicates (`0 OR 7=7` / `0 OR 7=8`, an independent 9-based pair, and a repeated pair). Successful true responses must match one another, false responses must match one another, both groups must differ, and the original control must restore the stable successful baseline. The selected HTML input value is masked; arbitrary response text is not stripped. These observations still require review.

Each finding has its own Request/Response tabs. Yellow marks injected values and changed request lines; red marks finding excerpts such as a CSP header; green marks response lines changed from the baseline. Large responses use a bounded changed-region highlight; Compare baseline shows deletions. The separate all-evidence section has been removed. Original saved evidence remains available to the scanner.

### CSP framing and styles

The passive request/response audit checks whether enforced CSP permits unrestricted framing and arbitrary inline styles. It honors `style-src-elem` / `style-src-attr`, then `style-src`, then `default-src`; duplicate directives use their first occurrence, and multiple enforced policies restrict one another. Nonce/hash source expressions suppress an unsafe-inline style finding. `frame-ancestors` has no default-src fallback; valid X-Frame-Options is considered when frame-ancestors is absent. Report-Only headers do not enforce restrictions. Findings are informational policy weaknesses, not demonstrated clickjacking or XSS exploits. Response evidence includes the CSP header for highlighting.


### Concurrent endpoint scans

Configure and start another endpoint while existing scans run. Each task owns its engine, copied request, profile session, evidence, and save status. Dashboard Pause/Resume/Stop controls act on that task only. A failed evidence save can be retried per task without blocking new scans or sending probes again. Rate, duration, timeout and evidence limits apply per task. Leaving the Dashboard keeps tasks running; changing workspace stops outgoing scans and retains their evidence in the original workspace. The finding evidence tabs wrap onto multiple lines to fit the panel width.


### Passive scan from Replay

After a Replay tab receives an HTTP response, choose **Scan passive** from that tab or its request/response panel. The scanner receives the completed send's actual request and response snapshot, including resolved variables and credentials. Later editor changes are not paired with an older response; **Scan active** uses the current resolved editor request instead. If no Replay response exists, starting the passive scan automatically sends the resolved request once in the background and records the response as evidence. Preparing the scan sends nothing. Fetch failures do not retry or produce findings. Existing responses are not fetched again.


### Automatic API audit deduplication

Automatic NoAuthen/CORS audits are deduplicated per workspace using the HTTP method, URL, request body and headers after recognized credential headers and query parameters have been removed. Noncredential headers, query values and body bytes remain significant. Changing a bearer token or cookie alone does not schedule another audit. Queued and running duplicates are suppressed, and completed results remain recognized after restarting Slurp. Older automatic reports are also recognized. Incomplete or failed checks may be retried by later captures without overwriting previous evidence. Deleting all matching reports permits a new audit. Existing duplicate reports are retained; manual scans remain independent.


## Browser XSS validation (phase 5, initial scope)

Two experimental manual active checks are available in **Create profile / Edit profile**:

- **Reflected and DOM XSS (browser validation)**: mutates selected query/JSON scalar parameters, then renders each HTML response in an isolated headless Chromium profile. Supported payload contexts include HTML tags, quoted attributes, script termination and quoted JavaScript strings.
- **DOM XSS (script audit and browser validation)**: audits inline and captured external JavaScript first, identifies URL source/sink candidates, observes a benign marker and selects HTML, JavaScript-string/expression or executable-URL payloads. Browser-only query/fragment changes use the original response snapshots; the server response is not modified.

New browser installations include a **Browser XSS** scan profile. Existing saved profiles are preserved; add the checks by editing or creating a profile. The built-in **Active standard** profile excludes browser checks so installing a browser is optional for other scans.

Install Chrome or Chromium on the machine running Slurp. Common macOS, Linux and Windows executable locations are detected, including Windows Edge. For another location, set the executable path before starting Slurp:

```sh
SLURP_BROWSER_PATH="/path/to/chrome" ./target/debug/slurp
```

The Rust backend launches the installed browser directly; Node.js, Playwright and browser downloads are not required. A missing browser, startup failure, busy worker, unsupported response or timeout produces an **inconclusive** result, never a clean security result or a finding. Chromium's OS sandbox stays enabled. At most two browser processes run simultaneously, with eight total active/queued jobs and a 30-second queue deadline. Each uses a fresh temporary profile and a 12-second startup/render deadline. Each successfully loaded snapshot is observed for 1.2 seconds.

All actual scan HTTP requests still use the shared Replay sender with its DNS pinning, timeouts, rate/evidence limits and no redirect following. The browser receives only a successful `text/html` response snapshot of at most 256 KB, served through DevTools request interception at the original URL. Original CSP headers and HTML meta policies remain in effect. Transport compression/length fields, response cookies and Refresh are omitted; the decoded document is served as UTF-8. A deny proxy and resolver rules block direct network access, and interception rejects uncaptured secondary requests and frames. The DOM check can fulfill captured script resources from its explicit snapshot set. The browser does not reuse the user's cookies, storage, extensions or normal profile.

A finding requires execution of two independently marked callback payloads, followed by a non-executable marker control and original-value control that do not execute. The callback is registered through DevTools; the scan does not evaluate the payload itself. HTML reflection alone is insufficient. Marker-bearing `innerHTML`, `outerHTML`, `srcdoc`, `insertAdjacentHTML`, `document.write` and `document.writeln` calls are recorded as DOM sink observations. These wrappers do not constitute full JavaScript taint tracking.

Findings retain Request/Response evidence and add **Browser N** tabs with callback outcome, marker, actual browser URL (including fragments), sink names, blocked-request count and browser security messages. `verified` means the supplied payload executed in this isolated response snapshot, not that every live application state was exercised. Findings explicitly retain that verification scope.

The ordinary browser checks do not exercise event interactions. The separate interaction check below adds bounded input/click exploration. Dependencies outside the bounded load window, prior browser state, full source/sink taint analysis, stored-XSS write/readback/cleanup workflows, second-order injection and arbitrary event handlers remain outside this scope. Negative snapshot results are inconclusive for those paths. Existing automatic capture audits remain unchanged; browser checks run only when selected for a manual active scan.


### DOM script audit and context-selected probes

Select **DOM XSS (script audit and browser validation)** in an active scan profile. It does not require manually selecting parameters. The check parses HTML with parse5 and JavaScript with Acorn without evaluating scripts during the static audit. Executable inline scripts, event-handler code and script `src` references are inspected. Script URLs honor the document's base URL. Literal relative/absolute ES module imports and exports are followed. Computed imports, import maps and runtime-created dependencies can also be discovered when the original snapshot requests them during bounded browser execution.

External scripts use credential-preserving GET requests only on the selected origin, including its scheme and port. Another origin is fetched only when its hostname is explicitly included in enabled Target Scope; its request carries no captured headers or credentials. Script requests have no body, never follow redirects and do not update the scan authentication cookie jar. They pass through the shared sender's DNS pinning, per-request timeout, scan rate, duration and evidence limits, and count toward the task's sent count. Each URL is fetched at most once per task. Chrome never fetches scripts directly: it receives only captured response snapshots. CSP, SRI, MIME and CORS behavior remain browser-enforced.

The bounded AST analysis follows selected URL fields, URLSearchParams aliases and literal `get("name")` calls, decoding/base64 operations, variable assignments and simple local function-argument transfers. It identifies HTML sinks (including innerHTML, outerHTML, srcdoc, document.write, insertAdjacentHTML and common HTML method calls), code-evaluation sinks and navigation/URL sinks. Cross-script bindings are heuristic and do not implement lexical-scope-aware or complete interprocedural taint analysis. Comments and literal examples are not treated as executable source/sink paths. A static candidate alone never becomes a vulnerability finding.

A benign marker is rendered before attack payloads. Marker-bearing HTML sink values and stacks guide attribute-quote/element payload ordering. Code and URL candidates instead select JavaScript expressions/string breakouts or javascript: URLs. Supported query names can be discovered from scripts even when absent from the original URL. Query/fragment mutations occur only in the browser URL; the original HTML and captured script content stay unchanged. Two independently marked payload executions and benign/original controls remain mandatory for a verified finding. Calls are attributed only to the main document in its original origin; sandboxed iframe callbacks are not promoted to page XSS.

Open **DOM script audit** inside a task to see scripts, parse outcomes, static sources/sinks, source lines, candidate excerpts, payload families and analysis notes, including scans with no findings. Browser evidence includes marker-bearing sink values and stack traces. Findings link the original HTML and captured script request/response evidence. Static sink candidates are labeled separately from observed runtime sinks.

Limits: 100 inline script/handler units, 16 attempted external script URLs, 256 KB per script, 1 MB of external script bodies, 20,000 HTML nodes, 50,000 AST nodes per unit, five bounded binding passes, 40 retained candidates and 500 browser observations per HTTP evidence item. Existing scan duration and 8 MB evidence limits can stop work earlier. Unsupported charsets, parse failures, scope exclusions and unresolved dependencies are recorded in the audit notes. Unsupported/referrer/storage-driven sources and unexecuted candidates remain inconclusive; this check does not establish full DOM-XSS coverage.

### Runtime script dependency discovery

After the first static audit, DOM XSS renders the original URL with the original HTML and captured scripts, even when no static source/sink candidate was found. Blocked main-frame GET requests classified by Chromium as scripts become dependency hints. Fetch/XHR, images, frames, WebSockets, navigation, non-HTTP URLs and credential-bearing URLs do not become script downloads. The browser never contacts these destinations itself.

The shared sender captures eligible dependencies, then the engine audits the expanded script set before choosing payloads. Discovery repeats for up to three rounds to cover loaders and computed module imports. A single 16-URL attempt quota and 1 MB script-body budget span all rounds and static imports. Requests and failures are cached; excluded URLs are not retried. Same-origin credentials, cross-origin Target Scope restrictions, no redirects, rate, duration and evidence limits are unchanged.

Only original-URL discovery observations may initiate script capture. Dependencies seen while rendering a payload are recorded in Browser evidence but never fetched. The task's **DOM script audit** lists runtime dependencies, captured scripts and exclusions, including scans without findings. Re-audits update the same audit record. Discovery itself is not a finding; the two independent execution callbacks and negative/original controls are still required.

This covers dependencies requested during the 1.2-second snapshot window, not an application crawl or full browser taint analysis. In the ordinary DOM check, lazy scripts requiring clicks remain untested; the separate interaction check can discover some event-driven dependencies. Long timers, uncaptured API responses, previous storage/session state and deeper dependency chains remain untested. Scope exclusions, parse failures and limit notes must be considered when interpreting an empty finding list.

### Browser interaction checks

Select **DOM XSS (input and event interaction)** in an active scan profile. This is separate from the ordinary DOM check. The audit recognizes direct `getElementById()` / `querySelector()` input-value sources and simple aliases in addition to URL sources. A candidate input receives a benign marker first, then context-selected payloads. Query/fragment sources continue to change only the browser URL. Original HTML and script snapshots are preserved.

Each fresh isolated render can fill one identified text/search/email/url/tel input or textarea, dispatch input/change, and explore up to 12 interactive elements with synthetic mouseover, focus and click/input/change events. Form submission is prevented. The backend records the actual interaction trace; missing inputs do not become findings. Two independently marked executions and non-executing benign/original controls use the same event exploration. The original control does not overwrite the input's captured default value. CSP remains browser-enforced, and external network, API responses, new navigation and uncaptured frames remain blocked.

Interaction discovery can reveal additional runtime scripts within the existing three-round quota. This does not model arbitrary state machines, trusted physical input, complex component-specific gestures, storage/session initialization or multi-page login flows. Click-only paths can be missed outside the 12-element limit, and combined event exploration does not attribute a finding to one specific click. Static input-source hints remain heuristic; only main-document callbacks establish execution.

## OAST: blind SSRF and external XML entity interactions

Select **Blind SSRF (OAST HTTP/DNS)** or **Blind XXE (OAST HTTP/DNS)** in an active scan profile. OAST is excluded from the built-in Active standard profile. The scan dialog shows collector status and links to setup. Existing profiles are preserved; edit or create a profile to enable the checks.

Slurp includes a self-hosted callback collector on a separate listener. No external service account is required. Collection is disabled until `SLURP_OAST_PUBLIC_URL` is set before starting Slurp. The advertised URL must be reachable **from the scanned server**. The API/UI port is not a callback endpoint, and exposing the callback listener does not expose the API. The callback listener issues no probes and reveals no event logs; issuing/polling probes requires the normal authenticated Slurp API.

For an application running directly on the same machine:

```sh
SLURP_OAST_PUBLIC_URL=http://127.0.0.1:8899 \
SLURP_OAST_LISTEN=127.0.0.1:8899 \
./target/debug/slurp --no-open
```

For another machine/container, advertise a reachable LAN/public hostname or IP and bind the collector to the appropriate interface, for example `SLURP_OAST_PUBLIC_URL=http://192.168.1.10:8899` with `SLURP_OAST_LISTEN=0.0.0.0:8899`. Container loopback is not host loopback. Open/forward only the callback port as needed. HTTPS public URLs require a TLS reverse proxy in front of the HTTP listener; preserve `/slurp-oast/<id>` when proxying. A public URL path prefix is supported when the reverse proxy strips that prefix.

Optional DNS collection requires a domain you control and authoritative delegation (or equivalent test DNS routing) to Slurp's UDP listener:

| Variable | Purpose |
| --- | --- |
| `SLURP_OAST_PUBLIC_URL` | HTTP(S) base URL advertised in probes; required |
| `SLURP_OAST_LISTEN` | HTTP bind address; default `127.0.0.1:8899` |
| `SLURP_OAST_DNS_DOMAIN` | Delegated callback domain, e.g. `oast.example.com`; enables DNS |
| `SLURP_OAST_DNS_LISTEN` | DNS UDP bind address; default `127.0.0.1:5354`; route authoritative UDP port 53 to it |
| `SLURP_OAST_DNS_ADDRESS` | Optional IPv4 A-record address pointing to the HTTP collector/reverse proxy |

With DNS enabled, each probe uses `<random-id>.<domain>` as its HTTP hostname and DNS correlation name. Provide wildcard host routing (and a matching wildcard certificate for HTTPS). Without `SLURP_OAST_DNS_ADDRESS`, live names receive no address answer, allowing DNS observations but preventing subsequent HTTP connection through this responder. It is a minimal UDP authoritative responder, not a recursive resolver: no forwarding, DNS TCP, DNSSEC or general zone service. Only live probe names produce events or A answers. No address records are provided for unrelated names.

SSRF probes replace explicitly selected query/JSON values with unique HTTP callback URLs. XXE probes insert an external parameter-entity DTD into XML bodies while preserving the document content. Existing DTD/entity declarations and XML signatures are excluded. Existing shared sender origin/path restrictions, DNS pinning, no redirects, rate/time/evidence limits and sending consent still apply. OAST checks do not read cloud metadata, internal resources or local files.

For each candidate, Slurp issues two independent addresses plus an unsubmitted control, sends the two requests and polls for up to 15 seconds after sending. A finding requires callbacks for both probes and none for the control. DNS alone confirms resolution, not an HTTP fetch. HTTP callbacks confirm external interaction, not sensitive-data access; link scanners and intermediaries require review, so findings remain **needs_review**. Reflection, timeouts and no callbacks do not establish a vulnerability or a clean result.

Each associated request has an **OAST N** evidence tab with callback URL, DNS name when enabled, local display timestamps, protocol, peer and request/query detail. The unsubmitted control is saved beside the first probe. Captured request/response evidence remains available. Pending probes and callbacks live in backend memory for 10 minutes, capped at 1,024 probes and 16 events per probe. Saved observations persist with the scan in its original workspace. Delayed callbacks after the polling window are not automatically promoted to findings; pending state disappears on restart. Background correlation, longer/persistent polling, external collector providers and workflow-aware OAST remain planned.


## JWT, GraphQL and HTTP protocol active checks

Select **JWT active**, **GraphQL active** or **HTTP protocol** in the scan profile picker. Existing saved profiles are preserved; these specialized built-ins are added when missing. Checks can also be selected individually in a custom profile.

- `jwt-signature` requires a signed compact JWT in `Authorization: Bearer` and stable successful baselines. It removes recognized alternative credentials, verifies that the original JWT alone reproduces the baseline, and requires anonymous and malformed-token controls to return 401/403. It tests two changed signatures, `alg:none` and omitted signatures, preserving claims, with original-token restoration after each variant. Matching HTTP 200 alone is insufficient. Findings require protected-data review; role escalation is not tested. Cookie JWTs, JWE, weak-secret cracking, algorithm confusion and remote key-source attacks are not covered. Probe cookies do not update the shared cookie jar.
- `graphql-introspection` recognizes captured GET `query`, JSON POST and `application/graphql` requests. It replaces captured operations (including mutations) with small read-only queries. Two root-schema introspection results must agree and an unknown-field control must produce GraphQL errors. This is an informational configuration observation, not an authentication bypass. It does not download the entire schema.
- `graphql-batching` sends two `__typename` queries per JSON POST batch, repeats the batch and compares against a single-operation control. A correlated alias avoids treating echoed input as execution. Accepted batching is informational; rate-limit bypass, depth/complexity denial of service and field authorization are not tested.
- `http-framing` requires an intrusive profile and a GET endpoint. The authenticated `/api/scan/protocol` API constructs only fixed HTTP/1 variants: ordinary Content-Length, chunked, CL/TE, TE/CL and conflicting duplicate Content-Length. Each probe uses a fresh isolated TCP/TLS connection, verified TLS/SNI, shared destination validation and pinned DNS results. No application headers, cookies or recognized token query parameters are sent. No embedded second request is used. Two accepted ambiguous-framing requests plus successful ordinary/chunked controls produce a low-severity review finding; this does **not** confirm request smuggling or cross-user impact. Timeouts, incomplete/oversized responses and rejected requests do not establish a vulnerability. Connection reuse, HTTP/2/3 desync and cache poisoning remain unimplemented.

Raw protocol request and response bytes are shown in the existing Request/Response evidence tabs and persist with the scan. The raw engine allows four concurrent probes, a maximum 10-second request deadline and 32 KB responses. It has no general raw-bytes API, proxy use, redirect following or connection pool. Existing scan pacing, duration, workspace cancellation and evidence budgets apply. The HTTP protocol profile also includes existing OPTIONS/TRACE and response-header CRLF checks (select parameters for CRLF). Ordinary Replay/Flows/Intruder/Matrix sender protections are unchanged.


## Vulnerable JavaScript dependencies

Choose **JavaScript dependencies (OSV)** for a captured JavaScript response, or select `dependency-audit` in a passive profile. This check tokenizes up to 256 KB of JavaScript without executing it, extracts explicit stable `x.y.z` release banners from comments and checks at most ten unique package/version pairs. Generic VERSION variables, filenames, HTML examples, strings containing fake comment banners and prerelease/range versions are not treated as package attribution. Supported banner families: jQuery, lodash/Lo-Dash, AngularJS, Bootstrap, Moment, Vue, React/ReactDOM, Handlebars, Underscore, Axios and DOMPurify. Unknown or stripped bundles are inconclusive, not safe.

The backend queries `https://api.osv.dev/v1/query` for the exact npm package/version. **Only the package name and version leave Slurp; JavaScript source, target URLs, headers, cookies and tokens are never included.** This is passive with respect to the captured application but requires internet access for uncached OSV queries. The fixed upstream uses certificate validation, DNS pinning, no proxy/redirects, a 12-second overall deadline, four concurrent lookups and a 2 MB response cap. Successful results are cached in memory for one hour (256 entries). Failures are not cached and produce inconclusive results, not clean bills of health.

Findings include the banner, declared package/version, advisory ID, CVE aliases when available, an OSV advisory URL and the captured response evidence. Withdrawn advisories are ignored. Exact-version advisory matches do not prove the bundled code is original, executed, unpatched or exploitable; findings require review and use medium severity pending contextual assessment. Versionless bundles, source-map/lockfile attribution, patched-fork verification and runtime reachability remain future work. Large assets are analyzed only within the inspection bound and reported as incomplete where appropriate. This module runs from scan profiles; the existing automatic JS endpoint/secret collector is unchanged.


## Automatic 403 bypass audit

New proxy API captures returning HTTP 403 trigger `403-bypass` in the Rust backend. Target Scope and the Dashboard automatic audit Pause/Resume switch apply before every request; stored History is not backfilled. Results appear as **Automatic 403 bypass** tasks with findings and Request/Response evidence even when the Dashboard is closed.

The check replays the original request twice and requires stable 403 responses matching the complete captured denial (JSON key order is normalized). It then tests one header at a time: `X-Real-IP: 127.0.0.1`, `X-Client-IP: 127.0.0.1`, same-origin root Referer, and current-path `X-Original-URL`/`X-Rewrite-URL`. A successful candidate is repeated, compared with a negative IP/origin/missing-path control and followed by an unmodified request that must restore the same 403. Only matching nonempty JSON API responses with HTTP 200 are candidates; HTML login/error pages, empty replies and common JSON error envelopes do not establish a bypass. Redirects are not followed. Findings remain **needs_review** because the returned data/functionality and intended access policy need confirmation.

Credentials, actual endpoint, method and body are retained; repeated requests can change state if a bypass succeeds on a write API. These are same-endpoint header checks, not comprehensive 403 coverage: path/method mutations, forwarded/Host headers, WAF payloads and browser workflows are not tested. Shared Replay DNS pinning, localhost/LAN support, TLS verification, header restrictions, 10-second request timeouts and bounded responses remain enforced. The 403 module permits at most 22 requests, two request starts per second and a 60-second wall-clock budget. Existing NoAuthen/CORS checks are preserved and run only if not already completed (up to two additional requests).

Completed 403 checks are deduplicated per workspace and full request/authentication context, including successful retry reports. Existing NoAuthen/CORS reports do not suppress this new module; a different user/token, method, body, query or header context can receive an independent audit. Failed/inconclusive checks can be retried on later captures without replacing old evidence. Temporary results and deduplication disappear when the temporary workspace is discarded; saved-workspace completion survives restart. Probe traffic does not re-enter History, preventing recursive scans.
