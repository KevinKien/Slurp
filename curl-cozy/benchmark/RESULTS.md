# Scan benchmark results

Run on 2026-11-10 against the local lab in `benchmark/lab.ts` (106 cases: 71 vulnerable, 31 safe, 4 noise; 22,880 requests in 98 s). Every case is scanned with **every** HTTP-capable check, so a finding on a safe or noise case is a false positive for that check.

**Read this first.** The lab was written together with the checks' author's view of how these flaws behave, and covers 106 cases, not the open internet. It shows that a check works on the shapes below and stays silent on the safe look-alikes; it does not measure how often a check fires on real applications. Treat the promotions as "no counter-evidence found" and confirm them on an independent target (Juice Shop, DVWA, a real staging app) before relying on them.

## Method

- The real `ScanEngine` runs headless in Node (`npm run bench:scan`). Requests go to a lab server on 127.0.0.1; the engine's 20 requests/second ceiling is lifted for it.
- Vulnerable cases emulate the behaviour (a MySQL-style evaluator with `SLEEP` and subqueries, a POSIX `sh` emulator, template and `eval` engines, PHP-style `include` wrappers, an XML parser with entities, a JWT verifier, GraphQL, ACLs). Safe cases are the secure counterpart of the same feature. Noise cases change on every request, answer slowly, or quote exploit text.
- Header, cookie and reflection observations (`passive-audit`, `security-headers`, `policy-audit`, `cookie-*`, `disclosure-audit`, `reflection`, `xss-bypass`) are true statements about any response, so they are scored only on cases meant to be silent for them.
- Not covered: checks that need a browser, an OAST collector, raw sockets or the dependency service (they return `inconclusive` here), and the automatic background audits.

## Cases

| Group | Vulnerable | Safe | Noise |
|---|---:|---:|---:|
| SQL injection | 10 | 4 | 0 |
| Noise | 0 | 0 | 4 |
| Command injection | 7 | 2 | 0 |
| Template injection | 9 | 3 | 0 |
| Files and redirects | 9 | 4 | 0 |
| XML | 9 | 3 | 0 |
| CORS | 4 | 2 | 0 |
| Access control | 7 | 3 | 0 |
| JWT | 4 | 1 | 0 |
| GraphQL | 2 | 1 | 0 |
| Passive | 3 | 4 | 0 |
| Other | 7 | 4 | 0 |

## Per check

*Variants* are the vulnerable cases a check should report. *Before* is the checks as they were; *after* includes the fixes listed below. A check is promoted from experimental to stable when it detected **every** variant (at least 3) and produced **no** false positive on any safe or noise case, before and after.

| Check | Status | Detected before | Detected after | FP before | FP after | Verdict |
|---|---|---:|---:|---:|---:|---|
| `auth-access` | experimental | 1/1 | 1/1 | 0 | 0 | keep: only 1 variant |
| `client-ip` | experimental | 1/2 | 1/2 | 0 | 0 | keep: only 2 variants; missed acl-client-ip-xff |
| `code-injection` | experimental | 1/4 | 4/4 | 0 | 0 | **promote** |
| `command-bypass` | experimental | 0/4 | 4/4 | 0 | 0 | **promote** |
| `el-injection` | experimental | 1/1 | 1/1 | 0 | 0 | keep: only 1 variant |
| `file-inclusion` | experimental | 1/1 | 1/1 | 0 | 0 | keep: only 1 variant |
| `file-upload` | experimental | 4/4 | 4/4 | 0 | 0 | **promote** |
| `graphql-field-suggestion` | experimental | 1/1 | 1/1 | 1 | 0 | keep: only 1 variant |
| `nosql-operators` | experimental | 1/1 | 1/1 | 0 | 0 | keep: only 1 variant |
| `referer-access` | experimental | 1/1 | 1/1 | 0 | 0 | keep: only 1 variant |
| `sql-time` | experimental | 3/4 | 4/4 | 0 | 0 | **promote** |
| `url-override` | experimental | 0/3 | 3/3 | 0 | 0 | **promote** |
| `xml-entity-body` | experimental | 6/6 | 6/6 | 0 | 0 | **promote** |
| `xml-injection-body` | experimental | 6/6 | 6/6 | 0 | 0 | **promote** |
| `xxe` | experimental | 0/3 | 3/3 | 0 | 0 | **promote** |
| `xxe-body` | experimental | 0/3 | 3/3 | 0 | 0 | **promote** |
| `business-negative` | implemented | 1/1 | 1/1 | 1 | 1 | stable, **review**: false positive on sqli-validate-safe |
| `command-injection` | implemented | 3/3 | 3/3 | 0 | 0 | promoted earlier, confirmed |
| `cookie-audit` | implemented | 1/1 | 1/1 | 0 | 0 | stable, confirmed |
| `cookie-flags` | implemented | 1/1 | 1/1 | 0 | 0 | stable, confirmed |
| `cors` | implemented | 1/1 | 1/1 | 0 | 0 | stable, confirmed |
| `cors-trust` | implemented | 3/3 | 3/3 | 0 | 0 | promoted earlier, confirmed |
| `error-disclosure` | implemented | 1/1 | 1/1 | 0 | 0 | stable, confirmed |
| `graphql-batching` | implemented | 1/1 | 1/1 | 0 | 0 | stable, confirmed |
| `graphql-introspection` | implemented | 1/1 | 1/1 | 0 | 0 | stable, confirmed |
| `http-methods` | implemented | 1/1 | 1/1 | 0 | 0 | stable, confirmed |
| `jwt-signature` | implemented | 3/3 | 3/3 | 0 | 0 | promoted earlier, confirmed |
| `jwt-weak-secret` | implemented | 1/1 | 1/1 | 0 | 0 | stable, confirmed |
| `open-redirect` | implemented | 3/3 | 3/3 | 0 | 0 | stable, confirmed |
| `passive-audit` | implemented | 1/1 | 1/1 | 0 | 0 | stable, confirmed |
| `path-traversal` | implemented | 5/5 | 5/5 | 0 | 0 | promoted earlier, confirmed |
| `reflection` | implemented | 1/1 | 1/1 | 0 | 0 | stable, confirmed |
| `security-headers` | implemented | 1/1 | 1/1 | 0 | 0 | stable, confirmed |
| `sql-boolean` | implemented | 3/3 | 3/3 | 0 | 0 | promoted earlier, confirmed |
| `sql-injection` | implemented | 3/3 | 3/3 | 0 | 0 | promoted earlier, confirmed |
| `ssti` | implemented | 4/4 | 4/4 | 0 | 0 | promoted earlier, confirmed |

## Defects found and fixed

Each was a miss or false positive in an earlier run, traced to the check or the engine rather than to the lab:

1. **A rejected payload ended the whole check.** `command-injection`, `command-bypass` and the arithmetic checks (`code-injection`, `el-injection`) returned `inconclusive` as soon as one probe was blocked or answered with an error. A filter that blocks `;` (the case `command-bypass` exists for) or an `eval` that answers 500 to the first syntax family hid every later payload. They now move on to the next payload or syntax family and report `inconclusive` only if nothing evaluated.
2. **`url-override` could never find the classic bypass.** The probe through the origin root (`GET /` with `X-Original-URL: <denied path>`) was refused by the engine's "stay on the selected endpoint" rule, so the branch was dead. The engine now allows a bodyless `GET /` on the same origin for this one check.
3. **`xxe` / `xxe-body` missed real XXE.** The `/etc/passwd` signature required `root:` at the start of a line, but entity content sits right after a tag or quote (`<name>root:x:0:0…`). The signature now accepts a preceding `>`, quote or whitespace.
4. **`graphql-field-suggestion` flagged every GraphQL server.** It treated the standard `Cannot query field` validation error as a suggestion. It now requires `Did you mean`.
5. **`sql-time` only knew quoted injection points.** Its payload started with a quote, so an unquoted numeric parameter (`id=1`) broke the query, the response changed and the check gave up. It now tries the bare form (`1 AND (SELECT … SLEEP(2)) …`) when the quoted form changes the response, as `sql-boolean` already does.

## Misses and false positives that remain

- **`business-negative` false positive on `sqli-validate-safe`** (Input validated (400 on non-digits)).
- **`client-ip` missed `acl-client-ip-xff`** (Trusts X-Forwarded-For only).

Notes on the ones that are by design: `client-ip` tries `X-Real-IP` and `X-Client-IP` but not `X-Forwarded-For`; `business-negative` reports accepted out-of-range values even for resource ids, which is noisy for `id=` parameters; `xml-injection-body` reports XML endpoints whose malformed-input error names the parser (SAXParseException, XmlException, XMLSyntaxError, "XML parsing error"); an endpoint that answers with a generic error is silent. Its severity is low: it indicates parser-error disclosure, not a confirmed injection. The lab's blind SQL endpoints share one evaluator, so they are genuinely time-injectable as well, and `sql-time` reporting them is tolerated.

## Promotions

Promoted to stable in this run: `code-injection`, `command-bypass`, `file-upload`, `sql-time`, `url-override`, `xml-entity-body`, `xml-injection-body`, `xxe`, `xxe-body`.

Promoted in earlier runs and re-confirmed: `command-injection`, `cors-trust`, `jwt-signature`, `path-traversal`, `sql-boolean`, `sql-injection`, `ssti`.

Stable checks that showed a miss or a false positive and should be reviewed (not changed here): `business-negative` (false positive on sqli-validate-safe).

## Reproduce

```sh
cd curl-cozy
# before: restore the original checks, then
BENCH_TAG=baseline npm run bench:scan
# after
BENCH_TAG=after npm run bench:scan
python3 benchmark/report.py /path/to/registry.json
```
