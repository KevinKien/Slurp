#!/usr/bin/env python3
"""Builds benchmark/RESULTS.md from the JSON files written by `npm run bench:scan`.

Usage: python3 benchmark/report.py <registry.json>
`registry.json` is a dump of checkRegistry (impact, requirements, ...). Statuses come from the result files,
which record what each check's status was when the benchmark ran, so the report can be rebuilt after a promotion.
"""
import collections, glob, json, sys, os

root = os.path.dirname(os.path.abspath(__file__))
reg = {x["id"]: x for x in json.load(open(sys.argv[1]))}
def latest(tag):
    files = sorted(glob.glob(os.path.join(root, "results", f"scan-benchmark-*-{tag}.json")))
    return json.load(open(files[-1]))
before, after = latest("baseline"), latest("after")
previous = set(json.load(open(os.path.join(root, "promoted.json")))) if os.path.exists(os.path.join(root, "promoted.json")) else set()
for cid, status in after.get("registry", {}).items():
    if cid in reg:
        reg[cid]["status"] = status

MIN_VARIANTS = 3  # distinct vulnerable variants, all detected
kinds = collections.Counter(c["kind"] for c in after["cases"])
groups = collections.OrderedDict()
for c in after["cases"]:
    groups.setdefault(c["group"], collections.Counter())[c["kind"]] += 1
sent = sum(r["sent"] for r in after["results"])

rows, promote, hold, stable_issues = [], [], [], []
for cid, a in after["score"].items():
    b = before["score"][cid]
    if not a["expected"] and not a["falsePositives"] and not b["falsePositives"]:
        continue
    status = reg[cid]["status"]
    n = len(a["expected"])
    clean = not a["missed"] and not a["falsePositives"]
    if status == "experimental":
        if n >= MIN_VARIANTS and clean and not b["falsePositives"]:
            verdict = "**promote**"; promote.append(cid)
        else:
            why = []
            if n < MIN_VARIANTS: why.append(f"only {n} variant{'s' if n != 1 else ''}")
            if a["missed"]: why.append("missed " + ", ".join(a["missed"]))
            if a["falsePositives"]: why.append("false positive on " + ", ".join(a["falsePositives"]))
            verdict = "keep: " + "; ".join(why); hold.append(cid)
    elif status == "implemented":
        if clean:
            verdict = "promoted earlier, confirmed" if cid in previous else "stable, confirmed"
        else:
            why = []
            if a["missed"]: why.append("missed " + ", ".join(a["missed"]))
            if a["falsePositives"]: why.append("false positive on " + ", ".join(a["falsePositives"]))
            verdict = "stable, **review**: " + "; ".join(why); stable_issues.append((cid, why))
    else:
        verdict = status
    rows.append((cid, status, f"{len(b['hit'])}/{len(b['expected'])}", f"{len(a['hit'])}/{n}", len(b["falsePositives"]), len(a["falsePositives"]), verdict))
rows.sort(key=lambda r: (r[1] != "experimental", r[0]))

out = []
w = out.append
w("# Scan benchmark results\n")
w(f"Run on {after['date']} against the local lab in `benchmark/lab.ts` ({len(after['cases'])} cases: {kinds['vuln']} vulnerable, {kinds['safe']} safe, {kinds['noise']} noise; {sent:,} requests in {after['seconds']:.0f} s). "
  "Every case is scanned with **every** HTTP-capable check, so a finding on a safe or noise case is a false positive for that check.\n")
w(f"**Read this first.** The lab was written together with the checks' author's view of how these flaws behave, and covers {len(after['cases'])} cases, not the open internet. "
  "It shows that a check works on the shapes below and stays silent on the safe look-alikes; it does not measure how often a check fires on real applications. "
  "Treat the promotions as \"no counter-evidence found\" and confirm them on an independent target (Juice Shop, DVWA, a real staging app) before relying on them.\n")
w("## Method\n")
w("- The real `ScanEngine` runs headless in Node (`npm run bench:scan`). Requests go to a lab server on 127.0.0.1; the engine's 20 requests/second ceiling is lifted for it.")
w("- Vulnerable cases emulate the behaviour (a MySQL-style evaluator with `SLEEP` and subqueries, a POSIX `sh` emulator, template and `eval` engines, PHP-style `include` wrappers, an XML parser with entities, a JWT verifier, GraphQL, ACLs). Safe cases are the secure counterpart of the same feature. Noise cases change on every request, answer slowly, or quote exploit text.")
w("- Header, cookie and reflection observations (`passive-audit`, `security-headers`, `policy-audit`, `cookie-*`, `disclosure-audit`, `reflection`, `xss-bypass`) are true statements about any response, so they are scored only on cases meant to be silent for them.")
w("- Not covered: checks that need a browser, an OAST collector, raw sockets or the dependency service (they return `inconclusive` here), and the automatic background audits.\n")
w("## Cases\n")
w("| Group | Vulnerable | Safe | Noise |\n|---|---:|---:|---:|")
for g, c in groups.items(): w(f"| {g} | {c['vuln']} | {c['safe']} | {c['noise']} |")
w("")
w("## Per check\n")
w(f"*Variants* are the vulnerable cases a check should report. *Before* is the checks as they were; *after* includes the fixes listed below. A check is promoted from experimental to stable when it detected **every** variant (at least {MIN_VARIANTS}) and produced **no** false positive on any safe or noise case, before and after.\n")
w("| Check | Status | Detected before | Detected after | FP before | FP after | Verdict |\n|---|---|---:|---:|---:|---:|---|")
for r in rows: w("| `%s` | %s | %s | %s | %d | %d | %s |" % r)
w("")
w("## Defects found and fixed\n")
w("Each was a miss or false positive in an earlier run, traced to the check or the engine rather than to the lab:\n")
w("1. **A rejected payload ended the whole check.** `command-injection`, `command-bypass` and the arithmetic checks (`code-injection`, `el-injection`) returned `inconclusive` as soon as one probe was blocked or answered with an error. A filter that blocks `;` (the case `command-bypass` exists for) or an `eval` that answers 500 to the first syntax family hid every later payload. They now move on to the next payload or syntax family and report `inconclusive` only if nothing evaluated.")
w("2. **`url-override` could never find the classic bypass.** The probe through the origin root (`GET /` with `X-Original-URL: <denied path>`) was refused by the engine's \"stay on the selected endpoint\" rule, so the branch was dead. The engine now allows a bodyless `GET /` on the same origin for this one check.")
w("3. **`xxe` / `xxe-body` missed real XXE.** The `/etc/passwd` signature required `root:` at the start of a line, but entity content sits right after a tag or quote (`<name>root:x:0:0…`). The signature now accepts a preceding `>`, quote or whitespace.")
w("4. **`graphql-field-suggestion` flagged every GraphQL server.** It treated the standard `Cannot query field` validation error as a suggestion. It now requires `Did you mean`.")
w("5. **`sql-time` only knew quoted injection points.** Its payload started with a quote, so an unquoted numeric parameter (`id=1`) broke the query, the response changed and the check gave up. It now tries the bare form (`1 AND (SELECT … SLEEP(2)) …`) when the quoted form changes the response, as `sql-boolean` already does.\n")
w("## Misses and false positives that remain\n")
for cid, a in sorted(after["score"].items()):
    for m in a["missed"]:
        case = next(c for c in after["cases"] if c["id"] == m)
        w(f"- **`{cid}` missed `{m}`** ({case['title']}).")
    for f in a["falsePositives"]:
        case = next(c for c in after["cases"] if c["id"] == f)
        w(f"- **`{cid}` false positive on `{f}`** ({case['title']}).")
w("")
w("Notes on the ones that are by design: `client-ip` tries `X-Real-IP` and `X-Client-IP` but not `X-Forwarded-For`; `business-negative` reports accepted out-of-range values even for resource ids, which is noisy for `id=` parameters; `xml-injection-body` reports XML endpoints whose malformed-input error names the parser (SAXParseException, XmlException, XMLSyntaxError, \"XML parsing error\"); an endpoint that answers with a generic error is silent. Its severity is low: it indicates parser-error disclosure, not a confirmed injection. The lab's blind SQL endpoints share one evaluator, so they are genuinely time-injectable as well, and `sql-time` reporting them is tolerated.\n")
w("## Promotions\n")
w("Promoted to stable in this run: " + (", ".join(f"`{c}`" for c in sorted(promote)) or "none") + ".\n")
earlier = sorted(previous - set(promote))
if earlier:
    w("Promoted in earlier runs and re-confirmed: " + ", ".join(f"`{c}`" for c in earlier) + ".\n")
w("Stable checks that showed a miss or a false positive and should be reviewed (not changed here): " + ("; ".join(f"`{c}` ({', '.join(w_)})" for c, w_ in stable_issues) or "none") + ".\n")
w("## Reproduce\n")
w("```sh\ncd curl-cozy\n# before: restore the original checks, then\nBENCH_TAG=baseline npm run bench:scan\n# after\nBENCH_TAG=after npm run bench:scan\npython3 benchmark/report.py /path/to/registry.json\n```\n")
open(os.path.join(root, "RESULTS.md"), "w").write("\n".join(out))
json.dump(sorted(promote), open(os.path.join(root, "results", "promote.json"), "w"))
print("promote:", sorted(promote)); print("hold:", len(hold)); print("stable issues:", stable_issues)
