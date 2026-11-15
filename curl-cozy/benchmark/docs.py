#!/usr/bin/env python3
"""Rewrites the "Vulnerability coverage" section of public/docs/scan.html from the check registry.

Usage: python3 benchmark/docs.py <registry.json>   (a JSON dump of checkRegistry)
"""
import html, json, os, sys

root = os.path.dirname(os.path.abspath(__file__))
page = os.path.join(root, "..", "public", "docs", "scan.html")
registry = json.load(open(sys.argv[1]))
by = {x["id"]: x for x in registry}
e = html.escape

GROUPS = [
    ("Injection into server-side interpreters", "SQL, NoSQL, OS command, server-side code, expression-language, template, LDAP and XPath injection, plus filter-bypass variants and prototype pollution. Checks compare repeated probes with controls and restore the original request; none extracts data.", ["Injection"]),
    ("XML parsing and XXE", "XML parser errors, internal entity expansion, local-file entities, for XML bodies and for XML carried in a parameter.", ["XML"]),
    ("Cross-site scripting and browser sinks", "Reflected and DOM XSS validated by running the response in an isolated Chrome/Chromium with network access blocked, framework-specific sinks and postMessage handling.", ["Browser", "DOM"]),
    ("Out-of-band (SSRF, XXE, JWT key fetch)", "Blind issues observed through a self-hosted callback collector (HTTP and optional DNS).", ["OAST"]),
    ("JWT and sessions", "Signature handling, weak HMAC secrets, attacker-supplied keys, remote key sources, key-lookup injection, algorithm confusion and tokens in the URL.", ["JWT", "Session"]),
    ("Authentication and access control", "Missing or weak authentication, OAuth redirect handling, and access that changes with headers, the Referer, the client address or URL-override headers.", ["Access control", "Authentication", "Routing"]),
    ("HTTP, headers, caching and browser policy", "Host and response header injection, ambiguous request framing, cache poisoning and deception, CORS, security headers, cookies, risky methods and open redirects.", ["Headers", "Cookies", "CORS", "Methods", "Configuration", "Protocol", "Infrastructure", "Navigation"]),
    ("Files and uploads", "Path traversal, local/remote file inclusion and file-upload restrictions.", ["File access"]),
    ("Information disclosure and discovery", "Technology and error disclosure, credentials in JavaScript, exposed API descriptions, and discovery of endpoints and hidden parameters. Discovery results are leads, not vulnerabilities.", ["Discovery", "Disclosure", "Input", "API"]),
    ("Business logic", "Numeric bounds and malformed or past dates accepted by write endpoints.", ["Business logic"]),
    ("GraphQL", "Schema introspection, field suggestions, endpoint detection, batching and alias policy.", ["GraphQL"]),
    ("Dependencies and known exposures", "Vulnerable JavaScript libraries and version-based exposure to specific CVEs and products. None of these sends an exploit payload.", ["Dependencies", "Runtime"]),
    ("Template-based scanning", "A bounded subset of Nuclei YAML templates (see above).", ["Templates"]),
]
label = {"implemented": "Stable", "experimental": "Experimental", "planned": "Planned"}
run = {"manual": "Manual", "automatic": "Automatic", "both": "Manual + automatic"}
impact = {"passive": "Passive (no requests)", "light": "Light", "medium": "Active", "intrusive": "Intrusive"}

def table(items):
    rows = "".join(
        f"<tr><td>{e(x['name'])}<br><code>{e(x['id'])}</code></td><td>{label[x['status']]}</td><td>{impact[x['impact']]}</td>"
        f"<td>{run[x.get('execution', 'manual')]}</td><td>{e(x['requirements'])}</td><td>{e(x['verification'])}</td></tr>"
        for x in items
    )
    return ('<div class="table"><table><thead><tr><th>Check</th><th>Status</th><th>Requests</th><th>Runs</th><th>Needs</th><th>Evidence required</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></div>")

planned = [x for x in registry if x["status"] == "planned"]
covered = {c for _, _, cats in GROUPS for c in cats}
missing = {x["category"] for x in registry if x["status"] != "planned"} - covered
assert not missing, f"categories without a group: {missing}"
count = {s: sum(1 for x in registry if x["status"] == s) for s in label}
out = (
    f'<h2 id="coverage">Vulnerability coverage</h2><p>Slurp ships {len(registry)} scan checks: {count["implemented"]} stable, {count["experimental"]} experimental and {count["planned"]} planned. '
    "<b>Stable</b> checks are routine observations, or were detected on every variant of a local benchmark of vulnerable and safe look-alike endpoints with no false positive (see <code>curl-cozy/benchmark/RESULTS.md</code> in the repository, which also lists the limits of that benchmark). "
    "<b>Experimental</b> checks are implemented and tested but depend on stable baselines, target behaviour or external tools, or have not been benchmarked on enough variants, so a finding means &ldquo;verified signal, review the evidence&rdquo; rather than a confirmed exploit. "
    "<b>Planned</b> checks are listed in the catalog but do not run yet. A check marked <i>Automatic</i> also runs in the background on new proxy captures; the rest run only when you start a scan.</p>"
    "<p><b>Requests</b> shows how much a check sends: <i>Passive</i> sends nothing, <i>Light</i> and <i>Active</i> send bounded probes, and <i>Intrusive</i> may change server state or load and needs both sending and intrusive checks to be allowed in the scan dialog. Stable checks run in the Balanced preset when their request level allows it; experimental checks need the Comprehensive preset. Uploaded traffic from remote capture clients is not scanned automatically.</p>"
)
for title, desc, cats in GROUPS:
    items = [x for x in registry if x["category"] in cats and x["status"] != "planned"]
    if items:
        out += f"<h3>{e(title)}</h3><p>{e(desc)}</p>{table(items)}"
out += f"<h3>Planned</h3><p>These catalog entries describe deeper variants of the areas above. They are not available yet.</p>{table(planned)}"
out += ("<h3>Automatic background audits</h3><p>Besides the checks above, two audits run only in the background on new proxy captures and are described in detail below: <b>Automatic CRLF injection</b> and "
        "<b>Host header injection</b> (Location redirects only). Automatic 403 bypass, anonymous API access (image responses are skipped), CORS, JavaScript endpoint and secret discovery, and the CVE exposure checks use the same pause control and Target Scope.</p>")

s = open(page).read()
start = s.index('<h2 id="coverage">')
marker = s.index("Automatic background audits", start)
end = s.index("</p>", marker) + 4
open(page, "w").write(s[:start] + out + s[end:])
print(f"{len(registry)} checks, {count}")
