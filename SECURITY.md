# Security Policy

Slurp is a security tool: it holds captured traffic, credentials and a local certificate authority. We take vulnerabilities in Slurp itself seriously.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub: on this repository open **Security → Report a vulnerability** (GitHub private vulnerability reporting).

Please include:

- the affected version (`slurp --version`, or the version in the UI footer) and operating system;
- the component (proxy, API, UI, MCP server, CLI, a scan check);
- steps to reproduce, a proof of concept and the impact you observed;
- whether the issue is already public.

## What to expect

| Step | Target |
|---|---|
| Acknowledge your report | within 3 business days |
| First assessment and severity | within 10 business days |
| Fix or mitigation for high and critical issues | within 90 days, sooner when actively exploited |

We will keep you updated, agree on a disclosure date with you, and credit you in the advisory unless you prefer otherwise. We do not currently pay bounties.

## Supported versions

Only the latest release receives security fixes. Please reproduce on the latest release before reporting.

## Scope

In scope, for example:

- the management API or WebSocket being reachable or usable from an untrusted origin or network, or an API token bypass;
- cross-site scripting or other code execution in the UI from captured traffic, imported files (`.slurp`, HAR, Burp, Postman, Bruno) or scan results;
- leaking the CA private key, captured credentials or workspace data;
- a scan check or automatic audit that sends the user's credentials or data to a host the user did not target;
- a scan check that is documented as non-destructive but changes state on the target;
- the MCP server exposing actions beyond what is documented.

Out of scope:

- findings that Slurp reports about *other* systems (contact that system's owner);
- issues that need an attacker who already controls the user's machine or account;
- risks that are documented and expected, such as the local CA being trusted by the browser you configure, or MCP clients reading captured traffic;
- denial of service through excessive traffic against your own instance;
- missing hardening headers without a demonstrated impact.

## Safe harbor

We will not pursue legal action against good-faith research that follows this policy, avoids privacy violations and data destruction, and only tests your own installations of Slurp.
