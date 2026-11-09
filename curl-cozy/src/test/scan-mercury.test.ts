import { expect, it } from "vitest";
import { getScanCheck } from "../lib/scan/checks";
import { mercuryExposure } from "../lib/scan/mercury-check";

const html = `<html><head><script src="/mercury/static/app.js"></script></head>
<body><div class="widget-html-content"><b>hello</b></div><footer>Mercury 3.2.6</footer></body></html>`;

it("fingerprints Mercury and compares the version with 3.2.11", () => {
  const exposure = mercuryExposure(html);
  expect(exposure.mercury).toBe(true);
  expect(exposure.markdownSink).toBe(true);
  expect(exposure.version).toBe("3.2.6");
  expect(exposure.vulnerable).toBe(true);
  expect(mercuryExposure(html.replace("3.2.6", "3.2.11")).vulnerable).toBe(false);
  expect(mercuryExposure("<html>plain</html>").mercury).toBe(false);
});

it("reports the Mercury sink without submitting a payload", async () => {
  const check = getScanCheck("mercury-markdown-xss");
  const context = {
    request: { method: "GET", url: "https://app.test/", headers: {}, body: "" },
    baselines: [
      {
        response: { status: 200, responseHeaders: { "content-type": "text/html" }, responseBody: html },
        evidence: { id: "baseline" },
      },
    ],
    stable: true,
    probe: async () => {
      throw Error("Mercury inspection must not send requests");
    },
    nonce: () => "marker",
  } as never;
  const output = await check.run(context);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]?.severity).toBe("medium");
  expect(output.findings[0]?.verification.outcome).toBe("inconclusive");
});
