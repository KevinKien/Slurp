import type { ScanCheck } from "./types";
import { result, observation } from "./extended-checks";

export function svgEntitySignature(body: string): boolean {
  const lower = body.toLowerCase();
  if (!lower.includes("<svg")) return false;
  const reference = /&(tab|newline);/.test(lower) || lower.includes("%26tab%3b") || lower.includes("%26newline%3b");
  return reference && lower.includes("javascript:");
}

export const svgEntityXss: ScanCheck = {
  id: "svg-entity-xss",
  name: "SVG DTD entity / named-reference XSS payload",
  active: false,
  perParameter: false,
  async run(ctx) {
    const baseline = ctx.baselines[0];
    if (!baseline?.response || baseline.response.status >= 300)
      return result("A successful HTML/JS baseline is required.", true);
    const body = baseline.response.responseBody;
    if (new TextEncoder().encode(body).length > 256000)
      return result("SVG inspection requires a response up to 256 KB.", true);
    if (!svgEntitySignature(body))
      return result("No SVG DTD entity/named-reference javascript: payload was observed.", true);
    return observation(
      "SVG sanitizer entity/named-reference bypass payload",
      "The captured response contains an SVG link whose href uses an HTML5 named character reference (&Tab; or &NewLine;) before a javascript: URL. enshrined/svg-sanitize <= 0.22.0 validates the XML-expanded value (which can begin with #), then serializes the entity reference and strips the DOCTYPE; a browser resolves it as whitespace and executes the javascript: URL when the link is clicked. This is a payload/signature observation, not proof that the link executes or that the SVG is rendered inline.",
      [baseline],
      ["SVG with &Tab;/&NewLine; before javascript:", "Click and inline rendering are not tested"],
      "medium",
    );
  },
};

export const svgEntityChecks = [svgEntityXss];
