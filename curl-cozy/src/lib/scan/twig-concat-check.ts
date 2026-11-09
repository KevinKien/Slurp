import type { ScanCheck } from "./types";
import { result, observation } from "./extended-checks";

export function twigConcatSignature(body: string): boolean {
  if (/\{\{[^}]*~[^}]*\}\}/.test(body) === false) return false;
  return /"(on|error|load|script|java|iframe|svg|style)"\s*~|~\s*"(on|error|load|script|java|iframe|svg|style)"/i.test(body);
}

export const twigConcatXss: ScanCheck = {
  id: "twig-concat-xss",
  name: "Twig concatenation XSS filter bypass",
  active: false,
  perParameter: false,
  async run(ctx) {
    const baseline = ctx.baselines[0];
    if (!baseline?.response || baseline.response.status >= 300)
      return result("A successful HTML baseline is required.", true);
    const body = baseline.response.responseBody;
    if (new TextEncoder().encode(body).length > 256000)
      return result("Twig inspection requires an HTML response up to 256 KB.", true);
    if (!twigConcatSignature(body))
      return result("No Twig string-concatenation XSS payload was observed.", true);
    return observation(
      "Twig concatenation XSS filter bypass",
      "The captured response contains Twig string concatenation ({{ \"on\" ~ \"error\" }} or similar) that constructs an event handler, script tag or javascript: protocol at render time. Grav's pre-render XSS validator sees the inert {{...}} expression and can allow it; after Twig processing, the output becomes live HTML. This is a signature observation, not proof that Twig processing is enabled or that the content executes.",
      [baseline],
      ["Twig concatenation constructing an event/tag/protocol", "Requires twig_content.process_enabled and raw rendering"],
      "medium",
    );
  },
};

export const twigConcatChecks = [twigConcatXss];
