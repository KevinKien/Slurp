import type { ScanCheck } from "./types";
import { result, observation } from "./extended-checks";

const fallback = ["noscript", "iframe", "noembed", "noframes"];
export function angularPiSignature(body: string): boolean {
  return fallback.some((tag) =>
    new RegExp(`<${tag}\\b[^>]*>[\\s\\S]{0,500}?<\\?[\\s\\S]{0,300}?<\\/${tag}`, "i").test(body),
  );
}

export const angularPiXss: ScanCheck = {
  id: "angular-pi-xss",
  name: "Angular SSR processing-instruction fallback breakout",
  active: false,
  perParameter: false,
  async run(ctx) {
    const baseline = ctx.baselines[0];
    if (!baseline?.response || baseline.response.status >= 300)
      return result("A successful HTML baseline is required.", true);
    const body = baseline.response.responseBody;
    if (new TextEncoder().encode(body).length > 256000)
      return result("Processing-instruction inspection requires HTML up to 256 KB.", true);
    if (!angularPiSignature(body))
      return result("No processing instruction inside a fallback raw-content element was observed.", true);
    return observation(
      "Angular SSR processing-instruction fallback breakout",
      "The captured HTML contains a processing instruction (<?...?>) inside <noscript>, <iframe>, <noembed> or <noframes>, and the instruction data contains the matching closing tag. Angular platform-server before 20.3.30/21.2.22/22.1.4 escaped '>' but not the ancestor's closing tag; a browser in RAWTEXT mode can end the container early and execute following markup. This is a serialized-signature observation, not proof that the data was attacker-controlled or that the payload executes.",
      [baseline],
      ["Fallback raw-content container with <?...?></tag sequence", "Angular SSR version and attacker control require review"],
      "medium",
    );
  },
};

export const angularPiChecks = [angularPiXss];
