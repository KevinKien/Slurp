import type { ScanCheck, Exchange } from "./types";
import { ok, result, observation } from "./extended-checks";
export const httpFraming: ScanCheck = {
  id: "http-framing",
  name: "HTTP/1 ambiguous request framing",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!ctx.protocol || ctx.request.method !== "GET")
      return result("Dedicated HTTP/1 engine and a GET endpoint required.", true);
    const accepted = (x: Exchange) =>
      ok(x) && x.response!.status >= 200 && x.response!.status < 400;
    const controls: Exchange[] = [];
    for (const variant of ["control", "chunked"] as const)
      controls.push(await ctx.protocol(variant, `HTTP/1 ${variant} control`));
    if (!controls.every(accepted))
      return result(
        "Ordinary Content-Length and chunked controls must both succeed; no framing conclusion.",
        true,
      );
    const findings = [];
    let incomplete = false;
    for (const variant of ["cl-te", "te-cl", "duplicate-cl"] as const) {
      const a = await ctx.protocol(variant, `HTTP/1 ${variant} probe`);
      const b = await ctx.protocol(variant, `HTTP/1 ${variant} repeat`);
      const restore = await ctx.protocol("control", "HTTP/1 ordinary framing restore");
      incomplete ||= ![a, b, restore].every(ok);
      if ([a, b, restore].every(accepted))
        findings.push(
          ...observation(
            `HTTP/1 ambiguous framing accepted: ${variant}`,
            "Two fresh isolated connections accepted conflicting framing headers, and ordinary/chunked controls succeeded. This establishes acceptance only: no embedded request, shared connection, cross-user effect or confirmed request smuggling was tested. Credentials were omitted. The actual wire bytes are attached.",
            [...controls, a, b, restore],
            [
              variant === "duplicate-cl"
                ? "Conflicting Content-Length: 5 and 0"
                : "Content-Length: 0 combined with chunked Transfer-Encoding",
            ],
            "low",
          ).findings,
        );
    }
    return {
      findings,
      message: "Fresh-connection HTTP/1 framing diagnostics completed; timeouts are inconclusive.",
      inconclusive: incomplete,
    };
  },
};
export const protocolChecks = [httpFraming];
