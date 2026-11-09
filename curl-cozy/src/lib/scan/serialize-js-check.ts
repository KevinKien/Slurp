import type { ScanCheck } from "./types";
import { result, observation } from "./extended-checks";

export function serializeFunctionSignature(body: string): boolean {
  const lower = body.toLowerCase();
  return (
    lower.includes("</script=+/") ||
    (lower.includes("function") && lower.includes("</script><img") && lower.includes("onerror"))
  );
}

export const serializeJsXss: ScanCheck = {
  id: "serialize-js-xss",
  name: "serialize-javascript function-body </script> signature",
  active: false,
  perParameter: false,
  async run(ctx) {
    const baseline = ctx.baselines[0];
    if (!baseline?.response || baseline.response.status >= 300)
      return result("A successful HTML/JS baseline is required.", true);
    const body = baseline.response.responseBody;
    if (new TextEncoder().encode(body).length > 256000)
      return result("Serialized-function inspection requires a response up to 256 KB.", true);
    if (!serializeFunctionSignature(body))
      return result("No serialize-javascript function-body signature was observed.", true);
    return observation(
      "serialize-javascript function-body </script> signature",
      "The captured response contains a serialized function body with </script=+/ or an unescaped </script><img onerror sequence. serialize-javascript 7.1.1 neutralizes only the leading '<' of a </script...> match, so a later complete tag can survive and terminate the script element, making the remainder live HTML. This is a signature observation, not proof that the value is attacker-controlled or executed.",
      [baseline],
      ["Serialized function body with </script=+/ or </script><img", "Version 7.1.1 is affected; 7.1.2 is fixed"],
      "medium",
    );
  },
};

export const serializeJsChecks = [serializeJsXss];
