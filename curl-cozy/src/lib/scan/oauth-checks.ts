import type { Exchange, ScanCheck, ScanCheckContext } from "./types";
import type { HttpRequest } from "../traffic";
import { compareResponses } from "../response-diff";
import { h, ok, text, result, observation } from "./extended-checks";

const authorizePath = /\/(?:oauth2?|openid-connect)\/authorize|\/connect\/authorize|\/authorize/i;

type Source = "query" | "form";

function oauthRequest(ctx: ScanCheckContext): { source: Source; url: URL; params: URLSearchParams } | undefined {
  const url = new URL(ctx.request.url);
  const query = url.searchParams;
  if (query.has("client_id") && query.has("redirect_uri") && (query.has("response_type") || authorizePath.test(url.pathname)))
    return { source: "query", url, params: query };
  const body = ctx.request.body ?? "";
  if (body && /redirect_uri=/.test(body)) {
    const form = new URLSearchParams(body);
    if (form.has("client_id") && form.has("redirect_uri") && (form.has("response_type") || authorizePath.test(url.pathname)))
      return { source: "form", url, params: form };
  }
  return undefined;
}

function withParam(request: HttpRequest, source: Source, name: string, value: string): HttpRequest {
  const next = structuredClone(request);
  if (source === "query") {
    const url = new URL(next.url);
    url.searchParams.set(name, value);
    next.url = url.href;
  } else {
    const form = new URLSearchParams(next.body);
    form.set(name, value);
    next.body = form.toString();
  }
  return next;
}

function locationOf(exchange: Exchange, base: string): string | undefined {
  const raw = h(exchange, "location");
  if (!raw) return undefined;
  try {
    return new URL(raw, base).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function isAttacker(host: string | undefined, attacker: string): boolean {
  return !!host && (host === attacker || host.endsWith("." + attacker));
}

function same(a: Exchange, b: Exchange, ctx: ScanCheckContext): boolean {
  if (!ok(a) || !ok(b)) return false;
  const diff = compareResponses(a.response!, b.response!, ctx.diffOptions);
  return !diff.statusChanged && !diff.bodyChanged;
}

function base64url(value: string): string {
  return value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
}

function decodePayload(token: string): Record<string, unknown> | undefined {
  const parts = token.split(".");
  if (parts.length < 2) return undefined;
  try {
    return JSON.parse(atob(base64url(parts[1]!)));
  } catch {
    return undefined;
  }
}

const takeoverFingerprints = [
  "NoSuchBucket",
  "There isn't a GitHub Pages site here",
  "This domain is not configured",
  "no such app",
  "Fastly error: unknown domain",
  "The specified bucket does not exist",
  "Repository not found",
  "Site not found",
  "This site is not available",
];

export const oauthRedirect: ScanCheck = {
  id: "oauth-redirect",
  name: "OAuth redirect_uri and login-chain weaknesses",
  active: true,
  perParameter: false,
  async run(ctx) {
    const detected = oauthRequest(ctx);
    if (!detected)
      return result(
        "A captured OAuth authorize request with client_id and redirect_uri is required.",
        true,
      );
    if (!ctx.stable) return result("Stable baselines required.", true);
    const { source, url, params } = detected;
    const baseline = ctx.baselines[0]!;
    const nonce = String(ctx.nonce()).replace(/[^A-Za-z0-9]/g, "");
    const attacker = `slurp-${nonce.toLowerCase()}.invalid`;
    const original = params.get("redirect_uri")!;
    let targetHost = "";
    try {
      targetHost = new URL(original, url).hostname.toLowerCase();
    } catch {
      return result("redirect_uri is not an absolute URL.", true);
    }
    const findings: ReturnType<typeof observation>["findings"] = [];
    const probe = (value: string, label: string) =>
      ctx.probe(withParam(ctx.request, source, "redirect_uri", value), label);
    const accepted = async (value: string, label: string) => {
      const candidate = await probe(value, `${label} candidate`);
      if (!ok(candidate)) return undefined;
      if (locationOf(candidate, url.href) === undefined) return undefined;
      if (!isAttacker(locationOf(candidate, url.href), attacker)) return undefined;
      const repeat = await probe(value, `${label} repeat`);
      if (!ok(repeat) || locationOf(repeat, url.href) !== locationOf(candidate, url.href))
        return undefined;
      return { candidate, repeat };
    };

    const direct = await accepted(`https://${attacker}/callback`, "OAuth redirect to attacker origin");
        if (direct) {
      findings.push(
        ...observation(
          "redirect_uri accepts an attacker-controlled origin",
          "The authorization endpoint redirected to an origin that the captured client does not own, twice and with the same destination. If the server issues codes or tokens to that redirect_uri, an attacker can receive them; no code or token was used by this check.",
          [baseline, direct.candidate, direct.repeat],
          [`redirect_uri: https://${attacker}/callback`, "Location host matched the attacker origin twice"],
          "high",
        ).findings,
      );
    } else {
      const variants: { label: string; value: string }[] = [
        { label: "userinfo prefix", value: `https://${targetHost}@${attacker}/callback` },
        { label: "host suffix", value: `https://${targetHost}.${attacker}/callback` },
        { label: "encoded userinfo", value: `https://${targetHost}%40${attacker}/callback` },
        { label: "port userinfo", value: `https://${targetHost}:443@${attacker}/callback` },
        { label: "protocol-relative", value: `//${attacker}/callback` },
        { label: "backslash prefix", value: `https://${targetHost}\\@${attacker}/callback` },
      ];
      for (const variant of variants) {
        const hit = await accepted(variant.value, `OAuth redirect_uri bypass (${variant.label})`);
        if (hit) {
          findings.push(
            ...observation(
              `redirect_uri bypass accepted: ${variant.label}`,
              "The authorization endpoint rejected a plain attacker origin but redirected to the attacker host for a crafted redirect_uri that starts with the legitimate host, twice and with the same destination. This indicates prefix or suffix validation instead of exact allowlisting; no code or token was used by this check.",
              [baseline, hit.candidate, hit.repeat],
              [`redirect_uri: ${variant.value}`, `Resolved Location host: ${attacker}`],
              "high",
            ).findings,
          );
          break;
        }
      }
    }

    if (!params.get("state")) {
      findings.push(
        ...observation(
          "OAuth authorize request omits state",
          "The captured authorization request has no state parameter. Without state the authorization response is not bound to the initiating session, which enables login CSRF and makes mix-up attacks easier when more than one identity provider is trusted. Server-side enforcement cannot be proven without a second identity provider.",
          [baseline],
          ["No state parameter in the authorize request"],
          "low",
        ).findings,
      );
    }
    const responseType = params.get("response_type") ?? "";
    if (!params.get("nonce") && /id_token|token/.test(responseType)) {
      findings.push(
        ...observation(
          "OAuth authorize request omits nonce",
          "The request can return tokens but carries no nonce. Missing nonce weakens ID-token replay and mix-up defenses; confirm whether the client validates the ID token in another way.",
          [baseline],
          [`response_type: ${responseType || "unknown"}`],
          "low",
        ).findings,
      );
    }

    const marker = `slurp-${nonce.toLowerCase()}`;
    const injected = `"><${marker}>`;
    const formRequest = withParam(
      withParam(ctx.request, source, "response_mode", "form_post"),
      source,
      "state",
      injected,
    );
    const injection = await ctx.probe(formRequest, "OAuth form_post injection probe");
    const injectionRepeat = await ctx.probe(formRequest, "OAuth form_post injection repeat");
    if (ok(injection) && ok(injectionRepeat)) {
      const body = text(injection);
      if (
        body.includes(`<${marker}>`) &&
        /<form[\s>]/i.test(body) &&
        text(injectionRepeat).includes(`<${marker}>`) &&
        !same(injection, baseline, ctx)
      ) {
        findings.push(
          ...observation(
            "OAuth form_post response reflects unescaped state",
            "With response_mode=form_post, an injected state value appeared as a raw tag in a form response twice. A raw tag in an auto-submitting form page can execute script in the identity-provider origin, where authorization codes are processed. No script was executed by this check.",
            [baseline, injection, injectionRepeat],
            [`Injected marker: <${marker}>`, "Raw tag present in a form_post HTML response twice"],
            "medium",
          ).findings,
        );
      }
    }

    let callbackHost = "";
    try {
      callbackHost = new URL(original, url).hostname.toLowerCase();
    } catch {
      callbackHost = "";
    }
    if (callbackHost && callbackHost !== url.hostname.toLowerCase()) {
      const callback = await ctx.probe(
        {
          method: "GET",
          url: `https://${callbackHost}/`,
          headers: { accept: "text/html" },
          body: "",
        },
        "OAuth callback host takeover fingerprint",
      );
      if (ok(callback)) {
        const body = text(callback);
        const fingerprint = takeoverFingerprints.find((value) => body.includes(value));
        if (fingerprint) {
          findings.push(
            ...observation(
              "OAuth callback host appears unclaimed",
              "The registered callback host returned a provider placeholder page. If that host can be claimed, authorization codes or tokens sent to it can be intercepted. Confirm the DNS/ownership state before reporting.",
              [baseline, callback],
              [`Callback host: ${callbackHost}`, `Fingerprint: ${fingerprint}`],
              "medium",
            ).findings,
          );
        }
      }
    }

    const tokenMatch = text(baseline).match(
      /"id_token"\s*:\s*"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)"/,
    );
    if (tokenMatch) {
      const payload = decodePayload(tokenMatch[1]!);
      if (
        payload &&
        typeof payload["email"] === "string" &&
        payload["email_verified"] !== true &&
        payload["email_verified"] !== "true"
      ) {
        findings.push(
          ...observation(
            "ID token carries an unverified email",
            "The captured ID token contains an email address without email_verified=true. An application that links accounts by email could let an attacker register the victim address first and inherit the account after SSO (pre-account takeover). The check did not attempt any registration.",
            [baseline],
            [`Email claim present; email_verified=${String(payload["email_verified"])}`],
            "medium",
          ).findings,
        );
      }
    }

    return {
      findings,
      message:
        "OAuth redirect_uri, state/nonce, form_post and callback controls completed. Code/token theft, two-IdP mix-up and pre-registration were not attempted.",
      inconclusive: !findings.length && !ok(baseline),
    };
  },
};

export const oauthChecks = [oauthRedirect];
