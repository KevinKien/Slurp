import { getDomain } from "tldts";
import { resolveReplayRequest, type ReplayVariables } from "./replay-features";
import { validateFlowVariables, flowId } from "./flows";
import type { HttpRequest } from "./traffic";

export interface ProfileCookie {
  name: string;
  value: string;
  domain: string;
  hostOnly: boolean;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
  expires: number | null;
  created: number;
}
export interface AuthProfile {
  id: string;
  name: string;
  origins: string[];
  variables: ReplayVariables;
  headers: Record<string, string>;
  cookies: ProfileCookie[];
}
export interface ProfilesDocument {
  profiles: AuthProfile[];
  active: string | null;
}
export const emptyProfiles = (): ProfilesDocument => ({ profiles: [], active: null });
export const newProfile = (): AuthProfile => ({
  id: flowId(),
  name: "New profile",
  origins: [],
  variables: {},
  headers: {},
  cookies: [],
});
export function validateProfiles(doc: ProfilesDocument) {
  if (!doc || !Array.isArray(doc.profiles) || doc.profiles.length > 30)
    throw Error("Up to 30 profiles per workspace.");
  const ids = new Set<string>();
  for (const p of doc.profiles) {
    if (
      !p.id ||
      p.id === "@anonymous" ||
      p.id.length > 100 ||
      ids.has(p.id) ||
      !p.name?.trim() ||
      p.name.length > 200
    )
      throw Error("Profiles require unique IDs and a name.");
    ids.add(p.id);
    if (!Array.isArray(p.origins) || p.origins.length > 20)
      throw Error("Up to 20 allowed origins per profile.");
    for (const origin of p.origins) {
      const url = new URL(origin);
      if (url.origin !== origin || !["http:", "https:"].includes(url.protocol) || url.username || url.password)
        throw Error("Origins must be HTTP(S) origins, such as http://localhost:8088.");
    }
    validateFlowVariables(p.variables);
    if (
      !p.headers ||
      typeof p.headers !== "object" ||
      Array.isArray(p.headers) ||
      Object.keys(p.headers).length > 50
    )
      throw Error("Up to 50 profile headers.");
    const seen = new Set<string>();
    for (const [name, value] of Object.entries(p.headers)) {
      if (
        !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) ||
        typeof value !== "string" ||
        value.length > 8192 ||
        /[\r\n\0]/.test(value) ||
        seen.has(name.toLowerCase())
      )
        throw Error("Invalid or duplicate profile header.");
      if (/^(cookie|host|content-length|connection|transfer-encoding|proxy-.*)$/i.test(name))
        throw Error("Use the cookie jar for cookies; connection headers are not supported.");
      seen.add(name.toLowerCase());
    }
    if (
      !Array.isArray(p.cookies) ||
      p.cookies.length > 100 ||
      p.cookies.some((c) => !validCookie(c))
    )
      throw Error("Invalid cookie jar (maximum 100 cookies).");
  }
  if (doc.active !== null && !ids.has(doc.active)) throw Error("Selected profile does not exist.");
  if (new TextEncoder().encode(JSON.stringify(doc)).length > 2_000_000)
    throw Error("Profiles exceed the 2 MB workspace limit.");
}
function validCookie(c: ProfileCookie) {
  return (
    c &&
    typeof c.name === "string" &&
    /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(c.name) &&
    typeof c.value === "string" &&
    !/[\x00-\x20\x7f;,]/.test(c.value) &&
    c.name.length + c.value.length <= 4096 &&
    typeof c.domain === "string" &&
    /^[a-z0-9.-]+$/i.test(c.domain) &&
    c.domain.length <= 253 &&
    typeof c.path === "string" &&
    c.path.startsWith("/") &&
    c.path.length <= 4096 &&
    !/[\r\n\0;]/.test(c.path) &&
    typeof c.secure === "boolean" &&
    typeof c.httpOnly === "boolean" &&
    typeof c.hostOnly === "boolean" &&
    typeof c.sameSite === "string" &&
    (c.expires === null || Number.isFinite(c.expires)) &&
    Number.isFinite(c.created)
  );
}
const domainMatches = (host: string, domain: string) =>
  host === domain || host.endsWith("." + domain);
export function cookieHeader(cookies: ProfileCookie[], rawUrl: string, now = Date.now()): string {
  const url = new URL(rawUrl);
  return cookies
    .filter(
      (c) =>
        validCookie(c) &&
        (c.expires === null || c.expires > now) &&
        (!c.secure || url.protocol === "https:") &&
        (c.hostOnly ? url.hostname === c.domain : domainMatches(url.hostname, c.domain)) &&
        (url.pathname === c.path ||
          url.pathname.startsWith(c.path.endsWith("/") ? c.path : c.path + "/")),
    )
    .sort((a, b) => b.path.length - a.path.length || a.created - b.created)
    .map((c) => `${c.name}=${c.value}`)
    .join("; ");
}
export function receiveCookies(
  existing: ProfileCookie[],
  rawUrl: string,
  lines: string[],
  now = Date.now(),
): ProfileCookie[] {
  const url = new URL(rawUrl);
  let jar = existing.filter((c) => validCookie(c) && (c.expires === null || c.expires > now));
  for (const line of lines.slice(0, 100)) {
    if (line.length > 8192) continue;
    const [pair = "", ...attributes] = line.split(";");
    const equal = pair.indexOf("=");
    if (equal < 1) continue;
    const attrs = new Map(
      attributes.map((item) => {
        const at = item.indexOf("=");
        return [
          item
            .slice(0, at < 0 ? undefined : at)
            .trim()
            .toLowerCase(),
          at < 0 ? "" : item.slice(at + 1).trim(),
        ] as const;
      }),
    );
    const domain = (attrs.get("domain") ?? url.hostname).toLowerCase().replace(/^\./, "");
    const hostOnly = !attrs.has("domain");
    if (
      !domainMatches(url.hostname, domain) ||
      (!hostOnly && !getDomain(domain, { allowPrivateDomains: true }))
    )
      continue;
    const defaultPath = url.pathname.slice(0, url.pathname.lastIndexOf("/")) || "/";
    const path = attrs.get("path")?.startsWith("/") ? attrs.get("path")! : defaultPath;
    const maxAge = attrs.get("max-age");
    let expires: number | null = null;
    if (maxAge && /^-?\d+$/.test(maxAge))
      expires = Number(maxAge) <= 0 ? 0 : now + Math.min(Number(maxAge), 315360000) * 1000;
    else if (attrs.has("expires")) {
      const parsed = Date.parse(attrs.get("expires")!);
      if (Number.isFinite(parsed)) expires = parsed;
    }
    const cookie: ProfileCookie = {
      name: pair.slice(0, equal).trim(),
      value: pair.slice(equal + 1).trim(),
      domain,
      hostOnly,
      path,
      secure: attrs.has("secure"),
      httpOnly: attrs.has("httponly"),
      sameSite: attrs.get("samesite") ?? "",
      expires,
      created: now,
    };
    if (
      !validCookie(cookie) ||
      (cookie.secure && url.protocol !== "https:") ||
      (cookie.name.startsWith("__Secure-") && (!cookie.secure || url.protocol !== "https:")) ||
      (cookie.name.startsWith("__Host-") &&
        (!cookie.secure || !hostOnly || attrs.get("path") !== "/" || url.protocol !== "https:"))
    )
      continue;
    const prior = jar.find((c) => c.name === cookie.name && c.domain === domain && c.path === path);
    if (prior) cookie.created = prior.created;
    jar = jar.filter((c) => !(c.name === cookie.name && c.domain === domain && c.path === path));
    if (expires === null || expires > now) jar.push(cookie);
  }
  return jar.slice(-100);
}
export function prepareProfileRequest(
  request: HttpRequest,
  profile: AuthProfile,
  variables: ReplayVariables,
  cookies = profile.cookies,
): HttpRequest {
  const url = new URL(request.url);
  if (!profile.origins.includes(url.origin))
    throw Error(
      `Profile ${profile.name} does not allow ${url.origin}. Add this origin in Profiles.`,
    );
  const profileHeaders = resolveReplayRequest(
    { method: "GET", url: "https://example.com", body: "", headers: profile.headers },
    variables,
  ).headers;
  const names = new Set(Object.keys(profileHeaders).map((k) => k.toLowerCase()));
  const headers = Object.fromEntries(
    Object.entries(request.headers).filter(
      ([key]) => !/^(authorization|cookie)$/i.test(key) && !names.has(key.toLowerCase()),
    ),
  );
  for (const [key, value] of Object.entries(profileHeaders))
    Object.defineProperty(headers, key, {
      value,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  const cookie = cookieHeader(cookies, request.url);
  if (cookie) headers["Cookie"] = cookie;
  return { ...request, headers };
}
