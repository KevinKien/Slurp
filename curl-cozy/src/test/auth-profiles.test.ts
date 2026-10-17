import { describe, it, expect } from "vitest";
import {
  cookieHeader,
  receiveCookies,
  prepareProfileRequest,
  newProfile,
  validateProfiles,
} from "../lib/auth-profiles";
const url = "https://api.example.com/auth/login";
describe("profile cookie jar", () => {
  it("handles separate cookies, Expires commas, Secure and path matching", () => {
    const jar = receiveCookies(
      [],
      url,
      [
        "sid=a; Path=/; Secure; HttpOnly; Expires=Wed, 01 Jan 2031 00:00:00 GMT",
        "refresh=b; Path=/auth; Secure",
      ],
      1000,
    );
    expect(jar).toHaveLength(2);
    expect(cookieHeader(jar, url, 2000)).toBe("refresh=b; sid=a");
    expect(cookieHeader(jar, "https://api.example.com/authz", 2000)).toBe("sid=a");
    expect(cookieHeader(jar, "http://api.example.com/auth", 2000)).toBe("");
    expect(cookieHeader(jar, "https://other.example.com/auth", 2000)).toBe("");
  });
  it("accepts domain cookies only for the origin domain and rejects public/private suffixes", () => {
    const jar = receiveCookies([], url, [
      "a=1; Domain=example.com; Path=/",
      "bad=1; Domain=com",
      "bad=2; Domain=evil.com",
      "bad=3; Domain=github.io",
    ]);
    expect(jar.map((c) => c.name)).toEqual(["a"]);
    expect(cookieHeader(jar, "https://sub.example.com/")).toBe("a=1");
    expect(cookieHeader(jar, "https://evil-example.com/")).toBe("");
  });
  it("replaces, expires and removes matching cookies without affecting other paths", () => {
    let jar = receiveCookies([], url, ["sid=a; Path=/", "sid=b; Path=/auth"], 1000);
    jar = receiveCookies(jar, url, ["sid=c; Path=/"], 2000);
    expect(cookieHeader(jar, url, 3000)).toBe("sid=b; sid=c");
    jar = receiveCookies(jar, url, ["sid=deleted; Path=/; Max-Age=0"], 3000);
    expect(cookieHeader(jar, url, 4000)).toBe("sid=b");
    jar = receiveCookies(jar, url, ["short=x; Path=/; Max-Age=1"], 4000);
    expect(cookieHeader(jar, url, 6000)).toBe("sid=b");
  });
  it("enforces cookie prefixes, limits and rejects header injection", () => {
    const jar = receiveCookies([], url, [
      "__Host-a=1; Domain=example.com; Path=/; Secure",
      "__Secure-b=1; Path=/",
      "bad=x\r\nInjected: yes",
      "__Host-good=ok; Secure; Path=/",
    ]);
    expect(jar.map((c) => c.name)).toEqual(["__Host-good"]);
    expect(
      receiveCookies(
        [],
        url,
        Array.from({ length: 120 }, (_, i) => `c${i}=1; Path=/`),
      ),
    ).toHaveLength(100);
  });
});
describe("profile requests", () => {
  it("isolates origins and replaces stale account credentials", () => {
    const profile = {
      ...newProfile(),
      origins: ["https://api.example.com"],
      headers: { Authorization: "Bearer {{token}}" },
      variables: { token: "user-b" },
      cookies: receiveCookies([], url, ["sid=b; Path=/; Secure"]),
    };
    const template = {
      method: "GET",
      url,
      headers: { authorization: "Bearer user-a", cookie: "sid=a", Accept: "application/json" },
      body: "",
    };
    expect(prepareProfileRequest(template, profile, profile.variables).headers).toEqual({
      Authorization: "Bearer user-b",
      Cookie: "sid=b",
      Accept: "application/json",
    });
    expect(template.headers.authorization).toBe("Bearer user-a");
    expect(() =>
      prepareProfileRequest(
        { ...template, url: "https://evil.example/" },
        profile,
        profile.variables,
      ),
    ).toThrow("does not allow");
  });
  it("validates profile origins, headers and variable sizes", () => {
    const profile = { ...newProfile(), origins: ["https://api.example.com"] };
    expect(() => validateProfiles({ profiles: [profile], active: profile.id })).not.toThrow();
    expect(() => validateProfiles({ profiles: [{ ...profile, origins: ["http://localhost:8088", "http://192.168.1.10:3000"] }], active: profile.id })).not.toThrow();
    expect(() =>
      validateProfiles({ profiles: [{ ...profile, headers: { Cookie: "x=1" } }], active: null }),
    ).toThrow();
    expect(() =>
      validateProfiles({
        profiles: [{ ...profile, origins: ["https://api.example.com/path"] }],
        active: null,
      }),
    ).toThrow();
    expect(() =>
      validateProfiles({
        profiles: [{ ...profile, variables: { token: "x".repeat(64001) } }],
        active: null,
      }),
    ).toThrow();
  });
});
