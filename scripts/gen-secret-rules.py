#!/usr/bin/env python3
"""Generate crates/web-server/src/secret_rules.rs from gitleaks' default config.

    curl -fsSL -o /tmp/gitleaks.toml https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
    python3.11+ scripts/gen-secret-rules.py /tmp/gitleaks.toml > crates/web-server/src/secret_rules.rs

Rules in gitleaks (MIT licence, https://github.com/gitleaks/gitleaks) come in two shapes:
  * standalone token formats (a distinctive prefix/structure) -> matched against the value alone;
  * "semi generic" rules: keyword identifiers + a secret pattern -> matched when the variable name
    contains an identifier and the value matches the pattern.
Rules that need file/command context, are purely entropy based, or are already covered by
js_audit.rs are skipped.
"""
import re
import sys
import tomllib

SKIP = {
    "generic-api-key", "jwt", "jwt-base64", "private-key", "pkcs12-file", "curl-auth-header",
    "curl-auth-user", "kubernetes-secret-yaml", "nuget-config-password", "freemius-secret-key",
    "sourcegraph-access-token", "sidekiq-secret", "sidekiq-sensitive-url",
}
# Identifiers/public keys: not secrets on their own.
SKIP_SUFFIX = ("-client-id", "-access-id", "-user-api-id", "-pub-key", "-pub-api-key")
WORDS = {
    "api": "API", "pat": "PAT", "aws": "AWS", "gcp": "GCP", "id": "ID", "url": "URL", "ad": "AD",
    "ca": "CA", "cicd": "CI/CD", "tf": "Terraform", "rrt": "runner registration token",
    "ptt": "pipeline trigger token", "scim": "SCIM", "oauth": "OAuth", "npm": "npm",
    "pypi": "PyPI", "jfrog": "JFrog", "sendinblue": "Brevo (Sendinblue)", "hubspot": "HubSpot",
    "github": "GitHub", "gitlab": "GitLab", "digitalocean": "DigitalOcean", "openai": "OpenAI",
    "planetscale": "PlanetScale", "huggingface": "Hugging Face", "linkedin": "LinkedIn",
    "sonar": "SonarQube", "newrelic": "New Relic", "new": "New", "ci": "CI", "cd": "CD",
    "droneci": "Drone CI", "travisci": "Travis CI", "flyio": "Fly.io", "mailchimp": "Mailchimp",
    "messagebird": "MessageBird", "launchdarkly": "LaunchDarkly", "rapidapi": "RapidAPI",
    "nytimes": "NYTimes", "gocardless": "GoCardless", "easypost": "EasyPost", "privateai": "Private AI",
    "1password": "1Password", "fcm": "FCM", "sas": "SAS", "xai": "xAI", "ifttt": "IFTTT",
    "circleci": "CircleCI", "sonarqube": "SonarQube", "pat": "PAT", "db": "Database", "aws": "AWS",
    "onesignal": "OneSignal", "dropbox": "Dropbox", "pinecone": "Pinecone", "paypal": "PayPal",
    "1password": "1Password", "kucoin": "KuCoin", "okta": "Okta", "pulumi": "Pulumi",
}
# Context rules whose identifier syntax the parser below cannot read, transcribed by hand.
MANUAL = [
    ("okta-access-token", ["okta"], r"00[\w=\-]{40}", []),
    ("mailchimp-api-key", ["mailchimp"], r"[a-f0-9]{32}-us\d\d", []),
    ("snyk-api-token", ["snykkey", "snyktoken", "snykapikey", "snykapitoken", "snykoauthkey", "snykoauthtoken"],
     r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", []),
    ("atlassian-api-token", ["atlassian", "confluence", "jira"], r"[a-z0-9]{20}[a-f0-9]{4}", []),
    ("atlassian-api-token-v2", [], r"\bATATT3[A-Za-z0-9_\-=]{186}", ["atatt3"]),
]
# Providers gitleaks does not cover as standalone formats: (id, pattern, lowercase keywords).
EXTRA = [
    ("google-oauth-access-token", r"\bya29\.[0-9A-Za-z_-]{30,}", ["ya29."]),
    ("google-oauth-refresh-token", r"\b1//0[0-9A-Za-z_-]{40,}", ["1//0"]),
    ("google-oauth-client-secret", r"\bGOCSPX-[0-9A-Za-z_-]{28}", ["gocspx-"]),
    ("google-service-account-key", r"\\?\"type\\?\"\s*:\s*\\?\"service_account\\?\"", ["service_account"]),
    ("firebase-fcm-server-key", r"\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}", ["apa91b"]),
    ("aws-session-token", r"\b(?:FwoGZXIvYXdz|IQoJb3JpZ2luX2Vj)[A-Za-z0-9+/=]{100,}", ["fwogzxivyxdz", "iqojb3jpz2lux2vj"]),
    ("azure-storage-account-key", r"AccountKey=[A-Za-z0-9+/]{86}==", ["accountkey="]),
    ("azure-shared-access-key", r"SharedAccessKey=[A-Za-z0-9+/]{43}=", ["sharedaccesskey="]),
    ("azure-sas-token", r"[?&]sv=\d{4}-\d{2}-\d{2}&[^\s'\"]{0,300}[?&]sig=[A-Za-z0-9%+/=]{30,}", ["sig="]),
    ("tencent-cloud-secret-id", r"\bAKID[A-Za-z0-9]{32}\b", ["akid"]),
    ("supabase-access-token", r"\bsbp_[0-9a-f]{40}\b", ["sbp_"]),
    ("neon-api-key", r"\bnapi_[a-z0-9]{50,}\b", ["napi_"]),
    ("render-api-key", r"\brnd_[A-Za-z0-9]{32}\b", ["rnd_"]),
    ("netlify-personal-access-token", r"\bnfp_[A-Za-z0-9]{36}\b", ["nfp_"]),
    ("doppler-token", r"\bdp\.(?:st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}", ["dp."]),
    ("docker-hub-pat", r"\bdckr_pat_[A-Za-z0-9_-]{27,}", ["dckr_pat_"]),
    ("bitbucket-app-token", r"\bATBB[A-Za-z0-9_=.-]{32,}", ["atbb"]),
    ("circleci-personal-token", r"\bCCIPAT_[A-Za-z0-9]{12}_[0-9a-f]{40}\b", ["ccipat_"]),
    ("buildkite-agent-token", r"\bbkua_[0-9a-f]{40}\b", ["bkua_"]),
    ("sonarqube-token", r"\bsq[pua]_[0-9a-f]{40}\b", ["sqp_", "squ_", "sqa_"]),
    ("new-relic-user-key", r"\bNR(?:AK|II)-[A-Z0-9]{27}\b", ["nrak-", "nrii-"]),
    ("new-relic-browser-key", r"\bNRJS-[a-f0-9]{19}\b", ["nrjs-"]),
    ("contentful-management-token", r"\bCFPAT-[A-Za-z0-9_-]{43}\b", ["cfpat-"]),
    ("hubspot-private-app-token", r"\bpat-(?:na|eu)\d-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", ["pat-na", "pat-eu"]),
    ("figma-personal-token", r"\bfigd_[A-Za-z0-9_-]{40}\b", ["figd_"]),
    ("dropbox-access-token", r"\bsl\.[A-Za-z0-9_-]{130,}", ["sl."]),
    ("zoho-oauth-token", r"\b1000\.[0-9a-f]{32}\.[0-9a-f]{32}\b", ["1000."]),
    ("pinterest-access-token", r"\bpina_[A-Za-z0-9]{20,}", ["pina_"]),
    ("pinecone-api-key", r"\bpcsk_[A-Za-z0-9]{5,10}_[A-Za-z0-9]{50,}", ["pcsk_"]),
    ("twitter-bearer-token", r"\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,}", ["aaaaaaaaaaaaaaaaaaaaa"]),
    ("cloudinary-url", r"cloudinary://\d{10,}:[A-Za-z0-9_-]{20,}@[A-Za-z0-9_-]+", ["cloudinary://"]),
    ("crates-io-token", r"\bcio[A-Za-z0-9]{32}\b", ["cio"]),
    ("nuget-api-key", r"\boy2[a-z0-9]{43}\b", ["oy2"]),
    ("openai-legacy-api-key", r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b", ["t3blbkfj"]),
    ("openai-project-api-key", r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}", ["sk-proj-", "sk-svcacct-", "sk-admin-"]),
    ("anthropic-api-key-loose", r"\bsk-ant-(?:api|admin)\d\d-[A-Za-z0-9_-]{80,}", ["sk-ant-"]),
    ("groq-api-key", r"\bgsk_[A-Za-z0-9]{52}\b", ["gsk_"]),
    ("xai-api-key", r"\bxai-[A-Za-z0-9]{80}\b", ["xai-"]),
    ("replicate-api-token", r"\br8_[A-Za-z0-9]{37}\b", ["r8_"]),
    ("resend-api-key", r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24,32}\b", ["re_"]),
    ("onesignal-rest-key", r"\bos_v2_(?:app|org)_[a-z0-9]{40,}", ["os_v2_"]),
    ("telnyx-api-key", r"\bKEY[0-9A-F]{26,}_[A-Za-z0-9]{20,}\b", ["key"]),
    ("mailgun-private-key", r"\bkey-[0-9a-f]{32}\b", ["key-"]),
    ("discord-bot-token", r"^[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}$", []),
    ("discord-webhook-url", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,}", ["/api/webhooks/"]),
    ("telegram-bot-token", r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b", [":aa"]),
    ("ifttt-webhook-key", r"maker\.ifttt\.com/use/[A-Za-z0-9_-]{20,}", ["maker.ifttt.com"]),
    ("zapier-webhook-url", r"hooks\.zapier\.com/hooks/catch/\d+/[a-z0-9]+", ["hooks.zapier.com"]),
    ("mapbox-secret-token", r"\bsk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", ["sk.eyj"]),
    ("stripe-webhook-secret", r"\bwhsec_[A-Za-z0-9]{32,}", ["whsec_"]),
    ("stripe-publishable-key", r"\bpk_(?:live|test)_[A-Za-z0-9]{24,}", ["pk_live_", "pk_test_"]),
    ("flutterwave-live-secret-key", r"\bFLWSECK-[0-9a-f]{32}-X\b", ["flwseck-"]),
    ("braintree-access-token", r"\baccess_token\$(?:production|sandbox)\$[0-9a-z]{16}\$[0-9a-f]{32}", ["access_token$"]),
    ("square-oauth-secret", r"\bsq0csp-[0-9A-Za-z_-]{43}\b", ["sq0csp-"]),
    ("intercom-access-token", r"\bdG9rOi[A-Za-z0-9+/=]{40,}", ["dg9roi"]),
    ("database-connection-string", r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://[^\s:/@'\"<>]{1,64}:[^\s@'\"<>/]{3,128}@[A-Za-z0-9._-]+", ["postgres://", "postgresql://", "mysql://", "mariadb://", "mongodb://", "mongodb+srv://", "redis://", "rediss://", "amqp://", "amqps://"]),
]
TAIL = r"""(?:[\x60'"\s;]|\\[nr]|$)"""


def kind(rule_id):
    return " ".join(WORDS.get(p, p.capitalize()) for p in rule_id.split("-"))


def unbounded(regex):
    """Large counted repetitions blow up the NFA; `{n,}` is equivalent for matching purposes."""
    return re.sub(r"\{(\d+),(\d{3,})\}", r"{\1,}", regex)


def rs(text):
    """Rust raw string literal."""
    for n in range(1, 8):
        h = "#" * n
        if f'"{h}' not in text:
            return f'r{h}"{text}"{h}'
    raise ValueError(text)


def keyed(regex):
    m = re.match(r"^\(\?i\)\[\\w\.-\]\{0,50\}\?\(\?:(.+?)\)\(\?:\[ \\t\\w\.-\]\{0,20\}\)", regex)
    t = re.search(r"\(([^()]*(?:\([^()]*\)[^()]*)*)\)" + re.escape(TAIL) + "$", regex)
    if not m or not t or "[\\x60'\"\\s=]{0,5}" not in regex:
        return None
    ids = [i for i in m.group(1).split("|") if i]
    if any(re.search(r"[^a-z0-9_-]", i) for i in ids):
        return None
    return sorted({i.replace("_", "").replace("-", "") for i in ids}), t.group(1)


def main(path):
    rules = tomllib.load(open(path, "rb"))["rules"]
    out = []
    for r in rules:
        rid, rx = r["id"], r.get("regex")
        if not rx or rid in SKIP or rid.endswith(SKIP_SUFFIX):
            continue
        keywords = sorted({k.lower() for k in r.get("keywords", [])})
        if "[\\w.-]{0,50}?" in rx:
            parsed = keyed(rx)
            if not parsed:
                if rid not in {m[0] for m in MANUAL}:
                    print(f"skipped (unparsed context rule): {rid}", file=sys.stderr)
                continue
            ids, secret = parsed
            out.append((rid, kind(rid), "(?i)^(?:" + secret + ")$", ids, []))
        else:
            out.append((rid, kind(rid), rx, [], keywords))
    for rid, pattern, kw in EXTRA:
        out.append((rid, kind(rid), pattern, [], sorted(kw)))
    for rid, ids, secret, kw in MANUAL:
        out.append((rid, kind(rid), ("(?i)^(?:" + secret + ")$") if ids else secret, ids, kw))
    print("//! Generated by scripts/gen-secret-rules.py from the gitleaks default configuration")
    print("//! (https://github.com/gitleaks/gitleaks, MIT licence). Do not edit by hand.")
    print("//!")
    print("//! `keys` empty: standalone token format, pre-filtered by `keywords`.")
    print("//! `keys` set: matches only when the (normalised) variable name contains one of them.")
    print("pub struct SecretRule {")
    print("    pub id: &'static str,")
    print("    pub kind: &'static str,")
    print("    pub pattern: &'static str,")
    print("    pub keys: &'static [&'static str],")
    print("    pub keywords: &'static [&'static str],")
    print("}")
    print(f"pub const SECRET_RULES: [SecretRule; {len(out)}] = [")
    for rid, k, rx, ids, kw in out:
        ids_s = ", ".join(rs(i) for i in ids)
        kw_s = ", ".join(rs(i) for i in kw)
        print(f"    SecretRule {{ id: {rs(rid)}, kind: {rs(k)}, pattern: {rs(unbounded(rx))}, keys: &[{ids_s}], keywords: &[{kw_s}] }},")
    print("];")


main(sys.argv[1])
