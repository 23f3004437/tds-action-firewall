from fastapi import FastAPI, Request
from html.parser import HTMLParser
import re

app = FastAPI()

TENANT = "tenant-wwf4cuv"
EMAIL_DOMAIN = "notify-j7umnh6.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


def response(reason):
    return {
        "decision": "allow" if reason == "ALLOW" else "block",
        "reason": reason,
    }


# -------------------------------------------------
# HTML safety
# -------------------------------------------------

class SafetyParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.unsafe = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()

        # scripts and iframes forbidden
        if tag in {"script", "iframe"}:
            self.unsafe = True
            return

        for name, value in attrs:
            name = name.lower()
            value = value or ""

            # inline event handlers: onclick, onload, onerror, etc.
            if name.startswith("on"):
                self.unsafe = True
                return

            # javascript: URLs
            if name in {
                "href",
                "src",
                "action",
                "formaction",
                "xlink:href",
            }:
                cleaned = value.strip().lower()

                if cleaned.startswith("javascript:"):
                    self.unsafe = True
                    return

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


def unsafe_html(html):
    parser = SafetyParser()

    try:
        parser.feed(html)
    except Exception:
        return True

    return parser.unsafe


# -------------------------------------------------
# Firewall
# -------------------------------------------------

def evaluate(data):

    # =============================================
    # 1. TOP-LEVEL SCHEMA
    # =============================================

    if not isinstance(data, dict):
        return response("INVALID_SCHEMA")

    allowed_top_keys = {
        "provenance",
        "humanApproved",
        "untrustedContent",
        "action",
    }

    required_top_keys = {
        "provenance",
        "humanApproved",
        "action",
    }

    if not required_top_keys.issubset(data.keys()):
        return response("INVALID_SCHEMA")

    if not set(data.keys()).issubset(allowed_top_keys):
        return response("INVALID_SCHEMA")

    if data["provenance"] not in {"trusted", "untrusted"}:
        return response("INVALID_SCHEMA")

    if not isinstance(data["humanApproved"], bool):
        return response("INVALID_SCHEMA")

    if "untrustedContent" in data:
        if not isinstance(data["untrustedContent"], str):
            return response("INVALID_SCHEMA")

    action = data["action"]

    if not isinstance(action, dict):
        return response("INVALID_SCHEMA")

    if set(action.keys()) != {"tool", "args"}:
        return response("INVALID_SCHEMA")

    if not isinstance(action["tool"], str):
        return response("INVALID_SCHEMA")

    # =============================================
    # 2. TOOL ALLOWLIST
    # =============================================

    tool = action["tool"]

    if tool not in ALLOWED_TOOLS:
        return response("TOOL_NOT_ALLOWED")

    args = action["args"]

    # =============================================
    # 3. SELECTED TOOL ARGUMENT SCHEMA
    # =============================================

    if not isinstance(args, dict):
        return response("INVALID_SCHEMA")

    if tool == "search":

        if set(args.keys()) != {"query"}:
            return response("INVALID_SCHEMA")

        query = args["query"]

        if not isinstance(query, str):
            return response("INVALID_SCHEMA")

        if not (1 <= len(query) <= 200):
            return response("INVALID_SCHEMA")


    elif tool == "lookup_record":

        if set(args.keys()) != {"tenantId", "recordId"}:
            return response("INVALID_SCHEMA")

        if not isinstance(args["tenantId"], str):
            return response("INVALID_SCHEMA")

        if not isinstance(args["recordId"], str):
            return response("INVALID_SCHEMA")

        if len(args["recordId"]) == 0:
            return response("INVALID_SCHEMA")


    elif tool == "send_email":

        if set(args.keys()) != {"to", "subject", "body"}:
            return response("INVALID_SCHEMA")

        if not all(
            isinstance(args[k], str)
            for k in ("to", "subject", "body")
        ):
            return response("INVALID_SCHEMA")


    elif tool == "render_html":

        if set(args.keys()) != {"html"}:
            return response("INVALID_SCHEMA")

        if not isinstance(args["html"], str):
            return response("INVALID_SCHEMA")


    # =============================================
    # 4. TENANT SCOPE
    # =============================================

    if tool == "lookup_record":
        if args["tenantId"] != TENANT:
            return response("TENANT_SCOPE")


    # =============================================
    # 5. EXACT EMAIL DOMAIN
    # =============================================

    if tool == "send_email":

        address = args["to"]

        if address.count("@") != 1:
            return response("EGRESS_DENIED")

        local, domain = address.rsplit("@", 1)

        if not local:
            return response("EGRESS_DENIED")

        if domain.lower() != EMAIL_DOMAIN.lower():
            return response("EGRESS_DENIED")


    # =============================================
    # 6. HUMAN APPROVAL
    # =============================================

    if tool == "send_email":
        if data["humanApproved"] is not True:
            return response("APPROVAL_REQUIRED")


    # -------------------------------------------------
# TERRAFORM PLAN POLICY
# -------------------------------------------------

PROD_WORKSPACE = "prod-fji7r9"

REQUIRED_LABELS = {
    "owner": "student-ig5hk",
    "environment": "production",
    "cost_center": "cc-ycfw",
}

SAFE_BACKENDS = {"gcs", "s3", "azurerm", "remote"}

PINNED_PROVIDERS = {
    "6.2.1",
    "= 6.2.1",
    "~> 6.0",
}

VALID_ACTIONS = {"create", "update", "delete"}

PROTECTED_DELETE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


def terraform_response(reason):
    return {
        "decision": "approve" if reason == "APPROVE" else "reject",
        "reason": reason,
    }


def evaluate_terraform(data):

    # =====================================================
    # 1. INVALID_PLAN
    # Check schema and shown value types first
    # =====================================================

    if not isinstance(data, dict):
        return terraform_response("INVALID_PLAN")

    if set(data.keys()) != {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }:
        return terraform_response("INVALID_PLAN")

    if not isinstance(data["environment"], str):
        return terraform_response("INVALID_PLAN")

    if not isinstance(data["providerVersion"], str):
        return terraform_response("INVALID_PLAN")

    if not isinstance(data["destroyApproved"], bool):
        return terraform_response("INVALID_PLAN")

    state = data["state"]

    if not isinstance(state, dict):
        return terraform_response("INVALID_PLAN")

    if set(state.keys()) != {"backend", "locked"}:
        return terraform_response("INVALID_PLAN")

    if not isinstance(state["backend"], str):
        return terraform_response("INVALID_PLAN")

    if not isinstance(state["locked"], bool):
        return terraform_response("INVALID_PLAN")

    resource = data["resource"]

    if not isinstance(resource, dict):
        return terraform_response("INVALID_PLAN")

    if set(resource.keys()) != {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }:
        return terraform_response("INVALID_PLAN")

    if not isinstance(resource["address"], str):
        return terraform_response("INVALID_PLAN")

    if not resource["address"]:
        return terraform_response("INVALID_PLAN")

    if not isinstance(resource["type"], str):
        return terraform_response("INVALID_PLAN")

    if not isinstance(resource["action"], str):
        return terraform_response("INVALID_PLAN")

    if resource["action"] not in VALID_ACTIONS:
        return terraform_response("INVALID_PLAN")

    if not isinstance(resource["labels"], dict):
        return terraform_response("INVALID_PLAN")

    # Every label key/value supplied must be a string
    if not all(
        isinstance(k, str) and isinstance(v, str)
        for k, v in resource["labels"].items()
    ):
        return terraform_response("INVALID_PLAN")

    secret = resource["secret"]

    if secret is not None and not isinstance(secret, str):
        return terraform_response("INVALID_PLAN")

    if not isinstance(resource["forceDestroy"], bool):
        return terraform_response("INVALID_PLAN")


    # =====================================================
    # 2. ENVIRONMENT_MISMATCH
    # =====================================================

    if data["environment"] != PROD_WORKSPACE:
        return terraform_response("ENVIRONMENT_MISMATCH")


    # =====================================================
    # 3. STATE_UNSAFE
    # =====================================================

    if (
        state["backend"] not in SAFE_BACKENDS
        or state["locked"] is not True
    ):
        return terraform_response("STATE_UNSAFE")


    # =====================================================
    # 4. UNPINNED_PROVIDER
    # =====================================================

    if data["providerVersion"] not in PINNED_PROVIDERS:
        return terraform_response("UNPINNED_PROVIDER")


    # =====================================================
    # 5. MISSING_LABELS
    # =====================================================

    labels = resource["labels"]

    for key, required_value in REQUIRED_LABELS.items():
        if labels.get(key) != required_value:
            return terraform_response("MISSING_LABELS")


    # =====================================================
    # 6. PLAINTEXT_SECRET
    # =====================================================

    if secret is not None:
        if not secret.startswith("secret://"):
            return terraform_response("PLAINTEXT_SECRET")

        # secret:// by itself is not a valid non-empty reference
        if len(secret) <= len("secret://"):
            return terraform_response("PLAINTEXT_SECRET")


    # =====================================================
    # 7. DELETE_NOT_APPROVED
    # =====================================================

    if (
        resource["action"] == "delete"
        and resource["type"] in PROTECTED_DELETE_TYPES
        and data["destroyApproved"] is not True
    ):
        return terraform_response("DELETE_NOT_APPROVED")


    # =====================================================
    # 8. FORCE_DESTROY
    # =====================================================

    if (
        resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return terraform_response("FORCE_DESTROY")


    return terraform_response("APPROVE")


@app.post("/terraform/plan")
async def terraform_plan(request: Request):

    try:
        data = await request.json()
    except Exception:
        return terraform_response("INVALID_PLAN")

    return evaluate_terraform(data)


    # =============================================
    # 7. HTML SAFETY
    # =============================================

    if tool == "render_html":
        if unsafe_html(args["html"]):
            return response("UNSAFE_OUTPUT")


    return response("ALLOW")


@app.post("/action-firewall")
async def action_firewall(request: Request):

    try:
        data = await request.json()
    except Exception:
        return response("INVALID_SCHEMA")

    return evaluate(data)


@app.get("/")
def root():
    return {"ok": True}

# -------------------------------------------------
# MODEL OUTPUT SANITIZER
# -------------------------------------------------

import re
from urllib.parse import unquote, urlsplit

SANITIZER_ALLOWED_HOSTS = {
    "cdn-bp1t5xs.example",
    "app-5z1e5jh.example",
}

SANITIZER_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}


def sanitize_response(reason):
    return {
        "safe": reason == "SAFE",
        "reason": reason,
    }


# -------------------------------------------------
# Decode exactly once:
# 1. percent escapes
# 2. specified HTML entities
# 3. \uXXXX escapes
# -------------------------------------------------

def decode_html_entities_once(text):

    named = {
        "lt": "<",
        "gt": ">",
        "quot": '"',
        "apos": "'",
        "amp": "&",
    }

    pattern = re.compile(
        r"&(?:#([0-9]+)|#x([0-9a-fA-F]+)|(lt|gt|quot|apos|amp));"
    )

    def replace(match):
        try:
            if match.group(1) is not None:
                return chr(int(match.group(1), 10))

            if match.group(2) is not None:
                return chr(int(match.group(2), 16))

            if match.group(3) is not None:
                return named[match.group(3)]

        except (ValueError, OverflowError):
            return match.group(0)

        return match.group(0)

    return pattern.sub(replace, text)


def decode_unicode_escapes_once(text):

    def replace(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)

    return re.sub(
        r"\\u([0-9a-fA-F]{4})",
        replace,
        text,
    )


def decode_once(text):
    # Required order
    result = unquote(text)
    result = decode_html_entities_once(result)
    result = decode_unicode_escapes_once(result)
    return result


# -------------------------------------------------
# URL extraction
# -------------------------------------------------

def extract_html_urls(text):
    urls = []

    pattern = re.compile(
        r"""\b(?:src|href)\s*=\s*(["'])(.*?)\1""",
        re.IGNORECASE | re.DOTALL,
    )

    for match in pattern.finditer(text):
        urls.append(match.group(2).strip())

    return urls


def extract_markdown_urls(text):
    urls = []

    # Extract target inside ](...)
    pattern = re.compile(
        r"\]\(\s*([^)]+?)\s*\)",
        re.DOTALL,
    )

    for match in pattern.finditer(text):
        target = match.group(1).strip()

        # Markdown may wrap a URL in angle brackets
        if target.startswith("<") and target.endswith(">"):
            target = target[1:-1].strip()

        urls.append(target)

    return urls


def extracted_urls(channel, text):

    if channel == "html":
        return extract_html_urls(text)

    if channel == "markdown":
        return extract_markdown_urls(text)

    if channel == "url":
        return [text.strip()]

    return []


# -------------------------------------------------
# URL policy
# -------------------------------------------------

def has_dangerous_scheme(text, urls):

    # Explicitly forbidden schemes anywhere in the text,
    # allowing whitespace immediately before ":"
    if re.search(
        r"(?:javascript|data|vbscript)\s*:",
        text,
        flags=re.IGNORECASE,
    ):
        return True

    # Extracted URLs may only use http/https when a scheme exists
    for value in urls:
        value = value.strip()

        # Protocol-relative URLs have no explicit scheme and are
        # handled by EXTERNAL_EXFIL.
        if value.startswith("//"):
            continue

        scheme_match = re.match(
            r"^([A-Za-z][A-Za-z0-9+.-]*):",
            value,
        )

        if scheme_match:
            scheme = scheme_match.group(1).lower()

            if scheme not in {"http", "https"}:
                return True

    return False


def has_external_exfil(urls):

    for value in urls:
        value = value.strip()

        # Protocol-relative reference counts as absolute.
        if value.startswith("//"):
            parsed = urlsplit("https:" + value)

            hostname = parsed.hostname

            if hostname is None:
                return True

            if hostname.lower() not in SANITIZER_ALLOWED_HOSTS:
                return True

            continue

        # Detect explicit URL schemes
        scheme_match = re.match(
            r"^([A-Za-z][A-Za-z0-9+.-]*):",
            value,
        )

        if not scheme_match:
            # Relative reference such as /local/page
            continue

        scheme = scheme_match.group(1).lower()

        # Non-http(s) schemes are handled by DANGEROUS_SCHEME,
        # so don't classify them as EXTERNAL_EXFIL here.
        if scheme not in {"http", "https"}:
            continue

        try:
            parsed = urlsplit(value)
        except ValueError:
            return True

        hostname = parsed.hostname

        if hostname is None:
            return True

        # EXACT hostname comparison: no substring or subdomain match.
        if hostname.lower() not in SANITIZER_ALLOWED_HOSTS:
            return True

    return False


# -------------------------------------------------
# Channel-specific checks
# -------------------------------------------------

def html_violation(text):

    # SCRIPT_TAG
    if re.search(
        r"<\s*(?:script|iframe|object|embed)\b",
        text,
        flags=re.IGNORECASE,
    ):
        return "SCRIPT_TAG"

    # EVENT_HANDLER
    # Look only inside HTML-looking tags.
    tags = re.findall(r"<[^>]+>", text, flags=re.DOTALL)

    for tag in tags:
        if re.search(
            r"\bon[^\s=/>]*\s*=",
            tag,
            flags=re.IGNORECASE,
        ):
            return "EVENT_HANDLER"

    urls = extract_html_urls(text)

    # DANGEROUS_SCHEME
    if has_dangerous_scheme(text, urls):
        return "DANGEROUS_SCHEME"

    # EXTERNAL_EXFIL
    if has_external_exfil(urls):
        return "EXTERNAL_EXFIL"

    return "SAFE"


def markdown_violation(text):
    urls = extract_markdown_urls(text)

    if has_dangerous_scheme(text, urls):
        return "DANGEROUS_SCHEME"

    if has_external_exfil(urls):
        return "EXTERNAL_EXFIL"

    return "SAFE"


def url_violation(text):
    urls = [text.strip()]

    if has_dangerous_scheme(text, urls):
        return "DANGEROUS_SCHEME"

    if has_external_exfil(urls):
        return "EXTERNAL_EXFIL"

    return "SAFE"


def sql_violation(text):

    # single quote or double quote or semicolon
    if "'" in text or '"' in text or ";" in text:
        return "SQL_METACHAR"

    # -- or /*
    if "--" in text or "/*" in text:
        return "SQL_METACHAR"

    # word UNION
    if re.search(r"\bunion\b", text, flags=re.IGNORECASE):
        return "SQL_METACHAR"

    # OR 1=1, allowing normal whitespace variations
    if re.search(
        r"\bor\s+1\s*=\s*1\b",
        text,
        flags=re.IGNORECASE,
    ):
        return "SQL_METACHAR"

    return "SAFE"


def shell_violation(text):

    # ; & | ` < >
    if re.search(r"[;&|`<>]", text):
        return "SHELL_METACHAR"

    # $( or ${
    if "$(" in text or "${" in text:
        return "SHELL_METACHAR"

    return "SAFE"


def channel_violation(channel, text):

    if channel == "html":
        return html_violation(text)

    if channel == "markdown":
        return markdown_violation(text)

    if channel == "url":
        return url_violation(text)

    if channel == "sql":
        return sql_violation(text)

    if channel == "shell":
        return shell_violation(text)

    return "SAFE"


# -------------------------------------------------
# Main sanitizer policy
# -------------------------------------------------

def evaluate_sanitizer(data):

    # 1. INVALID_SCHEMA
    if not isinstance(data, dict):
        return sanitize_response("INVALID_SCHEMA")

    channel = data.get("channel")
    output = data.get("output")

    if channel not in SANITIZER_CHANNELS:
        return sanitize_response("INVALID_SCHEMA")

    if not isinstance(output, str):
        return sanitize_response("INVALID_SCHEMA")

    if len(output) > 20000:
        return sanitize_response("INVALID_SCHEMA")


    # 2. ENCODED_PAYLOAD
    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = channel_violation(channel, decoded)

        if decoded_reason != "SAFE":
            return sanitize_response("ENCODED_PAYLOAD")


    # 3. Channel-specific rules on ORIGINAL output
    reason = channel_violation(channel, output)

    return sanitize_response(reason)


@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    try:
        data = await request.json()
    except Exception:
        return sanitize_response("INVALID_SCHEMA")

    return evaluate_sanitizer(data)
