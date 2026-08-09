from fastapi import FastAPI, Request
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit
import re


app = FastAPI()


# =========================================================
# ACTION FIREWALL
# =========================================================

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


class SafetyParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.unsafe = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()

        # Firewall question specifically forbids scripts and iframes
        if tag in {"script", "iframe"}:
            self.unsafe = True
            return

        for name, value in attrs:
            name = (name or "").lower()
            value = value or ""

            # onclick=, onload=, onerror=, etc.
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
                cleaned = value.strip()

                if re.match(
                    r"^javascript\s*:",
                    cleaned,
                    flags=re.IGNORECASE,
                ):
                    self.unsafe = True
                    return

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


def unsafe_html(html):
    parser = SafetyParser()

    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return True

    return parser.unsafe


def evaluate(data):

    # -----------------------------------------------------
    # 1. TOP-LEVEL SCHEMA
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # 2. TOOL ALLOWLIST
    # -----------------------------------------------------

    tool = action["tool"]

    if tool not in ALLOWED_TOOLS:
        return response("TOOL_NOT_ALLOWED")

    args = action["args"]

    # -----------------------------------------------------
    # 3. TOOL ARGUMENT SCHEMA
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # 4. TENANT SCOPE
    # -----------------------------------------------------

    if tool == "lookup_record":
        if args["tenantId"] != TENANT:
            return response("TENANT_SCOPE")

    # -----------------------------------------------------
    # 5. EMAIL EGRESS
    # -----------------------------------------------------

    if tool == "send_email":

        address = args["to"]

        if address.count("@") != 1:
            return response("EGRESS_DENIED")

        local, domain = address.rsplit("@", 1)

        if not local:
            return response("EGRESS_DENIED")

        if domain.lower() != EMAIL_DOMAIN.lower():
            return response("EGRESS_DENIED")

    # -----------------------------------------------------
    # 6. HUMAN APPROVAL
    # -----------------------------------------------------

    if tool == "send_email":
        if data["humanApproved"] is not True:
            return response("APPROVAL_REQUIRED")

    # -----------------------------------------------------
    # 7. HTML SAFETY
    # -----------------------------------------------------

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


# =========================================================
# TERRAFORM PLAN POLICY
# =========================================================

PROD_WORKSPACE = "prod-fji7r9"

REQUIRED_LABELS = {
    "owner": "student-ig5hk",
    "environment": "production",
    "cost_center": "cc-ycfw",
}

SAFE_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote",
}

PINNED_PROVIDERS = {
    "6.2.1",
    "= 6.2.1",
    "~> 6.0",
}

VALID_ACTIONS = {
    "create",
    "update",
    "delete",
}

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

    # -----------------------------------------------------
    # 1. INVALID_PLAN
    # -----------------------------------------------------

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

    if set(state.keys()) != {
        "backend",
        "locked",
    }:
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

    if not isinstance(resource["type"], str):
        return terraform_response("INVALID_PLAN")

    if not isinstance(resource["action"], str):
        return terraform_response("INVALID_PLAN")

    if not isinstance(resource["labels"], dict):
        return terraform_response("INVALID_PLAN")

    if not isinstance(resource["forceDestroy"], bool):
        return terraform_response("INVALID_PLAN")

    if resource["action"] not in VALID_ACTIONS:
        return terraform_response("INVALID_PLAN")

    if not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in resource["labels"].items()
    ):
        return terraform_response("INVALID_PLAN")

    secret = resource["secret"]

    if secret is not None and not isinstance(secret, str):
        return terraform_response("INVALID_PLAN")

    # -----------------------------------------------------
    # 2. ENVIRONMENT_MISMATCH
    # -----------------------------------------------------

    if data["environment"] != PROD_WORKSPACE:
        return terraform_response("ENVIRONMENT_MISMATCH")

    # -----------------------------------------------------
    # 3. STATE_UNSAFE
    # -----------------------------------------------------

    if (
        state["backend"] not in SAFE_BACKENDS
        or state["locked"] is not True
    ):
        return terraform_response("STATE_UNSAFE")

    # -----------------------------------------------------
    # 4. UNPINNED_PROVIDER
    # -----------------------------------------------------

    if data["providerVersion"] not in PINNED_PROVIDERS:
        return terraform_response("UNPINNED_PROVIDER")

    # -----------------------------------------------------
    # 5. MISSING_LABELS
    # -----------------------------------------------------

    labels = resource["labels"]

    for key, required_value in REQUIRED_LABELS.items():

        if labels.get(key) != required_value:
            return terraform_response("MISSING_LABELS")

    # -----------------------------------------------------
    # 6. PLAINTEXT_SECRET
    # -----------------------------------------------------

    if secret is not None:

        if not secret.startswith("secret://"):
            return terraform_response("PLAINTEXT_SECRET")

        if len(secret) <= len("secret://"):
            return terraform_response("PLAINTEXT_SECRET")

    # -----------------------------------------------------
    # 7. DELETE_NOT_APPROVED
    # -----------------------------------------------------

    if (
        resource["action"] == "delete"
        and resource["type"] in PROTECTED_DELETE_TYPES
        and data["destroyApproved"] is not True
    ):
        return terraform_response("DELETE_NOT_APPROVED")

    # -----------------------------------------------------
    # 8. FORCE_DESTROY
    # -----------------------------------------------------

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


# =========================================================
# MODEL OUTPUT SANITIZER
# =========================================================

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


# =========================================================
# ONE-PASS DECODING
# percent -> HTML entities -> \uXXXX
# =========================================================

def decode_entities_once(text):

    named = {
        "lt": "<",
        "gt": ">",
        "quot": '"',
        "apos": "'",
        "amp": "&",
    }

    pattern = re.compile(
        r"&(?:#([0-9]+)|#[xX]([0-9a-fA-F]+)|(lt|gt|quot|apos|amp));"
    )

    def replace(match):

        try:
            if match.group(1) is not None:
                value = int(match.group(1), 10)

            elif match.group(2) is not None:
                value = int(match.group(2), 16)

            else:
                return named[match.group(3)]

            if 0 <= value <= 0x10FFFF:
                return chr(value)

        except (ValueError, OverflowError):
            pass

        return match.group(0)

    return pattern.sub(replace, text)


def decode_unicode_once(text):

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

    text = unquote(text)
    text = decode_entities_once(text)
    text = decode_unicode_once(text)

    return text


# =========================================================
# HTML PARSING
# =========================================================

class OutputHTMLParser(HTMLParser):

    def __init__(self):
        super().__init__(convert_charrefs=False)

        self.has_script_tag = False
        self.has_event_handler = False
        self.urls = []

    def inspect_tag(self, tag):

        tag = (tag or "").lower()

        # Opening script / iframe / object / embed
        if tag in {
            "script",
            "iframe",
            "object",
            "embed",
        }:
            self.has_script_tag = True

        raw = self.get_starttag_text() or ""

        # Exact rule is an on...= attribute.
        #
        # onclick="x"      -> dangerous
        # onload=x         -> dangerous
        # onclick          -> NOT matched
        # data-onclick="x" -> NOT matched
        if re.search(
            r"\s+on[^\s=/>]*\s*=",
            raw,
            flags=re.IGNORECASE,
        ):
            self.has_event_handler = True

        # Only QUOTED src= and href= values are extracted.
        #
        # src="..."
        # href='...'
        #
        # data-href= does not count.
        pattern = re.compile(
            r"""\s+(?:src|href)\s*=\s*(["'])(.*?)\1""",
            flags=re.IGNORECASE | re.DOTALL,
        )

        for match in pattern.finditer(raw):
            self.urls.append(
                match.group(2).strip()
            )

    def handle_starttag(self, tag, attrs):
        self.inspect_tag(tag)

    def handle_startendtag(self, tag, attrs):
        self.inspect_tag(tag)


def inspect_html(text):

    parser = OutputHTMLParser()

    try:
        parser.feed(text)
        parser.close()
    except Exception:
        pass

    return parser


# =========================================================
# MARKDOWN DESTINATION EXTRACTION
# =========================================================

def extract_markdown_urls(text):

    urls = []
    position = 0

    while True:

        start = text.find("](", position)

        if start == -1:
            break

        i = start + 2
        depth = 1
        escaped = False

        while i < len(text):

            ch = text[i]

            if escaped:
                escaped = False

            elif ch == "\\":
                escaped = True

            elif ch == "(":
                depth += 1

            elif ch == ")":
                depth -= 1

                if depth == 0:
                    break

            i += 1

        if depth != 0:
            position = start + 2
            continue

        inside = text[start + 2:i].strip()

        # Markdown <URL> destination
        if inside.startswith("<"):

            end = inside.find(">")

            if end != -1:
                destination = inside[1:end].strip()
            else:
                destination = inside

        else:
            # Destination is before an optional Markdown title.
            #
            # [x](https://host/path "title")
            #
            # Parentheses within a URL are preserved.
            j = 0
            nested = 0
            escaped2 = False

            while j < len(inside):

                ch = inside[j]

                if escaped2:
                    escaped2 = False

                elif ch == "\\":
                    escaped2 = True

                elif ch == "(":
                    nested += 1

                elif ch == ")" and nested > 0:
                    nested -= 1

                elif ch.isspace() and nested == 0:
                    break

                j += 1

            destination = inside[:j].strip()

        if destination:
            urls.append(destination)

        position = i + 1

    return urls


# =========================================================
# SCHEME / HOST CHECKS
# =========================================================

def contains_forbidden_scheme(text):

    # Treat these as actual scheme tokens rather than matching
    # the end of an unrelated word such as "metadata:".
    return bool(
        re.search(
            r"(?<![A-Za-z0-9+.-])"
            r"(?:javascript|data|vbscript)\s*:",
            text,
            flags=re.IGNORECASE,
        )
    )


def get_explicit_scheme(value):

    value = value.strip()

    if value.startswith("//"):
        return None

    match = re.match(
        r"^([A-Za-z][A-Za-z0-9+.-]*):",
        value,
    )

    if not match:
        return None

    return match.group(1).lower()


def dangerous_scheme(text, urls):

    # javascript:, data:, vbscript: anywhere in text
    if contains_forbidden_scheme(text):
        return True

    # Any extracted explicit scheme other than http/https
    for value in urls:

        scheme = get_explicit_scheme(value)

        if (
            scheme is not None
            and scheme not in {"http", "https"}
        ):
            return True

    return False


def external_exfil(urls):

    for value in urls:

        value = value.strip()

        # //host/path is absolute, interpreted as https
        if value.startswith("//"):

            candidate = "https:" + value

        else:

            scheme = get_explicit_scheme(value)

            # Relative reference
            if scheme is None:
                continue

            # Other schemes already handled by DANGEROUS_SCHEME
            if scheme not in {"http", "https"}:
                continue

            candidate = value

        try:
            parsed = urlsplit(candidate)
            hostname = parsed.hostname

        except Exception:
            return True

        if hostname is None:
            return True

        # EXACT hostname comparison.
        if hostname.lower() not in SANITIZER_ALLOWED_HOSTS:
            return True

    return False


# =========================================================
# CHANNEL RULES
# =========================================================

def html_violation(text):

    parser = inspect_html(text)

    # 1. SCRIPT_TAG
    if parser.has_script_tag:
        return "SCRIPT_TAG"

    # 2. EVENT_HANDLER
    if parser.has_event_handler:
        return "EVENT_HANDLER"

    # 3. DANGEROUS_SCHEME
    if dangerous_scheme(
        text,
        parser.urls,
    ):
        return "DANGEROUS_SCHEME"

    # 4. EXTERNAL_EXFIL
    if external_exfil(parser.urls):
        return "EXTERNAL_EXFIL"

    return "SAFE"


def markdown_violation(text):

    urls = extract_markdown_urls(text)

    # 1. DANGEROUS_SCHEME
    if dangerous_scheme(text, urls):
        return "DANGEROUS_SCHEME"

    # 2. EXTERNAL_EXFIL
    if external_exfil(urls):
        return "EXTERNAL_EXFIL"

    return "SAFE"


def url_violation(text):

    urls = [text.strip()]

    # 1. DANGEROUS_SCHEME
    if dangerous_scheme(text, urls):
        return "DANGEROUS_SCHEME"

    # 2. EXTERNAL_EXFIL
    if external_exfil(urls):
        return "EXTERNAL_EXFIL"

    return "SAFE"


def sql_violation(text):

    if "'" in text:
        return "SQL_METACHAR"

    if '"' in text:
        return "SQL_METACHAR"

    if ";" in text:
        return "SQL_METACHAR"

    if "--" in text:
        return "SQL_METACHAR"

    if "/*" in text:
        return "SQL_METACHAR"

    if re.search(
        r"\bunion\b",
        text,
        flags=re.IGNORECASE,
    ):
        return "SQL_METACHAR"

    if re.search(
        r"\bor\s+1\s*=\s*1\b",
        text,
        flags=re.IGNORECASE,
    ):
        return "SQL_METACHAR"

    return "SAFE"


def shell_violation(text):

    if re.search(
        r"[;&|`<>]",
        text,
    ):
        return "SHELL_METACHAR"

    if "$(" in text:
        return "SHELL_METACHAR"

    if "${" in text:
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


# =========================================================
# MAIN SANITIZER
# =========================================================

def evaluate_sanitizer(data):

    # -----------------------------------------------------
    # 1. INVALID_SCHEMA
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # 2. ENCODED_PAYLOAD
    # -----------------------------------------------------

    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = channel_violation(
            channel,
            decoded,
        )

        if decoded_reason != "SAFE":
            return sanitize_response(
                "ENCODED_PAYLOAD"
            )

    # -----------------------------------------------------
    # 3. ORIGINAL STRING
    # -----------------------------------------------------

    reason = channel_violation(
        channel,
        output,
    )

    return sanitize_response(reason)


@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    try:
        data = await request.json()

    except Exception:
        return sanitize_response(
            "INVALID_SCHEMA"
        )

    return evaluate_sanitizer(data)
