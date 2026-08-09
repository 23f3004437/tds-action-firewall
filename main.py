from fastapi import FastAPI, Request
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit
import re


app = FastAPI()


# =========================================================
# 1. ACTION FIREWALL
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
        tag = (tag or "").lower()

        if tag in {"script", "iframe"}:
            self.unsafe = True
            return

        for name, value in attrs:
            name = (name or "").lower()
            value = value or ""

            if name.startswith("on"):
                self.unsafe = True
                return

            if name in {
                "href",
                "src",
                "action",
                "formaction",
                "xlink:href",
            }:
                if re.match(
                    r"^javascript\s*:",
                    value.strip(),
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

    # 1. Top-level schema
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

    # 2. Tool allowlist
    tool = action["tool"]

    if tool not in ALLOWED_TOOLS:
        return response("TOOL_NOT_ALLOWED")

    args = action["args"]

    # 3. Tool argument schema
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

        if not args["recordId"]:
            return response("INVALID_SCHEMA")

    elif tool == "send_email":

        if set(args.keys()) != {"to", "subject", "body"}:
            return response("INVALID_SCHEMA")

        if not all(
            isinstance(args[key], str)
            for key in ("to", "subject", "body")
        ):
            return response("INVALID_SCHEMA")

    elif tool == "render_html":

        if set(args.keys()) != {"html"}:
            return response("INVALID_SCHEMA")

        if not isinstance(args["html"], str):
            return response("INVALID_SCHEMA")

    # 4. Tenant scope
    if tool == "lookup_record":
        if args["tenantId"] != TENANT:
            return response("TENANT_SCOPE")

    # 5. Email egress
    if tool == "send_email":

        address = args["to"]

        if address.count("@") != 1:
            return response("EGRESS_DENIED")

        local, domain = address.rsplit("@", 1)

        if not local:
            return response("EGRESS_DENIED")

        if domain.lower() != EMAIL_DOMAIN.lower():
            return response("EGRESS_DENIED")

    # 6. Human approval
    if tool == "send_email":
        if data["humanApproved"] is not True:
            return response("APPROVAL_REQUIRED")

    # 7. HTML safety
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
# 2. TERRAFORM PLAN POLICY
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

    # 1. INVALID_PLAN
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

    if not isinstance(resource["type"], str):
        return terraform_response("INVALID_PLAN")

    if not isinstance(resource["action"], str):
        return terraform_response("INVALID_PLAN")

    if resource["action"] not in VALID_ACTIONS:
        return terraform_response("INVALID_PLAN")

    if not isinstance(resource["labels"], dict):
        return terraform_response("INVALID_PLAN")

    if not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in resource["labels"].items()
    ):
        return terraform_response("INVALID_PLAN")

    secret = resource["secret"]

    if secret is not None and not isinstance(secret, str):
        return terraform_response("INVALID_PLAN")

    if not isinstance(resource["forceDestroy"], bool):
        return terraform_response("INVALID_PLAN")

    # 2. ENVIRONMENT_MISMATCH
    if data["environment"] != PROD_WORKSPACE:
        return terraform_response("ENVIRONMENT_MISMATCH")

    # 3. STATE_UNSAFE
    if (
        state["backend"] not in SAFE_BACKENDS
        or state["locked"] is not True
    ):
        return terraform_response("STATE_UNSAFE")

    # 4. UNPINNED_PROVIDER
    if data["providerVersion"] not in PINNED_PROVIDERS:
        return terraform_response("UNPINNED_PROVIDER")

    # 5. MISSING_LABELS
    labels = resource["labels"]

    for key, required_value in REQUIRED_LABELS.items():
        if labels.get(key) != required_value:
            return terraform_response("MISSING_LABELS")

    # 6. PLAINTEXT_SECRET
    if secret is not None:

        if not secret.startswith("secret://"):
            return terraform_response("PLAINTEXT_SECRET")

        if len(secret) <= len("secret://"):
            return terraform_response("PLAINTEXT_SECRET")

    # 7. DELETE_NOT_APPROVED
    if (
        resource["action"] == "delete"
        and resource["type"] in PROTECTED_DELETE_TYPES
        and data["destroyApproved"] is not True
    ):
        return terraform_response("DELETE_NOT_APPROVED")

    # 8. FORCE_DESTROY
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
# 3. MODEL OUTPUT SANITIZER
# =========================================================

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


# ---------------------------------------------------------
# Decode once:
# percent escapes -> HTML entities -> \uXXXX
# ---------------------------------------------------------

def decode_html_entities_once(text):

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

    result = unquote(text)
    result = decode_html_entities_once(result)
    result = decode_unicode_once(result)

    return result


# ---------------------------------------------------------
# Parse actual HTML attributes
# ---------------------------------------------------------

def parse_raw_start_tag_attributes(raw):

    attributes = []

    n = len(raw)
    i = 0

    if i < n and raw[i] == "<":
        i += 1

    while i < n and raw[i].isspace():
        i += 1

    if i < n and raw[i] == "/":
        i += 1

    # Skip tag name
    while (
        i < n
        and not raw[i].isspace()
        and raw[i] not in "/>"
    ):
        i += 1

    while i < n:

        while i < n and raw[i].isspace():
            i += 1

        if i >= n or raw[i] == ">":
            break

        if raw[i] == "/":
            i += 1
            continue

        name_start = i

        while (
            i < n
            and not raw[i].isspace()
            and raw[i] not in "=/>"
        ):
            i += 1

        if i == name_start:
            i += 1
            continue

        name = raw[name_start:i].lower()

        while i < n and raw[i].isspace():
            i += 1

        has_equals = False
        quoted = False
        value = None

        if i < n and raw[i] == "=":

            has_equals = True
            i += 1

            while i < n and raw[i].isspace():
                i += 1

            if i < n and raw[i] in {"'", '"'}:

                quoted = True
                quote = raw[i]
                i += 1

                value_start = i

                while i < n and raw[i] != quote:
                    i += 1

                value = raw[value_start:i]

                if i < n and raw[i] == quote:
                    i += 1

            else:

                value_start = i

                while (
                    i < n
                    and not raw[i].isspace()
                    and raw[i] != ">"
                ):
                    i += 1

                value = raw[value_start:i]

        attributes.append(
            {
                "name": name,
                "has_equals": has_equals,
                "quoted": quoted,
                "value": value,
            }
        )

    return attributes


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

        for attr in parse_raw_start_tag_attributes(raw):

            name = attr["name"]

            # EVENT_HANDLER requires on...=
            if (
                name.startswith("on")
                and attr["has_equals"]
            ):
                self.has_event_handler = True

            # Extract only QUOTED src/href values
            if (
                name in {"src", "href"}
                and attr["has_equals"]
                and attr["quoted"]
            ):
                self.urls.append(
                    (attr["value"] or "").strip()
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


# ---------------------------------------------------------
# Markdown URL extraction
# ---------------------------------------------------------

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

        if inside.startswith("<"):

            closing = inside.find(">")

            if closing != -1:
                target = inside[1:closing].strip()
            else:
                target = inside

        else:

            # Extract destination before optional Markdown title.
            j = 0
            nested = 0
            escaped_inner = False

            while j < len(inside):

                ch = inside[j]

                if escaped_inner:
                    escaped_inner = False

                elif ch == "\\":
                    escaped_inner = True

                elif ch == "(":
                    nested += 1

                elif ch == ")" and nested > 0:
                    nested -= 1

                elif ch.isspace() and nested == 0:
                    break

                j += 1

            target = inside[:j].strip()

        if target:
            urls.append(target)

        position = i + 1

    return urls


# ---------------------------------------------------------
# Scheme and hostname checks
# ---------------------------------------------------------

def contains_forbidden_scheme(text):

    # The prompt says the TEXT CONTAINS these schemes.
    return bool(
        re.search(
            r"(?:javascript|data|vbscript)\s*:",
            text,
            flags=re.IGNORECASE,
        )
    )


def explicit_scheme(value):

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


def has_dangerous_scheme(text, urls):

    # javascript:, data:, vbscript: anywhere in text
    if contains_forbidden_scheme(text):
        return True

    # Extracted URLs: only http/https schemes permitted
    for value in urls:

        scheme = explicit_scheme(value)

        if (
            scheme is not None
            and scheme not in {"http", "https"}
        ):
            return True

    return False


def has_external_exfil(urls):

    for value in urls:

        value = value.strip()

        # Protocol-relative is absolute
        if value.startswith("//"):

            candidate = "https:" + value

        else:

            scheme = explicit_scheme(value)

            # Relative reference
            if scheme is None:
                continue

            # Non-http/https already handled above
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

        # Exact hostname only
        if hostname.lower() not in SANITIZER_ALLOWED_HOSTS:
            return True

    return False


# ---------------------------------------------------------
# Channel rules
# ---------------------------------------------------------

def html_violation(text):

    inspector = inspect_html(text)

    # 1. SCRIPT_TAG
    if inspector.has_script_tag:
        return "SCRIPT_TAG"

    # 2. EVENT_HANDLER
    if inspector.has_event_handler:
        return "EVENT_HANDLER"

    # 3. DANGEROUS_SCHEME
    if has_dangerous_scheme(
        text,
        inspector.urls,
    ):
        return "DANGEROUS_SCHEME"

    # 4. EXTERNAL_EXFIL
    if has_external_exfil(inspector.urls):
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

    value = text.strip()
    urls = [value]

    if has_dangerous_scheme(text, urls):
        return "DANGEROUS_SCHEME"

    if has_external_exfil(urls):
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

    if re.search(r"[;&|`<>]", text):
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


# ---------------------------------------------------------
# Main sanitizer policy
# ---------------------------------------------------------

def evaluate_sanitizer(data):

    # 1. INVALID_SCHEMA
    if not isinstance(data, dict):
        return sanitize_response("INVALID_SCHEMA")

    channel = data.get("channel")
    output = data.get("output")

    # IMPORTANT:
    # Type-check before using set membership.
    # Otherwise [] / {} can cause an unhashable-type 500.
    if not isinstance(channel, str):
        return sanitize_response("INVALID_SCHEMA")

    if channel not in SANITIZER_CHANNELS:
        return sanitize_response("INVALID_SCHEMA")

    if not isinstance(output, str):
        return sanitize_response("INVALID_SCHEMA")

    if len(output) > 20000:
        return sanitize_response("INVALID_SCHEMA")

    # 2. ENCODED_PAYLOAD
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

    # 3. Rules on original output
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


# =========================================================
# 4. CORROBORATION SERVICE
# =========================================================

from datetime import datetime, timezone, timedelta


CORROBORATION_SOURCE_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan",
}


def corroboration_response(verdict, confidence, sources):
    return {
        "verdict": verdict,
        "confidence": confidence,
        "corroboratingSources": sources,
    }


def parse_timestamp(value):
    if not isinstance(value, str):
        return None

    try:
        # Support normal ISO 8601 Z timestamps
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        dt = datetime.fromisoformat(value)

        # Require a timezone-aware timestamp
        if dt.tzinfo is None:
            return None

        return dt.astimezone(timezone.utc)

    except (ValueError, TypeError, OverflowError):
        return None


def valid_corroboration_source(source):
    if not isinstance(source, dict):
        return False

    if not isinstance(source.get("id"), str):
        return False

    if not isinstance(source.get("origin"), str):
        return False

    if not isinstance(source.get("value"), str):
        return False

    if not isinstance(source.get("observedAt"), str):
        return False

    if source.get("type") not in CORROBORATION_SOURCE_TYPES:
        return False

    return True


def evaluate_corroboration(data):

    # =====================================================
    # 1. INVALID
    # =====================================================

    if not isinstance(data, dict):
        return corroboration_response(
            "invalid",
            "low",
            [],
        )

    claim = data.get("claim")

    if not isinstance(claim, dict):
        return corroboration_response(
            "invalid",
            "low",
            [],
        )

    claim_value = claim.get("value")

    if not isinstance(claim_value, str):
        return corroboration_response(
            "invalid",
            "low",
            [],
        )

    as_of = parse_timestamp(data.get("asOf"))

    if as_of is None:
        return corroboration_response(
            "invalid",
            "low",
            [],
        )

    staleness_days = data.get("stalenessDays")

    # JSON booleans are not numbers for this policy.
    if (
        isinstance(staleness_days, bool)
        or not isinstance(staleness_days, (int, float))
    ):
        return corroboration_response(
            "invalid",
            "low",
            [],
        )

    sources = data.get("sources")

    if not isinstance(sources, list):
        return corroboration_response(
            "invalid",
            "low",
            [],
        )

    # =====================================================
    # FILTER TO VALID + FRESH SOURCES
    # =====================================================

    fresh_sources = []

    max_age = timedelta(days=staleness_days)

    for source in sources:

        # Invalid sources are ignored entirely.
        if not valid_corroboration_source(source):
            continue

        observed_at = parse_timestamp(
            source["observedAt"]
        )

        # An unparseable source timestamp cannot establish freshness,
        # so this source carries no weight.
        if observed_at is None:
            continue

        age = as_of - observed_at

        # Rule:
        # Fresh when asOf - observedAt <= stalenessDays.
        #
        # Future observations therefore also satisfy the literal rule.
        if age <= max_age:
            fresh_sources.append(source)

    # =====================================================
    # 2. CONTRADICTED
    # =====================================================

    contradicting_ids = []

    for source in fresh_sources:

        if (
            source.get("authoritative") is True
            and source["value"] != claim_value
        ):
            contradicting_ids.append(
                source["id"]
            )

    if contradicting_ids:
        return corroboration_response(
            "contradicted",
            "low",
            sorted(contradicting_ids),
        )

    # =====================================================
    # 3. SUPPORTED
    # Keep only fresh sources matching the claim.
    # Reduce to one representative per origin.
    # Representative = lexicographically smallest id.
    # =====================================================

    matching_sources = [
        source
        for source in fresh_sources
        if source["value"] == claim_value
    ]

    representatives_by_origin = {}

    for source in matching_sources:

        origin = source["origin"]

        if origin not in representatives_by_origin:
            representatives_by_origin[origin] = source

        else:
            current = representatives_by_origin[origin]

            if source["id"] < current["id"]:
                representatives_by_origin[origin] = source

    representatives = list(
        representatives_by_origin.values()
    )

    if len(representatives) >= 2:

        representative_types = {
            source["type"]
            for source in representatives
        }

        if len(representative_types) >= 2:
            confidence = "high"
        else:
            confidence = "medium"

        ids = sorted(
            source["id"]
            for source in representatives
        )

        return corroboration_response(
            "supported",
            confidence,
            ids,
        )

    # =====================================================
    # 4. UNVERIFIED
    # =====================================================

    return corroboration_response(
        "unverified",
        "low",
        [],
    )


@app.post("/corroborate")
async def corroborate(request: Request):

    try:
        data = await request.json()

    except Exception:
        return corroboration_response(
            "invalid",
            "low",
            [],
        )

    return evaluate_corroboration(data)

# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/")
def root():
    return {
        "ok": True,
        "endpoints": [
            "/action-firewall",
            "/terraform/plan",
            "/sanitize-output",
        ],
        }
