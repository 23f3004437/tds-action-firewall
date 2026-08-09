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
