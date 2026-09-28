"""Scheduling Agent class with explicit model invocation."""

import asyncio
import re
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server


_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_BASE64_TOKEN_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_TOKEN_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){8,}\b")


def _replace_if_decoded_instruction(match: re.Match[str]) -> str:
    token = match.group(0)
    decoded = None
    try:
        if token.lower().startswith("0x"):
            hex_value = token[2:]
            if len(hex_value) % 2 == 0:
                decoded = bytes.fromhex(hex_value).decode("utf-8", errors="ignore")
        else:
            padding = "=" * (-len(token) % 4)
            decoded = __import__("base64").b64decode(token + padding, validate=True).decode("utf-8", errors="ignore")
    except Exception:
        return token

    if decoded and _contains_instructional_attack(decoded):
        return "<prompt_injection_removed: encoded_payload>"
    return token


def _contains_instructional_attack(text: str) -> bool:
    normalized = urllib.parse.unquote(text or "")
    compact = re.sub(r"[^a-z0-9]+", "", normalized.lower())
    suspicious_patterns = [
        r"\bignore\s+(?:all\s+)?previous\s+instructions\b",
        r"\bforget\s+everything\s+(?:above|before)\b",
        r"\byou\s+are\s+now\s+(?:dan|in\s+admin\s+mode)\b",
        r"\bact\s+as\s+(?:an\s+)?(?:unrestricted|system|developer)\b",
        r"\breveal\s+(?:the\s+)?system\s+prompt\b",
        r"\blist\s+all\s+(?:passwords|api\s+keys|secrets)\b",
        r"\bcurl\s+https?://\S+\b",
        r"\b(?:rm\s+-rf|wget\s+https?://|powershell\s+-|bash\s+-c|sh\s+-c)\b",
        r"</?(?:system|assistant|tool|user)>",
        r"<!--.*?(?:ignore|reveal|send|leak).*?-->",
    ]
    if any(re.search(pattern, normalized, flags=re.IGNORECASE | re.DOTALL) for pattern in suspicious_patterns):
        return True
    compact_triggers = [
        "ignorepreviousinstructions",
        "forgeteverythingabove",
        "youarenowdan",
        "actasunrestricted",
        "revealthesystemprompt",
        "listallpasswordsandapikeys",
    ]
    return any(trigger in compact for trigger in compact_triggers)


def _sanitize_untrusted_prompt_content(text: str) -> str:
    if not text:
        return text

    sanitized = text
    sanitized = re.sub(
        r"<!--.*?(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|reveal\s+the\s+system\s+prompt|send\s+data\s+to\s+https?://\S+).*?-->",
        "<prompt_injection_removed: hidden_text>",
        sanitized,
        flags=re.IGNORECASE | re.DOTALL,
    )
    sanitized = re.sub(
        r"<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</[^>]+>",
        "<prompt_injection_removed: hidden_text>",
        sanitized,
        flags=re.IGNORECASE | re.DOTALL,
    )
    sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(
        r"\b(?:ignore|disregard)\s+(?:all\s+)?previous\s+instructions\b|\bforget\s+everything\s+(?:above|before)\b",
        "<prompt_injection_removed: instruction_override>",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"\byou\s+are\s+now\s+(?:dan|in\s+admin\s+mode)\b|\bact\s+as\s+(?:an\s+)?(?:unrestricted\s+ai|unrestricted|developer\s+mode)\b",
        "<prompt_injection_removed: role_hijack>",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"</?(?:system|assistant|tool|user)>|(?:^|\n)\s*(?:---|===)\s*(?:$|\n)",
        "<prompt_injection_removed: delimiter_escape>",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = _BASE64_TOKEN_RE.sub(_replace_if_decoded_instruction, sanitized)
    sanitized = _HEX_TOKEN_RE.sub(_replace_if_decoded_instruction, sanitized)
    sanitized = re.sub(
        r"\b(?:system|assistant|tool)\s*:\s*(?:ignore\s+previous\s+instructions|reveal\s+the\s+system\s+prompt|send\s+data\s+to\s+https?://\S+)\b",
        "<prompt_injection_removed: fake_system_message>",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"!\[[^\]]*\]\(https?://[^)]+\)|\b(?:send|post|upload|exfiltrate|leak)\b[^\n]*\b(?:to|via)\b[^\n]*https?://\S+|\breveal\s+(?:the\s+)?system\s+prompt\b|\blist\s+all\s+(?:passwords|api\s+keys|secrets)\b",
        "<prompt_injection_removed: exfiltration_attempt>",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"\bin\s+(?:the\s+)?next\s+turn\b[^\n]*\b(?:ignore|override|instead)\b|\bfrom\s+now\s+on\b[^\n]*\b(?:ignore|only\s+follow)\b",
        "<prompt_injection_removed: context_poisoning>",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"\b(?:metadata|comment|code\s+comment|file\s+contents?)\b[^\n]*\b(?:ignore\s+previous\s+instructions|reveal\s+the\s+system\s+prompt)\b",
        "<prompt_injection_removed: indirect_injection>",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"\b(?:rm\s+-rf\s+/|curl\s+https?://\S+|wget\s+https?://\S+|bash\s+-c\s+\S+|sh\s+-c\s+\S+|powershell\s+-[A-Za-z]+\s+\S+|subprocess\.(?:run|Popen)\s*\(|os\.system\s*\(|exec\s*\(|eval\s*\()",
        "<prompt_injection_removed: command_injection>",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"(?:i\s*g\s*n\s*o\s*r\s*e\s+previous\s+instructions|y\s*o\s*u\s+a\s*r\s*e\s+n\s*o\s*w\s+d\s*a\s*n)",
        "<prompt_injection_removed: split_payload>",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"\b(?:DAN|developer\s+mode|jailbreak|bypass\s+safety|fictional\s+framing)\b",
        "<prompt_injection_removed: jailbreak_attempt>",
        sanitized,
        flags=re.IGNORECASE,
    )
    return sanitized


class SchedulingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon nova lite"
    # Must be supplied from an organization-approved model registry/configuration at deployment time.
    BEDROCK_MODEL_ID = "amazon.nova-lite-v1:0"
    DESCRIPTION = "Schedules borrower, underwriting, and support meetings."
    MCP_SERVERS = ["Google Calendar", "Email", "Slack"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Coordinate calendar events and notify the relevant teams."

    async def call_agent_model(self, user_message: str, meeting_reference: str) -> str:
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Meeting reference: {meeting_reference}\n"
                        f"Scheduling request: {user_message or 'Loan coordination meeting requested.'}\n\n"
                        "Draft a scheduling confirmation."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=180,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        user_message = _sanitize_untrusted_prompt_content(user_message)
        meeting_reference = extract_reference_number(user_message, prefix="MEET")
        model_output = await self.call_agent_model(user_message, meeting_reference)

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
            ),
        )

        response = (
            f"Meeting reference: {meeting_reference}\n"
            f"Scheduling request: {user_message or 'No scheduling request provided.'}\n\n"
            f"Scheduling summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


scheduling_agent = SchedulingAgent()
