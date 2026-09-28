"""Scheduling Agent class with explicit model invocation."""

import asyncio
import base64
import binascii
import re
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server


_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
_HTML_HIDDEN_RE = re.compile(
    r"<!--.*?-->|<script\b.*?>.*?</script>|<style\b.*?>.*?</style>|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0",
    re.IGNORECASE | re.DOTALL,
)
_DELIMITER_ESCAPE_RE = re.compile(r"</?(?:system|user|assistant|tool)>|```|---\s*$|===\s*$", re.IGNORECASE | re.MULTILINE)
_FAKE_SYSTEM_MESSAGE_RE = re.compile(
    r"\b(?:system message|developer message|tool message|assistant message)\s*:\s*",
    re.IGNORECASE,
)
_INSTRUCTION_OVERRIDE_RE = re.compile(
    r"\b(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+(?:all\s+)?prior\s+instructions|override\s+(?:the\s+)?(?:system|developer)\s+prompt)\b",
    re.IGNORECASE,
)
_ROLE_HIJACK_RE = re.compile(
    r"\b(?:you\s+are\s+now\s+dan|act\s+as\s+(?:an\s+)?unrestricted|pretend\s+to\s+be\s+the\s+system|you\s+are\s+no\s+longer\s+bound)\b",
    re.IGNORECASE,
)
_JAILBREAK_RE = re.compile(
    r"\b(?:dan\b|developer\s+mode|jailbreak|fictional\s+framing|unfiltered\s+mode|do\s+anything\s+now)\b",
    re.IGNORECASE,
)
_CONTEXT_POISONING_RE = re.compile(
    r"\b(?:in\s+the\s+next\s+message\s+you\s+must|for\s+the\s+rest\s+of\s+this\s+chat|from\s+now\s+on|remember\s+this\s+as\s+the\s+highest\s+priority)\b",
    re.IGNORECASE,
)
_EXFILTRATION_RE = re.compile(
    r"\b(?:send\s+(?:the\s+)?(?:system\s+prompt|secrets?|credentials?|data)\s+to\s+https?://\S+|leak\s+(?:the\s+)?system\s+prompt|markdown\s+image\s+exfiltration|exfiltrat\w+)\b",
    re.IGNORECASE,
)
_COMMAND_INJECTION_RE = re.compile(
    r"\b(?:curl\s+https?://\S+|wget\s+https?://\S+|(?:bash|sh|zsh|powershell|cmd)(?:\s+-[A-Za-z]|\s+/[A-Za-z])|os\.system\s*\(|subprocess\.(?:run|Popen|call)\s*\(|rm\s+-rf\b|chmod\s+\+x\b|python\s+-c\b|nc\s+-e\b)",
    re.IGNORECASE,
)
_SPLIT_PAYLOAD_RE = re.compile(
    r"i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s",
    re.IGNORECASE,
)
_INDIRECT_INJECTION_RE = re.compile(
    r"\b(?:metadata|comment|hidden\s+field|file\s+content|document\s+instructions?)\b.{0,80}\b(?:ignore\s+previous\s+instructions|act\s+as|system\s+prompt)\b",
    re.IGNORECASE | re.DOTALL,
)
_BASE64_TOKEN_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{24,}={0,2})\b")
_HEX_TOKEN_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){12,}\b")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
_BINARY_MARKER_RE = re.compile(r"\b(?:MZ|ELF)\b")

_LEETSPEAK_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
})


def _looks_like_base64_instruction(token: str) -> bool:
    try:
        decoded = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        decoded_text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return bool(_BINARY_MARKER_RE.search(decoded[:8].decode("latin1", errors="ignore")))
    lowered = decoded_text.lower()
    return any(
        phrase in lowered
        for phrase in (
            "ignore previous instructions",
            "forget everything above",
            "act as unrestricted",
            "you are now dan",
            "system prompt",
            "curl http",
            "wget http",
            "rm -rf",
        )
    )


def _looks_like_hex_instruction(token: str) -> bool:
    hex_text = token[2:] if token.lower().startswith("0x") else token
    try:
        decoded = bytes.fromhex(hex_text)
    except ValueError:
        return False
    try:
        decoded_text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return False
    lowered = decoded_text.lower()
    return any(
        phrase in lowered
        for phrase in (
            "ignore previous instructions",
            "forget everything above",
            "act as unrestricted",
            "you are now dan",
            "system prompt",
            "curl http",
            "wget http",
        )
    )


def _sanitize_untrusted_prompt_text(text: str) -> str:
    if not text:
        return text

    sanitized = text
    sanitized = _HTML_HIDDEN_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _DELIMITER_ESCAPE_RE.sub("<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = _FAKE_SYSTEM_MESSAGE_RE.sub("<prompt_injection_removed: fake_system_message>", sanitized)
    sanitized = _INSTRUCTION_OVERRIDE_RE.sub("<prompt_injection_removed: instruction_override>", sanitized)
    sanitized = _ROLE_HIJACK_RE.sub("<prompt_injection_removed: role_hijack>", sanitized)
    sanitized = _EXFILTRATION_RE.sub("<prompt_injection_removed: exfiltration_attempt>", sanitized)
    sanitized = _CONTEXT_POISONING_RE.sub("<prompt_injection_removed: context_poisoning>", sanitized)
    sanitized = _INDIRECT_INJECTION_RE.sub("<prompt_injection_removed: indirect_injection>", sanitized)
    sanitized = _COMMAND_INJECTION_RE.sub("<prompt_injection_removed: command_injection>", sanitized)
    sanitized = _SPLIT_PAYLOAD_RE.sub("<prompt_injection_removed: split_payload>", sanitized)
    sanitized = _JAILBREAK_RE.sub("<prompt_injection_removed: jailbreak_attempt>", sanitized)

    sanitized = _URL_ENCODED_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
    sanitized = _BASE64_TOKEN_RE.sub(
        lambda match: "<prompt_injection_removed: encoded_payload>"
        if _looks_like_base64_instruction(match.group(0))
        else match.group(0),
        sanitized,
    )
    sanitized = _HEX_TOKEN_RE.sub(
        lambda match: "<prompt_injection_removed: encoded_payload>"
        if _looks_like_hex_instruction(match.group(0))
        else match.group(0),
        sanitized,
    )

    leetspeak_normalized = sanitized.translate(_LEETSPEAK_TRANSLATION).lower()
    if any(
        phrase in leetspeak_normalized
        for phrase in (
            "ignore previous instructions",
            "forget everything above",
            "you are now dan",
            "act as unrestricted",
        )
    ):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    return sanitized


class SchedulingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon nova lite"
    BEDROCK_MODEL_ID = "amazon.nova-lite-v1:0"  # TODO: replace with an organization-approved LLM from the runtime registry/allow list.
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
        user_message = _sanitize_untrusted_prompt_text(user_message)
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
