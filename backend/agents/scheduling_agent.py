"""Scheduling Agent class with explicit model invocation."""

import asyncio
import base64
import os
import re
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server


_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u2060\uFEFF]")
_WHITESPACE_ONLY_RE = re.compile(r"^\s+$")


def _looks_like_base64_segment(value: str) -> bool:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 16 or len(compact) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return False
    try:
        decoded = base64.b64decode(compact, validate=True)
    except Exception:
        return False
    return any(32 <= b <= 126 for b in decoded)


def _neutralize_prompt_content(value: str) -> str:
    if not value:
        return value

    sanitized = value
    replacements = [
        (re.compile(r"(?is)<!--.*?(ignore|system prompt|instructions|override|forget).*?-->"), "<prompt_injection_removed: hidden_text>"),
        (re.compile(r"(?i)ignore\s+(all\s+)?previous\s+instructions|forget\s+everything\s+above|disregard\s+prior\s+instructions"), "<prompt_injection_removed: instruction_override>"),
        (re.compile(r"(?i)you\s+are\s+now\s+dan|act\s+as\s+unrestricted|developer\s+mode|do\s+anything\s+now"), "<prompt_injection_removed: role_hijack>"),
        (re.compile(r"(?is)</?(system|assistant|user|tool)>|```(?:system|assistant|user|tool)|---\s*(system|assistant|user|tool)\s*---"), "<prompt_injection_removed: delimiter_escape>"),
        (re.compile(r"(?i)(system\s*:)\s*(you must|ignore|override)|(tool\s*:)\s*(execute|run)|(assistant\s*:)\s*(ignore|reveal)"), "<prompt_injection_removed: fake_system_message>"),
        (re.compile(r"(?i)send\s+data\s+to\s+https?://|leak\s+the\s+system\s+prompt|exfiltrat|upload\s+secrets|markdown\s+image\s+exfil"), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"(?i)from\s+now\s+on|in\s+the\s+next\s+turn|when\s+asked\s+later|remember\s+this\s+secret|persist\s+this\s+instruction"), "<prompt_injection_removed: context_poisoning>"),
        (re.compile(r"(?i)\b(?:rm\s+-rf|curl\b|wget\b|powershell\b|bash\b|sh\b|cmd\.exe\b|python\s+-c|node\s+-e|subprocess\b|os\.system\b|eval\(|exec\()"), "<prompt_injection_removed: command_injection>"),
        (re.compile(r"(?i)jailbreak|bypass\s+safety|fictional\s+framing|stay\s+in\s+character\s+no\s+matter\s+what"), "<prompt_injection_removed: jailbreak_attempt>"),
        (re.compile(r"(?i)(?:i\s*g\s*n\s*o\s*r\s*e\s*p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s*i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s)"), "<prompt_injection_removed: split_payload>"),
    ]

    if _ZERO_WIDTH_RE.search(sanitized):
        sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

    if "%" in sanitized:
        decoded_url = urllib.parse.unquote(sanitized)
        if decoded_url != sanitized and re.search(r"(?i)ignore\s+previous|system|instructions|bash|powershell|curl|wget", decoded_url):
            sanitized = "<prompt_injection_removed: encoded_payload>"

    if _looks_like_base64_segment(sanitized):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    if re.search(r"(?i)0x[0-9a-f]{2,}|[01]{16,}|[\.-]{8,}", sanitized):
        sanitized = re.sub(r"(?i)0x[0-9a-f]{2,}|[01]{16,}|[\.-]{8,}", "<prompt_injection_removed: encoded_payload>", sanitized)

    for pattern, marker in replacements:
        sanitized = pattern.sub(marker, sanitized)

    if re.search(r"(?i)1gn0r[e3]|pr3v10us|1nstruct10ns|r0le|h1j4ck", sanitized):
        sanitized = re.sub(r"(?i)1gn0r[e3]|pr3v10us|1nstruct10ns|r0le|h1j4ck", "<prompt_injection_removed: encoded_payload>", sanitized)

    return sanitized


def _sanitize_ai_text(value: str, *, file_derived: bool = False) -> str:
    sanitized = _neutralize_prompt_content(value or "")
    if file_derived and sanitized != (value or ""):
        return "<prompt_injection_removed: indirect_injection>"
    if _WHITESPACE_ONLY_RE.fullmatch(sanitized):
        return ""
    return sanitized


class SchedulingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon nova lite"
    BEDROCK_MODEL_ID = os.getenv("SCHEDULING_AGENT_BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")
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
        user_message = _sanitize_ai_text(user_message)
        meeting_reference = _sanitize_ai_text(meeting_reference, file_derived=True)
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
        meeting_reference = extract_reference_number(user_message, prefix="MEET")
        sanitized_user_message = _sanitize_ai_text(user_message)
        sanitized_meeting_reference = _sanitize_ai_text(meeting_reference, file_derived=True)
        model_output = await self.call_agent_model(sanitized_user_message, sanitized_meeting_reference)

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {sanitized_meeting_reference}",
                    "description": sanitized_user_message or "Loan coordination meeting requested.",
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
                    "subject": f"Meeting scheduled for {sanitized_meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {sanitized_meeting_reference}.",
                },
            ),
        )

        response = (
            f"Meeting reference: {sanitized_meeting_reference}\n"
            f"Scheduling request: {sanitized_user_message or 'No scheduling request provided.'}\n\n"
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
