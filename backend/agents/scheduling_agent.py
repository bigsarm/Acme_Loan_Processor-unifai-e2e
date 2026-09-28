"""Scheduling Agent class with explicit model invocation."""

import asyncio
import os
import re
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server


_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\u2060\uFEFF]")
_BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}[\s,;-]?){12,}\b")
_BINARY_RE = re.compile(r"\b[01]{32,}\b")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_SPLIT_PAYLOAD_RE = re.compile(r"(?i)\bi\W*g\W*n\W*o\W*r\W*e\W+(?:all\W+)?p\W*r\W*e\W*v\W*i\W*o\W*u\W*s\W+(?:i\W*n\W*s\W*t\W*r\W*u\W*c\W*t\W*i\W*o\W*n\W*s|d\W*i\W*r\W*e\W*c\W*t\W*i\W*o\W*n\W*s)\b")


def _contains_hidden_or_encoded_prompt(text: str) -> bool:
    if not text:
        return False
    return any(
        pattern.search(text)
        for pattern in (_ZERO_WIDTH_RE, _BASE64_RE, _HEX_RE, _BINARY_RE, _URL_ENCODED_RE, _SPLIT_PAYLOAD_RE)
    )


def _sanitize_prompt_content(text: str) -> str:
    if not text:
        return text

    sanitized = text
    replacements = [
        (re.compile(r"(?is)<!--.*?(ignore|system prompt|developer message|send data|leak|tool).*?-->"), "<prompt_injection_removed: hidden_text>"),
        (re.compile(r"(?i)\b(ignore|disregard|forget|bypass)\b.{0,80}\b(previous|prior|above|earlier)\b.{0,80}\b(instructions?|directions?|rules?|messages?)\b"), "<prompt_injection_removed: instruction_override>"),
        (re.compile(r"(?i)\b(you are now|act as|pretend to be|roleplay as)\b.{0,80}\b(dan|developer mode|unrestricted|root|system|administrator|admin)\b"), "<prompt_injection_removed: role_hijack>"),
        (re.compile(r"(?is)</?system>|</?assistant>|</?user>|</?tool>|```system|```assistant|\[/?system\]|\[/?assistant\]|\[/?tool\]"), "<prompt_injection_removed: delimiter_escape>"),
        (re.compile(r"(?i)\b(system|assistant|developer|tool)\s*:\s*"), "<prompt_injection_removed: fake_system_message> "),
        (re.compile(r"(?i)\b(send|post|upload|exfiltrate|leak|reveal|expose)\b.{0,120}\b(system prompt|secrets?|credentials?|tokens?|memory|conversation|data)\b"), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"(?i)!\[[^\]]*\]\([^\)]*(?:https?://|ftp://)[^\)]*\)"), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"(?i)\b(on the next turn|in your next response|from now on|for the rest of this chat|remember this instruction)\b"), "<prompt_injection_removed: context_poisoning>"),
        (re.compile(r"(?i)\b(file metadata|document metadata|csv field|json field|yaml field|code comment|comment says)\b.{0,120}\b(ignore|override|bypass|execute|follow these instructions)\b"), "<prompt_injection_removed: indirect_injection>"),
        (re.compile(r"(?i)\b(?:rm\s+-rf|curl\b|wget\b|powershell\b|cmd\.exe\b|bash\b|sh\b|zsh\b|python\s+-c\b|node\s+-e\b|subprocess\b|os\.system\b|exec\b|eval\b|chmod\b|chown\b|scp\b|nc\b|netcat\b)\b"), "<prompt_injection_removed: command_injection>"),
        (re.compile(r"(?i)\b(dan|developer mode|jailbreak|do anything now|fictional scenario override|unfiltered response)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
        (re.compile(r"(?i)\b[a4@]ct\s+a[s5]\b.{0,80}\b[d][a4][n]\b|\b1gn0r[e3]\b.{0,40}\bpr[e3]v[i1]ous\b"), "<prompt_injection_removed: encoded_payload>"),
    ]

    for pattern, replacement in replacements:
        sanitized = pattern.sub(replacement, sanitized)

    if _ZERO_WIDTH_RE.search(sanitized):
        sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

    if _contains_hidden_or_encoded_prompt(sanitized):
        sanitized = _BASE64_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _HEX_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _BINARY_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _URL_ENCODED_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _SPLIT_PAYLOAD_RE.sub("<prompt_injection_removed: split_payload>", sanitized)

    decoded = urllib.parse.unquote(text)
    if decoded != text and re.search(r"(?i)\b(ignore|bypass|system|developer|act as|dan|curl|wget|powershell|bash|exec|eval)\b", decoded):
        sanitized = urllib.parse.unquote(sanitized)
        sanitized = re.sub(r"(?i)\b(ignore|bypass|system|developer|act as|dan|curl|wget|powershell|bash|exec|eval)\b[^\n]*", "<prompt_injection_removed: encoded_payload>", sanitized)

    return sanitized


class SchedulingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("SCHEDULING_AGENT_MODEL_NAME", "amazon nova lite")
    # Replace with an approved registry-listed LLM via environment configuration.
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
        sanitized_user_message = _sanitize_prompt_content(user_message)
        meeting_reference = extract_reference_number(user_message, prefix="MEET")
        model_output = await self.call_agent_model(sanitized_user_message, meeting_reference)

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
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
