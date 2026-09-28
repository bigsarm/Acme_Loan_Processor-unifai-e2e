"""Scheduling Agent class with explicit model invocation."""

import asyncio
import base64
import binascii
import re
from typing import Any
from urllib.parse import unquote

from .framework import AcmeLoanAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server


_ZERO_WIDTH_PATTERN = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
_LEETSPEAK_TRANSLATION = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _looks_like_base64(value: str) -> bool:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 16 or len(compact) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return False
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return False
    return bool(decoded)


def _sanitize_prompt_content(value: str) -> str:
    if not value:
        return value

    sanitized = value
    normalized = value.lower()
    url_decoded = unquote(value).lower()
    deobfuscated = normalized.translate(_LEETSPEAK_TRANSLATION)

    hidden_instruction_patterns = [
        (re.compile(r"<!--.*?(ignore|system prompt|developer message|act as|follow these instructions).*?-->", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
        (re.compile(r"font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*white", re.IGNORECASE), "<prompt_injection_removed: hidden_text>"),
    ]
    for pattern, replacement in hidden_instruction_patterns:
        sanitized = pattern.sub(replacement, sanitized)

    if _ZERO_WIDTH_PATTERN.search(sanitized):
        sanitized = _ZERO_WIDTH_PATTERN.sub("", sanitized)
        sanitized = "<prompt_injection_removed: hidden_text> " + sanitized

    replacement_checks = [
        (re.compile(r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|above|earlier|system|developer)\b.{0,40}\b(instruction|instructions|prompt|prompts|message|messages)\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: instruction_override>"),
        (re.compile(r"\byou are now\b|\bact as\b.{0,40}\b(unrestricted|dan|developer|system)\b|\bpretend to be\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: role_hijack>"),
        (re.compile(r"</?system>|</?assistant>|</?user>|\[/?system\]|\[/?assistant\]|\[/?user\]|```(?:system|assistant|user)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
        (re.compile(r"\b(system prompt|developer message|tool message)\b.{0,40}\b(says|said|instructs|instructed)\b|^\s*(system|assistant|tool)\s*:\s*", re.IGNORECASE | re.DOTALL | re.MULTILINE), "<prompt_injection_removed: fake_system_message>"),
        (re.compile(r"\b(send|post|upload|exfiltrate|leak|reveal|expose)\b.{0,60}\b(system prompt|secrets?|credentials?|tokens?|data)\b|!\[[^\]]*\]\([^)]*https?://[^)]*\)", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"\bfrom now on\b|\bin all future responses\b|\bfor the rest of this chat\b|\bremember this rule\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
        (re.compile(r"\b(eval|exec|__import__|subprocess|os\.system|bash\s+-c|sh\s+-c|powershell(?:\.exe)?|cmd(?:\.exe)?\s*/c|curl\b|wget\b|chmod\b|rm\s+-rf|del\s+/f|python\s+-c)\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
        (re.compile(r"\bDAN\b|\bdeveloper mode\b|\bjailbreak\b|\bno restrictions\b|\bbypass safety\b|\bfictional scenario\b.{0,40}\bignore\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: jailbreak_attempt>"),
        (re.compile(r"\b(metadata|frontmatter|yaml|json|code comment|comment field|hidden field)\b.{0,50}\b(ignore|override|instruction|prompt)\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: indirect_injection>"),
        (re.compile(r"(?:^|\n)\s*(?:ignore|reveal|bypass|run|execute)\s*(?:\n\s*){2,}(?:system|prompt|tool|shell|command)", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
    ]

    for pattern, replacement in replacement_checks:
        sanitized = pattern.sub(replacement, sanitized)

    encoded_or_obfuscated = False
    if _looks_like_base64(value) or _looks_like_base64(re.sub(r"\s+", "", value)):
        encoded_or_obfuscated = True
    if re.search(r"(?:%[0-9a-fA-F]{2}){3,}", value) or re.search(r"\\x[0-9a-fA-F]{2}", value) or re.search(r"\\u[0-9a-fA-F]{4}", value):
        encoded_or_obfuscated = True
    if re.search(r"\b[01]{8}(?:\s+[01]{8}){2,}\b", value):
        encoded_or_obfuscated = True
    if re.search(r"(?:^|\s)(?:[.-]{1,6}\s+){4,}[.-]{1,6}(?:\s|$)", value):
        encoded_or_obfuscated = True
    if any(marker in deobfuscated for marker in ("ignore previous instructions", "forget everything above", "act as unrestricted", "you are now dan")):
        encoded_or_obfuscated = True
    if any(marker in url_decoded for marker in ("ignore%20previous", "forget%20everything", "system%20prompt")):
        encoded_or_obfuscated = True
    if encoded_or_obfuscated:
        sanitized = "<prompt_injection_removed: encoded_payload>"

    return sanitized


class SchedulingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon nova lite"
    BEDROCK_MODEL_ID = "amazon.nova-lite-v1:0"  # Replace with an organization-approved model ID from runtime configuration/registry.
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
        user_message = _sanitize_prompt_content(user_message or "Loan coordination meeting requested.")
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
        user_message = _sanitize_prompt_content(user_message)
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
