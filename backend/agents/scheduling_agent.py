"""Scheduling Agent class with explicit model invocation."""

import asyncio
import base64
import binascii
import re
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server


_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")


def _redact_zero_tolerance_pii(text: str) -> str:
    if not text:
        return text

    redacted = text
    patterns = [
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:ssn>"),
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<redacted:email>"),
        (re.compile(r"\b(?:\+?1[\s.-]*)?(?:\(\d{3}\)[\s.-]*|\d{3}[\s.-]*)\d{3}[\s.-]*\d{4}\b"), "<redacted:phone>"),
        (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<redacted:credit_card>"),
        (re.compile(r"\b(?:\d[ -]*?){9,17}\b"), "<redacted:financial_account>"),
        (re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"), "<redacted:ip_address>"),
        (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted:mac_address>"),
        (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<redacted:vin>"),
    ]
    for pattern, replacement in patterns:
        redacted = pattern.sub(replacement, redacted)

    labeled_patterns = [
        (re.compile(r"(?i)(\bDOB\s*:\s*)([^\n,;]+)"), "<redacted:year_of_birth>"),
        (re.compile(r"(?i)(\bYear of Birth\s*:\s*)([^\n,;]+)"), "<redacted:year_of_birth>"),
        (re.compile(r"(?i)(\bBirthplace\s*:\s*)([^\n,;]+)"), "<redacted:birthplace>"),
        (re.compile(r"(?i)(\bMother'?s Maiden Name\s*:\s*)([^\n,;]+)"), "<redacted:maiden_name>"),
        (re.compile(r"(?i)(\bHome Address\s*:\s*)([^\n]+)"), "<redacted:home_address>"),
        (re.compile(r"(?i)(\bAddress\s*:\s*)([^\n]+)"), "<redacted:home_address>"),
        (re.compile(r"(?i)(\bPassport(?: Number| No\.)?\s*:\s*)([^\n,;]+)"), "<redacted:passport_number>"),
        (re.compile(r"(?i)(\bDriver'?s License(?: Number)?\s*:\s*)([^\n,;]+)"), "<redacted:drivers_license>"),
        (re.compile(r"(?i)(\bTaxpayer Identification Number\s*:\s*)([^\n,;]+)"), "<redacted:tin>"),
        (re.compile(r"(?i)(\bEmployee ID\s*:\s*)([^\n,;]+)"), "<redacted:employee_id>"),
        (re.compile(r"(?i)(\bSchool ID\s*:\s*)([^\n,;]+)"), "<redacted:school_id>"),
        (re.compile(r"(?i)(\bMedical Records?\s*:\s*)([^\n]+)"), "<redacted:medical_records>"),
        (re.compile(r"(?i)(\bEthnicity\s*:\s*)([^\n,;]+)"), "<redacted:ethnicity>"),
        (re.compile(r"(?i)(\bSexual Orientation\s*:\s*)([^\n,;]+)"), "<redacted:sexual_orientation>"),
        (re.compile(r"(?i)(\bFine Location\s*:\s*)([^\n]+)"), "<redacted:fine_location>"),
        (re.compile(r"(?i)(\bFingerprints?\s*:\s*)([^\n]+)"), "<redacted:fingerprints>"),
        (re.compile(r"(?i)(\bRetina/Iris Scan\s*:\s*)([^\n]+)"), "<redacted:retina_iris_scan>"),
        (re.compile(r"(?i)(\bVoice Signature\s*:\s*)([^\n]+)"), "<redacted:voice_signature>"),
        (re.compile(r"(?i)(\bFacial Image\s*:\s*)([^\n]+)"), "<redacted:facial_image>"),
    ]
    for pattern, replacement in labeled_patterns:
        redacted = pattern.sub(lambda match: f"{match.group(1)}{replacement}", redacted)

    return redacted


def _looks_like_encoded_instruction(token: str) -> bool:
    if len(token) < 16 or len(token) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", token):
        return False
    try:
        decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError):
        return False
    lowered = decoded.lower()
    return any(
        phrase in lowered
        for phrase in (
            "ignore previous instructions",
            "forget everything above",
            "act as unrestricted",
            "you are now dan",
            "developer mode",
            "reveal system prompt",
            "curl http://",
            "curl https://",
            "wget http://",
            "wget https://",
            "rm -rf",
        )
    )


def _neutralize_prompt_injection(text: str) -> str:
    if not text:
        return text

    sanitized = text

    replacements = [
        (
            re.compile(r"(?i)\b(?:ignore previous instructions|forget everything above|disregard all prior instructions)\b"),
            "<prompt_injection_removed: instruction_override>",
        ),
        (
            re.compile(r"(?i)\b(?:you are now dan|act as unrestricted|act as an unrestricted ai|developer mode|jailbreak)\b"),
            "<prompt_injection_removed: role_hijack>",
        ),
        (
            re.compile(r"(?i)</?system>|</?assistant>|</?user>|<{3,}|>{3,}"),
            "<prompt_injection_removed: delimiter_escape>",
        ),
        (
            re.compile(r"(?is)<!--\s*(?:ignore previous instructions|forget everything above|reveal system prompt|send data to https?://.*?|curl https?://.*?)\s*-->"),
            "<prompt_injection_removed: hidden_text>",
        ),
        (
            re.compile(r"(?is)<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</[^>]+>"),
            "<prompt_injection_removed: hidden_text>",
        ),
        (
            re.compile(r"(?i)\b(?:system|assistant|tool)\s*:\s*(?:ignore previous instructions|reveal system prompt|send secrets|list all passwords and api keys)\b"),
            "<prompt_injection_removed: fake_system_message>",
        ),
        (
            re.compile(r"(?i)!\[[^\]]*\]\(https?://[^)]+\)|\b(?:send|post|exfiltrate|upload)\b[^\n]*\b(?:https?://\S+|system prompt|passwords?|api keys?|confidential information)\b|\b(?:reveal|list|leak)\b[^\n]*\b(?:system prompt|passwords?|api keys?|confidential information)\b"),
            "<prompt_injection_removed: exfiltration_attempt>",
        ),
        (
            re.compile(r"(?i)\b(?:from now on|in future responses|on the next turn|for every subsequent reply)\b[^\n]*\b(?:ignore|override|reveal|leak)\b"),
            "<prompt_injection_removed: context_poisoning>",
        ),
        (
            re.compile(r"(?i)\b(?:metadata|comment|code comment|file contents?)\b[^\n]*\b(?:ignore previous instructions|reveal system prompt|list all passwords and api keys)\b"),
            "<prompt_injection_removed: indirect_injection>",
        ),
        (
            re.compile(r"(?i)\b(?:curl|wget)\s+https?://\S+|\brm\s+-rf\b|\bsubprocess\.[A-Za-z_]+\([^\n]*\)|\bos\.system\([^\n]*\)|\beval\([^\n]*\)|\bexec\([^\n]*\)"),
            "<prompt_injection_removed: command_injection>",
        ),
        (
            re.compile(r"(?i)i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s"),
            "<prompt_injection_removed: split_payload>",
        ),
        (
            re.compile(r"(?i)\b(?:dan|do anything now|fictional framing bypass)\b[^\n]*\b(?:ignore|bypass|override)\b|\byou are now in admin mode\b"),
            "<prompt_injection_removed: jailbreak_attempt>",
        ),
    ]

    for pattern, replacement in replacements:
        sanitized = pattern.sub(replacement, sanitized)

    if _ZERO_WIDTH_RE.search(sanitized):
        compact = _ZERO_WIDTH_RE.sub("", sanitized).lower()
        if any(
            phrase in compact
            for phrase in (
                "ignorepreviousinstructions",
                "forgeteverythingabove",
                "revealsystemprompt",
            )
        ):
            sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
        else:
            sanitized = _ZERO_WIDTH_RE.sub("", sanitized)

    sanitized = re.sub(
        r"\b(?:[A-Za-z0-9+/=]{16,})\b",
        lambda match: "<prompt_injection_removed: encoded_payload>" if _looks_like_encoded_instruction(match.group(0)) else match.group(0),
        sanitized,
    )

    sanitized = re.sub(
        r"%(?:[0-9A-Fa-f]{2}){4,}",
        lambda match: "<prompt_injection_removed: encoded_payload>"
        if any(
            phrase in urllib.parse.unquote(match.group(0)).lower()
            for phrase in (
                "ignore previous instructions",
                "forget everything above",
                "reveal system prompt",
            )
        )
        else match.group(0),
        sanitized,
    )

    return sanitized


class SchedulingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon nova lite"
    BEDROCK_MODEL_ID = "amazon.nova-lite-v1:0"  # Replace with an organization-approved model from the runtime allow list/registry.
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
        user_message = _neutralize_prompt_injection(user_message)
        user_message = _redact_zero_tolerance_pii(user_message)
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

        masked_user_message = _redact_zero_tolerance_pii(user_message)
        response = (
            f"Meeting reference: {meeting_reference}\n"
            f"Scheduling request: {masked_user_message or 'No scheduling request provided.'}\n\n"
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
