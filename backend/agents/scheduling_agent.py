"""Scheduling Agent class with explicit model invocation."""

import asyncio
import base64
import binascii
import codecs
import re
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server


_PII_ADDRESS_PATTERN = re.compile(
    r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b\.?(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2}\b(?:\s+\d{5}(?:-\d{4})?)?)?(?:,\s*(?:USA|United States)\b)?"
)
_PII_PATTERNS = [
    ("ssn", re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")),
    ("phone", re.compile(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("address", _PII_ADDRESS_PATTERN),
    ("dob", re.compile(r"(?i)\b(?:DOB|date of birth|born(?: on| in)?)\s*:?\s*(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:19|20)\d{2})\b")),
    ("passport", re.compile(r"(?i)\bpassport(?:\s*(?:no\.?|number|#))?\s*:?\s*(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b")),
    ("drivers_license", re.compile(r"(?i)\b(?:driver'?s license|drivers license|dl)\s*(?:no\.?|number|#)?\s*:?\s*[A-Z0-9-]{5,20}\b")),
    ("tax_id", re.compile(r"(?i)\b(?:taxpayer identification number|tax id|tin|itin|ein)\s*:?\s*[A-Z0-9-]{6,20}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("account_number", re.compile(r"(?i)\b(?:financial account number|account number|acct(?:ount)?\s*#?)\s*:?\s*[A-Z0-9-]{6,20}\b")),
    ("employee_id", re.compile(r"(?i)\bemployee id\s*:?\s*[A-Z0-9-]{2,20}\b")),
    ("school_id", re.compile(r"(?i)\bschool id\s*:?\s*[A-Z0-9-]{2,20}\b")),
    ("vin", re.compile(r"(?i)\b(?:vehicle identification number|vin)\s*:?\s*[A-HJ-NPR-Z0-9]{17}\b")),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("mac_address", re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b")),
    ("birthplace", re.compile(r"(?i)\bbirthplace\s*:?\s*[^\n,;]+")),
    ("maiden_name", re.compile(r"(?i)\bmother'?s maiden name\s*:?\s*[^\n,;]+")),
    ("medical", re.compile(r"(?i)\bmedical records?\s*:?\s*[^\n]+")),
    ("location", re.compile(r"(?i)\b(?:fine location|location)\s*:?\s*[^\n,;]+")),
    ("ethnicity", re.compile(r"(?i)\bethnicity\s*:?\s*[^\n,;]+")),
    ("sexual_orientation", re.compile(r"(?i)\bsexual orientation\s*:?\s*[^\n,;]+")),
]
_HIDDEN_TEXT_PATTERNS = [
    re.compile(r"<!--.*?-->", re.IGNORECASE | re.DOTALL),
    re.compile(r"<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0(?:px)?|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</[^>]+>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<[^>]*class\s*=\s*[\"'][^\"']*hidden[^\"']*[\"'][^>]*>.*?</[^>]+>", re.IGNORECASE | re.DOTALL),
    re.compile(r"[\u200B-\u200D\uFEFF]+"),
]
_DIRECT_PROMPT_PATTERNS = [
    ("instruction_override", re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b")),
    ("instruction_override", re.compile(r"(?i)\bforget\s+everything\s+above\b")),
    ("instruction_override", re.compile(r"(?i)\bignore\s+(?:all\s+)?safety\s+guidelines\b")),
    ("role_hijack", re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:developer\s+mode|admin\s+mode|DAN|unrestricted)\b")),
    ("role_hijack", re.compile(r"(?i)\bprovide\s+unrestricted\s+access\b")),
    ("role_hijack", re.compile(r"(?i)\benable\s+developer\s+mode\b")),
    ("role_hijack", re.compile(r"(?i)\bact\s+as\s+an\s+unrestricted\s+AI\b")),
    ("role_hijack", re.compile(r"(?i)\bwithout\s+safety\s+filters\b")),
    ("role_hijack", re.compile(r"(?i)\bSYSTEM\s+OVERRIDE\b")),
    ("exfiltration_attempt", re.compile(r"(?i)\breveal\s+(?:all\s+)?confidential\s+information\b")),
    ("exfiltration_attempt", re.compile(r"(?i)\breveal\s+(?:all\s+)?system\s+prompts?\b")),
    ("exfiltration_attempt", re.compile(r"(?i)\blist\s+all\s+financial\s+data,\s*user\s+passwords,\s*and\s+API\s+keys\b")),
    ("exfiltration_attempt", re.compile(r"(?i)\bprint\s+the\s+API\s+key\b")),
    ("exfiltration_attempt", re.compile(r"(?i)\b(?:send|post|upload|exfiltrate)\b[^\n]{0,120}\bhttps?://\S+")),
    ("exfiltration_attempt", re.compile(r"!\[[^\]]*\]\([^)]*https?://[^)]*\)", re.IGNORECASE)),
    ("delimiter_escape", re.compile(r"(?i)</system>")),
    ("delimiter_escape", re.compile(r"<\|im_start\|>", re.IGNORECASE)),
    ("delimiter_escape", re.compile(r"(?im)^###\s*system\s*:")),
    ("command_injection", re.compile(r"(?i)\bexecute\s*:\s*[^\n]+")),
    ("command_injection", re.compile(r"(?i)\brun\s+(?:rm\s+-rf\s+/|curl\s+https?://\S+(?:\s*\|\s*(?:sh|bash))?|wget\s+https?://\S+(?:\s*\|\s*(?:sh|bash))?|print\s*\(\s*os\.environ\.get\([^\n]+\))")),
    ("command_injection", re.compile(r"(?i)\bcurl\s+https?://\S+\s*\|\s*(?:sh|bash)\b")),
]


def _replace_pattern(text: str, pattern: re.Pattern[str], replacement: str) -> str:
    return pattern.sub(replacement, text)


def _replace_pii(text: str, marker_builder) -> str:
    sanitized = text
    for category, pattern in _PII_PATTERNS:
        sanitized = pattern.sub(lambda match, category=category: marker_builder(category, match.group(0)), sanitized)
    return sanitized


def _mask_identifier(category: str, value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 4:
        return f"<masked:{category}>-{digits[-4:]}"
    return f"<masked:{category}>"


def redact_pii(text: str) -> str:
    if not text:
        return text
    return _replace_pii(text, lambda category, _value: f"<redacted:{category}>")


def mask_pii(text: str) -> str:
    if not text:
        return text

    def _mask(category: str, value: str) -> str:
        if category in {"ssn", "credit_card", "account_number", "passport", "drivers_license", "tax_id", "employee_id", "school_id", "vin"}:
            return _mask_identifier(category, value)
        return f"<masked:{category}>"

    return _replace_pii(text, _mask)


def _sanitize_direct_attacks(text: str) -> str:
    sanitized = text
    for category, pattern in _DIRECT_PROMPT_PATTERNS:
        sanitized = _replace_pattern(sanitized, pattern, f"<prompt_injection_removed: {category}>")
    return sanitized


def _sanitize_hidden_text(text: str) -> str:
    sanitized = text
    for pattern in _HIDDEN_TEXT_PATTERNS:
        sanitized = _replace_pattern(sanitized, pattern, "<prompt_injection_removed: hidden_text>")
    return sanitized


def _normalize_for_obfuscated_scan(text: str) -> tuple[str, list[int]]:
    substitutions = str.maketrans({"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t"})
    normalized_chars: list[str] = []
    index_map: list[int] = []
    pending_space = False
    for index, char in enumerate(text):
        normalized_char = char.translate(substitutions).lower()
        if normalized_char.isalnum():
            if pending_space and normalized_chars and normalized_chars[-1] != " ":
                normalized_chars.append(" ")
                index_map.append(index)
            normalized_chars.append(normalized_char)
            index_map.append(index)
            pending_space = False
        elif char.isspace():
            pending_space = True
        else:
            if pending_space and normalized_chars and normalized_chars[-1] != " ":
                normalized_chars.append(" ")
                index_map.append(index)
            normalized_chars.append(normalized_char)
            index_map.append(index)
            pending_space = False
    return "".join(normalized_chars), index_map


def _apply_span_replacements(text: str, spans: list[tuple[int, int, str]]) -> str:
    if not spans:
        return text
    spans.sort(key=lambda item: (item[0], item[1]))
    merged: list[tuple[int, int, str]] = []
    for start, end, replacement in spans:
        if not merged or start >= merged[-1][1]:
            merged.append((start, end, replacement))
    parts: list[str] = []
    last_index = 0
    for start, end, replacement in merged:
        parts.append(text[last_index:start])
        parts.append(replacement)
        last_index = end
    parts.append(text[last_index:])
    return "".join(parts)


def _sanitize_obfuscated_attacks(text: str) -> str:
    normalized_text, index_map = _normalize_for_obfuscated_scan(text)
    attack_patterns = [
        ("instruction_override", re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b")),
        ("instruction_override", re.compile(r"\bforget\s+everything\s+above\b")),
        ("instruction_override", re.compile(r"\bignore\s+(?:all\s+)?safety\s+guidelines\b")),
        ("role_hijack", re.compile(r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer\s+mode|admin\s+mode|dan|unrestricted)\b")),
        ("role_hijack", re.compile(r"\bprovide\s+unrestricted\s+access\b")),
        ("role_hijack", re.compile(r"\benable\s+developer\s+mode\b")),
        ("role_hijack", re.compile(r"\bact\s+as\s+an\s+unrestricted\s+ai\b")),
        ("role_hijack", re.compile(r"\bwithout\s+safety\s+filters\b")),
        ("role_hijack", re.compile(r"\bsystem\s+override\b")),
        ("exfiltration_attempt", re.compile(r"\breveal\s+(?:all\s+)?confidential\s+information\b")),
        ("exfiltration_attempt", re.compile(r"\breveal\s+(?:all\s+)?system\s+prompts?\b")),
        ("exfiltration_attempt", re.compile(r"\blist\s+all\s+financial\s+data\s*,\s*user\s+passwords\s*,\s*and\s+api\s+keys\b")),
        ("exfiltration_attempt", re.compile(r"\bprint\s+the\s+api\s+key\b")),
    ]
    spans: list[tuple[int, int, str]] = []
    for category, pattern in attack_patterns:
        for match in pattern.finditer(normalized_text):
            start_index = index_map[match.start()]
            end_index = index_map[match.end() - 1] + 1
            spans.append((start_index, end_index, f"<prompt_injection_removed: {category}>"))
    return _apply_span_replacements(text, spans)


def _looks_like_attack(decoded_text: str) -> str | None:
    sanitized = _sanitize_direct_attacks(decoded_text)
    if sanitized != decoded_text:
        for category, pattern in _DIRECT_PROMPT_PATTERNS:
            if pattern.search(decoded_text):
                return category
    return None


def _sanitize_encoded_payloads(text: str) -> str:
    sanitized = text
    spans: list[tuple[int, int, str]] = []
    for match in re.finditer(r"\b[A-Za-z0-9+/=]{16,}\b|(?:%[0-9A-Fa-f]{2}){4,}|\b(?:[0-9A-Fa-f]{2}){8,}\b", text):
        token = match.group(0)
        decoded_candidates: list[str] = []
        try:
            if "%" in token:
                decoded_candidates.append(urllib.parse.unquote(token))
            elif re.fullmatch(r"(?:[0-9A-Fa-f]{2}){8,}", token):
                decoded_candidates.append(bytes.fromhex(token).decode("utf-8", errors="ignore"))
            else:
                padding = "=" * (-len(token) % 4)
                decoded_candidates.append(base64.b64decode(token + padding, validate=False).decode("utf-8", errors="ignore"))
        except (ValueError, binascii.Error):
            pass
        try:
            decoded_candidates.append(codecs.decode(token, "rot13"))
        except Exception:
            pass
        category = None
        for candidate in decoded_candidates:
            detected_category = _looks_like_attack(candidate)
            if detected_category:
                category = "encoded_payload"
                break
        if category:
            spans.append((match.start(), match.end(), f"<prompt_injection_removed: {category}>"))
    sanitized = _apply_span_replacements(sanitized, spans)
    return sanitized


def sanitize_untrusted_text(text: str) -> str:
    if not text:
        return text
    sanitized = _sanitize_hidden_text(text)
    sanitized = _sanitize_encoded_payloads(sanitized)
    sanitized = _sanitize_obfuscated_attacks(sanitized)
    sanitized = _sanitize_direct_attacks(sanitized)
    return sanitized


class SchedulingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon nova lite"
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
        redacted_user_message = redact_pii(user_message)
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Meeting reference: {meeting_reference}\n"
                        f"Scheduling request: {redacted_user_message or 'Loan coordination meeting requested.'}\n\n"
                        "Draft a scheduling confirmation."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=180,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        user_message = sanitize_untrusted_text(user_message)
        meeting_reference = extract_reference_number(user_message, prefix="MEET")
        model_output = await self.call_agent_model(user_message, meeting_reference)
        model_output = mask_pii(model_output)

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
            f"Scheduling request: {mask_pii(user_message) or 'No scheduling request provided.'}\n\n"
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
