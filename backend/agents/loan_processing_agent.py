"""Loan Processing Agent class with explicit model invocation."""

import asyncio
import os
import re
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary, extract_reference_number
from .mcp_servers import call_mcp_server

_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u2060\uFEFF]")
_BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b")
_HEX_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){8,}\b")
_BINARY_HINT_RE = re.compile(r"\b(?:MZ|ELF|PK\x03\x04)\b")
_SPLIT_PAYLOAD_RE = re.compile(r"\b(?:i\W*g\W*n\W*o\W*r\W*e|d\W*a\W*n)\b", re.IGNORECASE)
_URL_ENCODED_INSTRUCTION_RE = re.compile(r"%(?:[0-9a-fA-F]{2})")


def _replace_case_insensitive(text: str, pattern: str, replacement: str) -> str:
    return re.sub(pattern, replacement, text, flags=re.IGNORECASE)


def _neutralize_prompt_injection(text: str) -> str:
    if not text:
        return text

    sanitized = text
    sanitized = re.sub(r"<!--.*?-->", "<prompt_injection_removed: hidden_text>", sanitized, flags=re.DOTALL)
    sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"<\s*/?\s*(?:system|assistant|tool|developer)\s*>", "<prompt_injection_removed: delimiter_escape>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"(?:^|\n)\s*(?:system|assistant|tool|developer)\s*:\s*", "\n<prompt_injection_removed: fake_system_message>", sanitized, flags=re.IGNORECASE)
    sanitized = _replace_case_insensitive(sanitized, r"ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+all\s+prior\s+instructions|override\s+system\s+prompt", "<prompt_injection_removed: instruction_override>")
    sanitized = _replace_case_insensitive(sanitized, r"you\s+are\s+now\s+DAN|act\s+as\s+unrestricted|act\s+as\s+developer\s+mode|roleplay\s+as\s+system", "<prompt_injection_removed: role_hijack>")
    sanitized = _replace_case_insensitive(sanitized, r"developer\s+mode|jailbreak|do\s+anything\s+now|fictional\s+framing\s+bypass", "<prompt_injection_removed: jailbreak_attempt>")
    sanitized = _replace_case_insensitive(sanitized, r"send\s+data\s+to\s+https?://\S+|leak\s+the\s+system\s+prompt|exfiltrate|markdown\s+image\s+exfil", "<prompt_injection_removed: exfiltration_attempt>")
    sanitized = _replace_case_insensitive(sanitized, r"in\s+the\s+next\s+turn|when\s+asked\s+later|remember\s+this\s+for\s+future\s+steps", "<prompt_injection_removed: context_poisoning>")
    sanitized = _replace_case_insensitive(sanitized, r"(?:^|\n)\s*(?:#|//|/\*|\*)\s*(?:ignore|system|assistant|developer|tool)\b.*", "<prompt_injection_removed: indirect_injection>")
    sanitized = _replace_case_insensitive(sanitized, r"\b(?:rm\s+-rf|curl\s+|wget\s+|powershell\b|bash\b|sh\b|cmd\.exe\b|subprocess\b|os\.system\b|eval\b|exec\b)\b", "<prompt_injection_removed: command_injection>")
    sanitized = _BASE64_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
    sanitized = _HEX_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
    sanitized = _BINARY_HINT_RE.sub("<prompt_injection_removed: command_injection>", sanitized)
    sanitized = _URL_ENCODED_INSTRUCTION_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
    sanitized = _SPLIT_PAYLOAD_RE.sub("<prompt_injection_removed: split_payload>", sanitized)
    return sanitized


def _contains_suspicious_prompt_content(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    leetspeak_normalized = lowered.translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}))
    decoded_once = urllib.parse.unquote(text)
    suspicious_markers = [
        "ignore previous instructions",
        "forget everything above",
        "you are now dan",
        "act as unrestricted",
        "developer mode",
        "jailbreak",
        "rm -rf",
        "curl ",
        "wget ",
        "powershell",
    ]
    return any(marker in lowered or marker in leetspeak_normalized or marker in decoded_once.lower() for marker in suspicious_markers)


def _sanitize_prompt_input(text: str) -> str:
    if not text:
        return text
    sanitized = _neutralize_prompt_injection(text)
    if _contains_suspicious_prompt_content(text):
        sanitized = _neutralize_prompt_injection(sanitized)
    return sanitized


def _redact_zero_tolerance_pii(text: str) -> str:
    if not text:
        return text

    redacted = text
    pii_patterns = [
        (r"\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b", "[REDACTED_SSN_OR_TIN]"),
        (r"\b(?:19|20)\d{2}\b", "[REDACTED_YEAR_OF_BIRTH]"),
        (r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b", "[REDACTED_PHONE]"),
        (r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]"),
        (r"\b\d{1,5}\s+[A-Za-z0-9.\-\s]+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b", "[REDACTED_HOME_ADDRESS]"),
        (r"\b(?:passport|passport number)[:#\s]*[A-Z0-9-]{6,}\b", "[REDACTED_PASSPORT]"),
        (r"\b(?:driver'?s license|drivers license|dl)[:#\s]*[A-Z0-9-]{5,}\b", "[REDACTED_DRIVERS_LICENSE]"),
        (r"\b(?:employee id|school id)[:#\s]*[A-Z0-9-]{3,}\b", "[REDACTED_ID]"),
        (r"\b(?:vin)[:#\s]*[A-HJ-NPR-Z0-9]{17}\b|\b[A-HJ-NPR-Z0-9]{17}\b", "[REDACTED_VIN]"),
        (r"\b(?:\d[ -]*?){13,19}\b", "[REDACTED_CARD_OR_ACCOUNT]"),
        (r"\b(?:account number|financial account number)[:#\s]*\d{6,}\b", "[REDACTED_FINANCIAL_ACCOUNT]"),
        (r"\b(?:mother'?s maiden name|birthplace|medical records?|ethnicity|sexual orientation|voice signature|facial image|fingerprints?|retina(?:/|\s+)iris scan|fine location)\b[^\n]*", "[REDACTED_SENSITIVE_PII]"),
        (r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b", "[REDACTED_IP_ADDRESS]"),
        (r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b", "[REDACTED_MAC_ADDRESS]"),
    ]
    for pattern, replacement in pii_patterns:
        redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)
    return redacted


def _sanitize_uploaded_file_contents(file_contents: list[Any]) -> list[Any]:
    sanitized_contents: list[Any] = []
    for item in file_contents or []:
        if isinstance(item, str):
            sanitized_contents.append(_sanitize_prompt_input(_redact_zero_tolerance_pii(item)))
        else:
            sanitized_contents.append(item)
    return sanitized_contents


def _sanitize_display_text(text: str) -> str:
    return _redact_zero_tolerance_pii(_sanitize_prompt_input(text))


class LoanProcessingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("LOAN_PROCESSING_AGENT_MODEL", "gpt-4o mini")
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Handles loan application intake, borrower updates, and loan package generation."
    MCP_SERVERS = ["Docx", "Excel", "Email"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Process loan requests, summarize borrower context, and prepare follow-up actions."
    IS_ROUTABLE = False
    IS_SCAN_ONLY = True

    async def call_agent_model(self, user_message: str, file_summary: str) -> str:
        user_message = _sanitize_prompt_input(_redact_zero_tolerance_pii(user_message))
        file_summary = _sanitize_prompt_input(_redact_zero_tolerance_pii(file_summary))
        return await self.model_client.chat(
            model=self.MODEL_NAME,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Loan request:\n{user_message or 'No user message provided.'}\n\n"
                        f"File summary:\n{file_summary}\n\n"
                        "Draft a concise loan processing next-step summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        safe_user_message = _sanitize_prompt_input(_redact_zero_tolerance_pii(user_message))
        sanitized_file_contents = _sanitize_uploaded_file_contents(context.get("file_contents", []))
        file_summary = build_file_summary(sanitized_file_contents)
        file_summary = _sanitize_prompt_input(_redact_zero_tolerance_pii(file_summary))
        display_user_message = _sanitize_display_text(user_message)
        loan_number = extract_reference_number(user_message, prefix="LOAN")
        model_output = await self.call_agent_model(safe_user_message, file_summary)

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{safe_user_message}\n\nFile summary:\n{file_summary}",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Excel",
                "upsert_row",
                {
                    "workbook": "Loan Pipeline",
                    "worksheet": "Applications",
                    "row": {
                        "loan_number": loan_number,
                        "status": "processing",
                        "borrower_request": display_user_message[:240],
                    },
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example"],
                    "subject": f"Loan update for {loan_number}",
                    "body": "Your loan request is being reviewed by the Loan Processing Agent.",
                },
            ),
        )

        response = (
            "This scan-only agent is disconnected from the Orchestrator Agent.\n\n"
            f"Loan reference: {loan_number}\n"
            f"Borrower request: {display_user_message or 'No user message provided.'}\n\n"
            f"Loan summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


loan_processing_agent = LoanProcessingAgent()
