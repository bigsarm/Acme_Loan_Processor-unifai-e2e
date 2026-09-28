"""Loan Processing Agent class with explicit model invocation."""

import asyncio
import os
import re
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary, extract_reference_number
from .mcp_servers import call_mcp_server


_ZERO_TOLERANCE_PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:ssn>"),
    (re.compile(r"\b(?:19|20)\d{2}\b"), "<redacted:year_of_birth>"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<redacted:email>"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"), "<redacted:personal_phone>"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<redacted:credit_card>"),
    (re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"), "<redacted:passport_number>"),
    (re.compile(r"\b[A-Z0-9]{6,12}\b"), "<redacted:drivers_license_or_id>"),
    (re.compile(r"\b\d{2}-\d{7}\b"), "<redacted:tin>"),
    (re.compile(r"\b(?:\d{4}[- ]?){2,4}\d{1,4}\b"), "<redacted:financial_account>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted:mac_address>"),
    (re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"), "<redacted:ip_address>"),
    (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<redacted:vin>"),
    (re.compile(r"\bemployee id\b\s*[:#-]?\s*\w+", re.IGNORECASE), "Employee ID: <redacted:employee_id>"),
    (re.compile(r"\bschool id\b\s*[:#-]?\s*\w+", re.IGNORECASE), "School ID: <redacted:school_id>"),
    (re.compile(r"\bmother'?s maiden name\b\s*[:#-]?\s*[^\n,;]+", re.IGNORECASE), "Mother's Maiden Name: <redacted>"),
    (re.compile(r"\bbirthplace\b\s*[:#-]?\s*[^\n,;]+", re.IGNORECASE), "Birthplace: <redacted>"),
    (re.compile(r"\bhome address\b\s*[:#-]?\s*[^\n]+", re.IGNORECASE), "Home Address: <redacted>"),
    (re.compile(r"\bmedical records?\b\s*[:#-]?\s*[^\n]+", re.IGNORECASE), "Medical Records: <redacted>"),
    (re.compile(r"\b(?:ethnicity|sexual orientation|voice signature|facial image|fingerprints|retina(?:/iris)? scan|fine location)\b\s*[:#-]?\s*[^\n,;]+", re.IGNORECASE), "<redacted:sensitive_attribute>"),
]

_PROMPT_INJECTION_REPLACEMENTS = [
    (re.compile(r"(?i)\b(ignore|disregard|forget)\b.{0,80}\b(previous|above|earlier)\b.{0,80}\b(instruction|prompt|message|system)\b"), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"(?i)\b(you are now|act as|pretend to be|assume the role of)\b.{0,80}\b(dan|developer mode|unrestricted|system|assistant)\b"), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"(?i)</?(system|assistant|user|tool)>|```(?:system|assistant|user|tool)|-----+|###\s*(system|assistant|developer)"), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"(?i)\b(system prompt|send data to|upload to|post to|exfiltrate|leak)\b.{0,120}\b(http|www\.|https?://)"), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"(?i)!\[[^\]]*\]\([^\)]*\)|\b(leak|reveal|dump|export)\b.{0,120}\b(system prompt|secrets?|credentials?|tokens?|files?)\b"), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"(?i)\b(as a reminder|from now on|in the next turn|for every future response|persist this instruction)\b"), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"(?i)\b(system message|tool message|function result|developer instruction)\b\s*[:=-]"), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"(?i)\b(eval\(|exec\(|os\.system\(|subprocess\.|bash\b|sh\b|powershell\b|cmd\.exe\b|curl\b|wget\b|rm\s+-rf\b)"), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"(?i)\b(DAN|do anything now|jailbreak|bypass safety|fictional framing|developer mode)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
    (re.compile(r"(?i)\b(?:i\s*g\s*n\s*o\s*r\s*e|d\s*a\s*n|b\s*y\s*p\s*a\s*s\s*s)\b"), "<prompt_injection_removed: split_payload>"),
]


def _mask_zero_tolerance_pii(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text
    masked = text
    for pattern, replacement in _ZERO_TOLERANCE_PII_PATTERNS:
        masked = pattern.sub(replacement, masked)
    return masked


def _contains_hidden_or_encoded_prompt(text: str) -> bool:
    if not isinstance(text, str) or not text:
        return False

    if re.search(r"[\u200b\u200c\u200d\ufeff]", text):
        return True
    if re.search(r"<!--.*?(ignore|system|instruction|prompt|bypass).*?-->", text, re.IGNORECASE | re.DOTALL):
        return True
    if re.search(r"(?i)font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*white", text):
        return True
    if re.search(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b", text):
        return True
    if re.search(r"\b(?:0x)?[0-9A-Fa-f]{16,}\b", text):
        return True
    if re.search(r"(?i)\b(?:h4ck|1gn0re|byp4ss|3xfil|pr0mpt)\b", text):
        return True
    if re.search(r"(?i)\b(?:bash|powershell|cmd\.exe|curl|wget|nc\s+-e|python\s+-c|perl\s+-e|sh\s+-c)\b", text):
        return True

    try:
        decoded = urllib.parse.unquote(text)
    except Exception:
        decoded = text
    if decoded != text and re.search(r"(?i)\b(ignore previous instructions|you are now|act as|system prompt|bash|powershell|curl|wget)\b", decoded):
        return True

    return False


def _neutralize_prompt_injection(text: str, *, file_context: bool = False) -> str:
    if not isinstance(text, str) or not text:
        return text

    neutralized = text
    if _contains_hidden_or_encoded_prompt(neutralized):
        neutralized = re.sub(r"[\u200b\u200c\u200d\ufeff]+", "<prompt_injection_removed: hidden_text>", neutralized)
        neutralized = re.sub(r"<!--.*?-->", "<prompt_injection_removed: hidden_text>", neutralized, flags=re.DOTALL)
        neutralized = re.sub(r"(?i)font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*white", "<prompt_injection_removed: hidden_text>", neutralized)
        neutralized = re.sub(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b", "<prompt_injection_removed: encoded_payload>", neutralized)
        neutralized = re.sub(r"\b(?:0x)?[0-9A-Fa-f]{16,}\b", "<prompt_injection_removed: encoded_payload>", neutralized)
        neutralized = re.sub(r"(?i)\b(?:h4ck|1gn0re|byp4ss|3xfil|pr0mpt)\b", "<prompt_injection_removed: encoded_payload>", neutralized)
        neutralized = re.sub(r"(?i)\b(?:bash|powershell|cmd\.exe|curl|wget|nc\s+-e|python\s+-c|perl\s+-e|sh\s+-c)\b", "<prompt_injection_removed: command_injection>", neutralized)

    for pattern, replacement in _PROMPT_INJECTION_REPLACEMENTS:
        neutralized = pattern.sub(replacement, neutralized)

    if file_context:
        neutralized = re.sub(
            r"(?i)\b(todo|note|comment|instruction)\b\s*[:#-]?\s*(ignore|bypass|override|reveal|leak|exfiltrate)[^\n]*",
            "<prompt_injection_removed: indirect_injection>",
            neutralized,
        )

    return neutralized


def _sanitize_ai_text(text: str, *, file_context: bool = False, mask_pii: bool = False) -> str:
    if not isinstance(text, str) or not text:
        return text
    sanitized = _neutralize_prompt_injection(text, file_context=file_context)
    if mask_pii:
        sanitized = _mask_zero_tolerance_pii(sanitized)
    return sanitized


def _sanitize_file_contents(file_contents: Any) -> Any:
    if isinstance(file_contents, list):
        sanitized_contents = []
        for item in file_contents:
            if isinstance(item, str):
                sanitized_contents.append(_sanitize_ai_text(item, file_context=True, mask_pii=True))
            elif isinstance(item, dict):
                sanitized_item = {}
                for key, value in item.items():
                    if isinstance(value, str):
                        sanitized_item[key] = _sanitize_ai_text(value, file_context=True, mask_pii=True)
                    else:
                        sanitized_item[key] = value
                sanitized_contents.append(sanitized_item)
            else:
                sanitized_contents.append(item)
        return sanitized_contents
    return file_contents


class LoanProcessingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("LOAN_PROCESSING_AGENT_MODEL", "gpt-4o mini")  # Replace this default with an approved model from the organization allow list.
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
        user_message = _sanitize_ai_text(user_message, mask_pii=True)
        file_summary = _sanitize_ai_text(file_summary, file_context=True, mask_pii=True)
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
        user_message = _sanitize_ai_text(user_message, mask_pii=True)
        sanitized_file_contents = _sanitize_file_contents(context.get("file_contents", []))
        file_summary = build_file_summary(sanitized_file_contents)
        file_summary = _sanitize_ai_text(file_summary, file_context=True, mask_pii=True)
        display_user_message = _mask_zero_tolerance_pii(user_message)
        loan_number = extract_reference_number(user_message, prefix="LOAN")
        model_output = await self.call_agent_model(user_message, file_summary)

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{display_user_message}\n\nFile summary:\n{file_summary}",
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
