"""Loan Processing Agent class with explicit model invocation."""

import asyncio
import os
import re
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary, extract_reference_number
from .mcp_servers import call_mcp_server


_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u2060]")
_BASE64_BLOCK_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b")
_HEX_BLOCK_RE = re.compile(r"\b(?:0x)?(?:[0-9A-Fa-f]{2}){8,}\b")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_LEETSPEAK_RE = re.compile(r"\b(?:[A-Za-z0-9]*[013457@$][A-Za-z0-9]*){4,}\b")
_BINARY_HINT_RE = re.compile(r"\b(?:MZ|ELF|PK\x03\x04)\b")
_SUSPICIOUS_COMMAND_RE = re.compile(
    r"(?i)(?:\b(?:cmd\.exe|powershell(?:\.exe)?|bash|sh|zsh|curl|wget|nc|netcat|python(?:3)?|perl|ruby)\b|(?:;|&&|\|\|)\s*(?:curl|wget|bash|sh|powershell|cmd\.exe)\b|\b(?:rm\s+-rf|del\s+/f|chmod\s+\+x|sudo\b|scp\b|ssh\b)\b)"
)


def _mask_pii(text: str) -> str:
    if not text:
        return text
    masked = text
    patterns = [
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<masked:ssn>"),
        (re.compile(r"\b\d{9}\b"), "<masked:taxpayer_id>"),
        (re.compile(r"\b(?:19|20)\d{2}\b"), "<masked:year_of_birth>"),
        (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "<masked:email>"),
        (re.compile(r"(?:(?<=\D)|^)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})(?=\D|$)"), "<masked:phone>"),
        (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<masked:credit_card>"),
        (re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"), "<masked:passport>"),
        (re.compile(r"\b[A-Z0-9]{5,20}\b"), "<masked:id_number>"),
        (re.compile(r"\b(?:\d{1,5}\s+[A-Za-z0-9.'#-]+(?:\s+[A-Za-z0-9.'#-]+){1,5})\b"), "<masked:address>"),
        (re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"), "<masked:ip_address>"),
        (re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b"), "<masked:mac_address>"),
        (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<masked:vin>"),
    ]
    for pattern, replacement in patterns:
        masked = pattern.sub(replacement, masked)
    return masked


def _contains_obfuscated_or_hidden_prompt(text: str) -> bool:
    if not text:
        return False
    if _ZERO_WIDTH_RE.search(text):
        return True
    lowered = text.lower()
    if "<!--" in text or "-->" in text:
        return True
    if any(token in lowered for token in ["color:white", "font-size:0", "display:none", "visibility:hidden"]):
        return True
    if _BASE64_BLOCK_RE.search(text) or _HEX_BLOCK_RE.search(text) or _URL_ENCODED_RE.search(text) or _LEETSPEAK_RE.search(text):
        return True
    return False


def _sanitize_prompt_content(text: str, source: str = "input") -> str:
    if not text:
        return text
    sanitized = text
    replacements = [
        (re.compile(r"(?is)\b(?:ignore|disregard|forget)\b.{0,80}\b(?:previous|above|earlier)\b.{0,80}\b(?:instruction|prompt|message)s?\b"), "<prompt_injection_removed: instruction_override>"),
        (re.compile(r"(?i)\b(?:you are now|act as|pretend to be|assume the role of)\b.{0,80}\b(?:dan|unrestricted|system|developer mode|root)\b"), "<prompt_injection_removed: role_hijack>"),
        (re.compile(r"(?is)</?(?:system|assistant|user|tool)>|(?:^|\n)\s*(?:---|###|```system|```assistant)"), "<prompt_injection_removed: delimiter_escape>"),
        (re.compile(r"(?i)\b(?:system message|developer message|tool message):"), "<prompt_injection_removed: fake_system_message>"),
        (re.compile(r"(?i)\b(?:send|post|upload|exfiltrate|leak|reveal)\b.{0,120}\b(?:system prompt|secrets?|credentials?|data)\b|!\[[^\]]*\]\([^)]*https?://[^)]*\)"), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"(?i)\b(?:on your next turn|in future responses|remember this instruction|persist this|across turns)\b"), "<prompt_injection_removed: context_poisoning>"),
        (re.compile(r"(?i)\b(?:DAN|developer mode|jailbreak|bypass safety|fictional framing)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
        (re.compile(r"(?i)\b(?:eval|exec|os\.system|subprocess|__import__)\s*\("), "<prompt_injection_removed: command_injection>"),
        (_SUSPICIOUS_COMMAND_RE, "<prompt_injection_removed: command_injection>"),
    ]
    for pattern, replacement in replacements:
        sanitized = pattern.sub(replacement, sanitized)
    if _contains_obfuscated_or_hidden_prompt(sanitized):
        sanitized = _ZERO_WIDTH_RE.sub("", sanitized)
        sanitized = re.sub(r"<!--.*?-->", "<prompt_injection_removed: hidden_text>", sanitized, flags=re.DOTALL)
        sanitized = re.sub(r"(?i)(?:color:white|font-size:0|display:none|visibility:hidden)", "<prompt_injection_removed: hidden_text>", sanitized)
        sanitized = _BASE64_BLOCK_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _HEX_BLOCK_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _URL_ENCODED_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _LEETSPEAK_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
    if _BINARY_HINT_RE.search(sanitized):
        sanitized = _BINARY_HINT_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
    if source == "file":
        sanitized = re.sub(
            r"(?i)\b(?:instructions?|prompt|system|assistant|developer|tool|ignore previous|act as|send data|curl|wget|powershell|cmd\.exe)\b",
            "<prompt_injection_removed: indirect_injection>",
            sanitized,
        )
    fragmented = re.compile(r"(?is)(?:i\s*g\s*n\s*o\s*r\s*e|d\s*a\s*n|a\s*c\s*t\s*a\s*s)")
    sanitized = fragmented.sub("<prompt_injection_removed: split_payload>", sanitized)
    return sanitized


def _redact_uploaded_file_contents(file_contents: Any) -> Any:
    if isinstance(file_contents, str):
        return _mask_pii(_sanitize_prompt_content(file_contents, source="file"))
    if isinstance(file_contents, list):
        return [_redact_uploaded_file_contents(item) for item in file_contents]
    if isinstance(file_contents, dict):
        return {key: _redact_uploaded_file_contents(value) for key, value in file_contents.items()}
    return file_contents


class LoanProcessingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("LOAN_PROCESSING_AGENT_MODEL", "")
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Handles loan application intake, borrower updates, and loan package generation. Configure LOAN_PROCESSING_AGENT_MODEL with an approved model from the organization allow list."
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
        user_message = _sanitize_prompt_content(user_message, source="user")
        file_summary = _sanitize_prompt_content(file_summary, source="file")
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
        sanitized_user_message = _sanitize_prompt_content(user_message, source="user")
        masked_user_message = _mask_pii(sanitized_user_message)
        redacted_file_contents = _redact_uploaded_file_contents(context.get("file_contents", []))
        file_summary = build_file_summary(redacted_file_contents)
        file_summary = _mask_pii(_sanitize_prompt_content(file_summary, source="file"))
        loan_number = extract_reference_number(user_message, prefix="LOAN")
        model_output = await self.call_agent_model(sanitized_user_message, file_summary)

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{masked_user_message}\n\nFile summary:\n{file_summary}",
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
                        "borrower_request": masked_user_message[:240],
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
            f"Borrower request: {masked_user_message or 'No user message provided.'}\n\n"
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
