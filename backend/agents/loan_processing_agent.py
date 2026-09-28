"""Loan Processing Agent class with explicit model invocation."""

import asyncio
import os
import re
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary, extract_reference_number
from .mcp_servers import call_mcp_server


_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_RE = re.compile(r"\b(?:0x[0-9A-Fa-f]{2,}|[0-9A-Fa-f]{16,})\b")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_SPLIT_IGNORE_RE = re.compile(r"\bi\s*g\s*n\s*o\s*r\s*e\b(?:\W+\b\w+\b){0,6}\W+\bp\s*r\s*e\s*v\s*i\s*o\s*u\s*s\b(?:\W+\b\w+\b){0,3}\W+\bi\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s\b", re.IGNORECASE)


def _redact_zero_tolerance_pii(text: str) -> str:
    if not text:
        return text

    patterns = [
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:ssn>"),
        (re.compile(r"\b(?:19|20)\d{2}\b"), "<redacted:year_of_birth>"),
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<redacted:email>"),
        (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"), "<redacted:personal_phone>"),
        (re.compile(r"\b(?:mother(?:'s|s)? maiden name)\s*[:=-]?\s*[^\n,;]+", re.IGNORECASE), "Mother's Maiden Name: <redacted>"),
        (re.compile(r"\b\d{1,6}\s+[A-Za-z0-9.\- ]+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter)\b(?:[^\n,;]*)", re.IGNORECASE), "<redacted:home_address>"),
        (re.compile(r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b", re.IGNORECASE), "<redacted:passport_number>"),
        (re.compile(r"\b(?:DL|DLS|Driver(?:'s)? License|Drivers License)\s*[:#-]?\s*[A-Z0-9-]{5,20}\b", re.IGNORECASE), "<redacted:drivers_license_number>"),
        (re.compile(r"\b(?:ITIN|TIN|Taxpayer Identification Number)\s*[:#-]?\s*\d{2,3}-?\d{2,7}-?\d{0,4}\b", re.IGNORECASE), "<redacted:taxpayer_identification_number>"),
        (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<redacted:credit_or_financial_account_number>"),
        (re.compile(r"\b(?:Employee Id|Employee ID)\s*[:#-]?\s*[A-Z0-9-]{3,20}\b", re.IGNORECASE), "<redacted:employee_id>"),
        (re.compile(r"\b(?:School Id|School ID)\s*[:#-]?\s*[A-Z0-9-]{3,20}\b", re.IGNORECASE), "<redacted:school_id>"),
        (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<redacted:vin>"),
        (re.compile(r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"), "<redacted:ip_address>"),
        (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted:mac_address>"),
        (re.compile(r"\b(?:birthplace|medical records|fingerprints|retina scan|iris scan|voice signature|facial image|ethnicity|sexual orientation|fine location)\s*[:=-]?\s*[^\n]+", re.IGNORECASE), lambda m: m.group(0).split(":", 1)[0].split("=", 1)[0].split("-", 1)[0].strip() + ": <redacted>"),
    ]

    redacted = text
    for pattern, replacement in patterns:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _neutralize_prompt_injection(text: str, *, file_derived: bool = False) -> str:
    if not text:
        return text

    sanitized = text
    sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"<!--(?:(?!-->).)*(?:ignore|system prompt|developer message|instructions)(?:(?!-->).)*-->", "<prompt_injection_removed: hidden_text>", sanitized, flags=re.IGNORECASE | re.DOTALL)
    sanitized = re.sub(r"<\s*/?\s*system\s*>", "<prompt_injection_removed: delimiter_escape>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"(?m)^\s*(?:---|===|```+)\s*$", "<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = re.sub(r"\b(?:ignore|disregard|forget)\b(?:[^\n]{0,80})\b(?:previous|above|earlier)\b(?:[^\n]{0,80})\b(?:instructions?|messages?|prompts?)\b", "<prompt_injection_removed: instruction_override>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(?:you are now|act as|pretend to be|roleplay as)\b(?:[^\n]{0,60})\b(?:dan|developer mode|unrestricted|root|system)\b", "<prompt_injection_removed: role_hijack>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(?:DAN|developer mode|jailbreak|bypass safety|fictional framing)\b", "<prompt_injection_removed: jailbreak_attempt>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(?:system|tool|developer)\s*:\s*(?:ignore|reveal|override|send)\b[^\n]*", "<prompt_injection_removed: fake_system_message>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(?:reveal|leak|print|send|upload|export|exfiltrate)\b(?:[^\n]{0,80})\b(?:system prompt|secrets?|credentials?|keys?|tokens?|data)\b(?:[^\n]{0,80})\b(?:https?://\S+|to\s+\S+)", "<prompt_injection_removed: exfiltration_attempt>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"!\[[^\]]*\]\([^)]*https?://[^)]*\)", "<prompt_injection_removed: exfiltration_attempt>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(?:in the next turn|across turns|persist this|remember this instruction|from now on)\b[^\n]*", "<prompt_injection_removed: context_poisoning>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd(?:\.exe)?|python\s+-c|perl\s+-e|ruby\s+-e|node\s+-e|os\.system\(|subprocess\.|exec\(|eval\()\b[^\n]*", "<prompt_injection_removed: command_injection>", sanitized, flags=re.IGNORECASE)
    sanitized = _SPLIT_IGNORE_RE.sub("<prompt_injection_removed: split_payload>", sanitized)

    def _replace_encoded(match: re.Match[str]) -> str:
        token = match.group(0)
        if token.isdigit():
            return token
        decoded_candidates = [urllib.parse.unquote(token)]
        if len(token) % 4 == 0:
            try:
                import base64
                decoded_candidates.append(base64.b64decode(token, validate=True).decode("utf-8", errors="ignore"))
            except Exception:
                pass
        for candidate in decoded_candidates:
            lowered = candidate.lower()
            if any(phrase in lowered for phrase in ("ignore previous instructions", "system prompt", "act as unrestricted", "curl http", "wget http", "bash -c", "powershell", "developer mode")):
                return "<prompt_injection_removed: encoded_payload>"
        return token

    sanitized = _BASE64_RE.sub(_replace_encoded, sanitized)
    sanitized = _HEX_RE.sub(_replace_encoded, sanitized)
    sanitized = _URL_ENCODED_RE.sub(_replace_encoded, sanitized)

    if file_derived:
        sanitized = re.sub(r"\b(?:todo|note|comment)\s*[:#-]?\s*(?:ignore|override|reveal|leak|send|curl|wget|bash)\b[^\n]*", "<prompt_injection_removed: indirect_injection>", sanitized, flags=re.IGNORECASE)

    return sanitized


def _sanitize_untrusted_text(text: str, *, file_derived: bool = False) -> str:
    sanitized = _redact_zero_tolerance_pii(text)
    sanitized = _neutralize_prompt_injection(sanitized, file_derived=file_derived)
    return sanitized


class LoanProcessingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("LOAN_PROCESSING_AGENT_MODEL", "gpt-4o mini")
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Handles loan application intake, borrower updates, and loan package generation. Configure LOAN_PROCESSING_AGENT_MODEL with an approved registry-listed model at deployment time."
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
        user_message = _sanitize_untrusted_text(user_message or "")
        file_summary = _sanitize_untrusted_text(file_summary, file_derived=True)
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
        user_message = _sanitize_untrusted_text(user_message)
        file_summary = build_file_summary(context.get("file_contents", []))
        file_summary = _sanitize_untrusted_text(file_summary, file_derived=True)
        loan_number = extract_reference_number(user_message, prefix="LOAN")
        model_output = await self.call_agent_model(user_message, file_summary)

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{user_message}\n\nFile summary:\n{file_summary}",
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
                        "borrower_request": user_message[:240],
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
            f"Borrower request: {user_message or 'No user message provided.'}\n\n"
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
