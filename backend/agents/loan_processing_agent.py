"""Loan Processing Agent class with explicit model invocation."""

import asyncio
import os
import re
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary, extract_reference_number
from .mcp_servers import call_mcp_server


def _redact_zero_tolerance_pii(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    redacted = text
    pii_patterns = [
        (r"\b\d{3}-\d{2}-\d{4}\b", "<redacted:ssn>"),
        (r"\b(?:19|20)\d{2}\b", "<redacted:year_of_birth>"),
        (r"\b(?:birthplace|place of birth)\s*[:\-]\s*[^\n\r,;]+", "birthplace: <redacted:birthplace>"),
        (r"\b(?:mother(?:'s)? maiden name)\s*[:\-]\s*[^\n\r,;]+", "mother's maiden name: <redacted:mothers_maiden_name>"),
        (r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", "<redacted:email>"),
        (r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b", "<redacted:personal_phone_number>"),
        (r"\b\d{1,6}\s+[A-Za-z0-9.#'\- ]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter)\b(?:[^\n\r,;]*)", "<redacted:home_address>"),
        (r"\b[A-Z0-9]{6,9}\b", "<redacted:passport_number>"),
        (r"\b[A-Z0-9]{1,2}\d{4,8}\b", "<redacted:drivers_license_number>"),
        (r"\b\d{2}-\d{7}\b", "<redacted:taxpayer_identification_number>"),
        (r"\b(?:\d[ -]*?){13,19}\b", "<redacted:credit_card_number>"),
        (r"\b(?:account|acct|routing|iban)\s*[:#-]?\s*[A-Z0-9\-]{6,34}\b", "<redacted:financial_account_number>"),
        (r"\b(?:employee id|employee number)\s*[:#-]?\s*[A-Z0-9\-]{2,20}\b", "employee id: <redacted:employee_id>"),
        (r"\b(?:school id|student id)\s*[:#-]?\s*[A-Z0-9\-]{2,20}\b", "school id: <redacted:school_id>"),
        (r"\b[A-HJ-NPR-Z0-9]{17}\b", "<redacted:vehicle_identification_number>"),
        (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<redacted:ip_address>"),
        (r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", "<redacted:mac_address>"),
        (r"\b(?:latitude|longitude|lat|lon|location)\s*[:=]\s*[-+]?\d{1,3}(?:\.\d+)?(?:\s*,\s*[-+]?\d{1,3}(?:\.\d+)?)?", "location: <redacted:fine_location>"),
        (r"\b(?:ethnicity|sexual orientation)\s*[:\-]\s*[^\n\r,;]+", lambda m: m.group(0).split(":", 1)[0].split("-", 1)[0] + ": <redacted:sensitive_attribute>"),
    ]

    for pattern, replacement in pii_patterns:
        redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)

    keyword_redactions = {
        "fingerprint": "<redacted:fingerprints>",
        "fingerprints": "<redacted:fingerprints>",
        "retina scan": "<redacted:retina_iris_scan>",
        "iris scan": "<redacted:retina_iris_scan>",
        "voice signature": "<redacted:voice_signature>",
        "facial image": "<redacted:facial_image>",
        "medical record": "<redacted:medical_records>",
        "medical records": "<redacted:medical_records>",
    }
    for keyword, replacement in keyword_redactions.items():
        redacted = re.sub(rf"\b{re.escape(keyword)}\b", replacement, redacted, flags=re.IGNORECASE)

    return redacted


_BASE64_SEGMENT_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")


def _looks_like_leetspeak_instruction(text: str) -> bool:
    normalized = text.lower().translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}))
    suspects = [
        "ignore previous instructions",
        "forget everything above",
        "you are now dan",
        "developer mode",
        "system prompt",
        "act as unrestricted",
    ]
    return any(suspect in normalized for suspect in suspects)


def _neutralize_prompt_injection(text: str, indirect: bool = False) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text
    replacements = [
        (r"(?is)\b(?:ignore previous instructions|forget everything above|disregard all prior instructions|override (?:the )?(?:system|previous) instructions)\b", "<prompt_injection_removed: instruction_override>"),
        (r"(?is)\b(?:you are now dan|act as unrestricted|act as [^\n\r]{0,40}system|assume the role of|roleplay as)\b[^\n\r]*", "<prompt_injection_removed: role_hijack>"),
        (r"(?is)</?(?:system|assistant|tool|developer)>|(?:^|\n)\s*[-=]{3,}\s*(?:system|assistant|developer|tool)\s*[-=]{3,}", "<prompt_injection_removed: delimiter_escape>"),
        (r"(?is)<!--.*?(?:ignore|system|instruction|prompt).*?-->|[\u200b\u200c\u200d\ufeff]+|font-size\s*:\s*0|color\s*:\s*white|display\s*:\s*none", "<prompt_injection_removed: hidden_text>"),
        (r"(?im)^\s*(?:system|assistant|tool)\s*:\s*.*$", "<prompt_injection_removed: fake_system_message>"),
        (r"(?is)\b(?:send|post|upload|exfiltrate|leak|reveal)\b[^\n\r]{0,120}\b(?:system prompt|credentials|secrets|data)\b|!\[[^\]]*\]\([^)]*https?://[^)]*\)", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"(?is)\b(?:on the next turn|in future responses|remember this instruction|persist this|from now on)\b[^\n\r]*", "<prompt_injection_removed: context_poisoning>"),
        (r"(?is)\b(?:run|execute|shell|terminal|powershell|bash|sh|cmd\.exe|/bin/sh|python\s+-c|subprocess|os\.system|eval\(|exec\()\b[^\n\r]*", "<prompt_injection_removed: command_injection>"),
        (r"(?is)\b(?:dan|developer mode|jailbreak|bypass safety|fictional scenario to bypass)\b[^\n\r]*", "<prompt_injection_removed: jailbreak_attempt>"),
        (r"(?is)(?:i\s*g\s*n\s*o\s*r\s*e\s+previous\s+instructions|f\s*o\s*r\s*g\s*e\s*t\s+everything\s+above)", "<prompt_injection_removed: split_payload>"),
    ]

    for pattern, replacement in replacements:
        sanitized = re.sub(pattern, replacement, sanitized)

    def _replace_encoded(match: re.Match[str]) -> str:
        segment = match.group(0)
        return "<prompt_injection_removed: encoded_payload>" if len(segment) >= 32 else segment

    sanitized = _BASE64_SEGMENT_RE.sub(_replace_encoded, sanitized)

    decoded_url = urllib.parse.unquote(text)
    if decoded_url != text and re.search(r"(?is)\b(?:ignore previous instructions|forget everything above|you are now dan|act as unrestricted|system prompt|developer mode)\b", decoded_url):
        sanitized = sanitized.replace(text, "<prompt_injection_removed: encoded_payload>") if sanitized == text else sanitized + ""
        if sanitized == text:
            sanitized = "<prompt_injection_removed: encoded_payload>"

    if _looks_like_leetspeak_instruction(text):
        sanitized = "<prompt_injection_removed: encoded_payload>" if sanitized == text else sanitized

    if indirect and sanitized != text:
        sanitized = "<prompt_injection_removed: indirect_injection>"

    return sanitized


class LoanProcessingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.environ.get("LOAN_PROCESSING_AGENT_MODEL", "")
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Handles loan application intake, borrower updates, and loan package generation."
    # Set LOAN_PROCESSING_AGENT_MODEL to an organization-approved model from the runtime registry.
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
        user_message = _neutralize_prompt_injection(user_message or "")
        file_summary = _neutralize_prompt_injection(_redact_zero_tolerance_pii(file_summary or ""), indirect=True)
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
        user_message = _neutralize_prompt_injection(user_message)
        file_summary = build_file_summary(context.get("file_contents", []))
        file_summary = _redact_zero_tolerance_pii(file_summary)
        file_summary = _neutralize_prompt_injection(file_summary, indirect=True)
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
