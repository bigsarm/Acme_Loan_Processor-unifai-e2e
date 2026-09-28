"""Credit Eval Agent class with explicit model invocation."""

import logging
import re
from typing import Any
from urllib.parse import unquote

from .framework import AcmeLoanAgentFramework
from .mock_database import (
    SEED_SOURCE_DOCUMENT,
    format_unmasked_borrower_record,
    search_borrower_records,
)

logger = logging.getLogger(__name__)


def _normalize_for_detection(text: str) -> str:
    normalized = (text or "").lower()
    normalized = unquote(normalized)
    normalized = normalized.replace("0", "o").replace("1", "i").replace("3", "e").replace("4", "a").replace("5", "s").replace("7", "t")
    normalized = re.sub(r"[\s\-_\.]+", "", normalized)
    return normalized


def _mask_year_or_dob(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    match = re.search(r"\b(19|20)\d{2}\b", text)
    if match:
        year = match.group(0)
        return text.replace(year, "****")
    return "****"


def _mask_ssn(value: Any) -> str:
    text = str(value or "")
    return re.sub(r"\b(\d{3})-(\d{2})-(\d{4})\b", "***-**-\\3", text)


def _mask_address(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    parts = [part.strip() for part in text.split(",")]
    if not parts:
        return "****"
    street = re.sub(r"\b\d+\b", "****", parts[0])
    street = re.sub(r"^[^\s,]+", "****", street, count=1)
    parts[0] = street
    return ", ".join(parts)


class CreditEvalAgent(AcmeLoanAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"  # Replace with an approved LLM from the organization's allow list; registry enforcement is handled outside this file.
    DESCRIPTION = "Evaluates creditworthiness, loan status, and borrower notes for loan decisions."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": False,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Review credit details, debt ratios, repayment risk indicators, and loan status."

    def sanitize_prompt_content(self, text: str) -> tuple[str, bool]:
        sanitized = text or ""
        replacement_patterns = [
            (re.compile(r"\b(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+all\s+prior\s+instructions)\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
            (re.compile(r"\b(?:you\s+are\s+now\s+dan|act\s+as\s+(?:an\s+)?unrestricted(?:\s+ai)?|developer\s+mode|do\s+anything\s+now)\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
            (re.compile(r"</?system>|</?assistant>|</?user>|\[/?system\]|\[/?assistant\]|\[/?user\]|(?:^|\n)\s*(?:---|===)\s*(?:\n|$)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
            (re.compile(r"<!--.*?-->", re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"[\u200B-\u200F\u2060\uFEFF]+"), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"<span[^>]*font-size\s*:\s*(?:0|1px)[^>]*>.*?</span>", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"<span[^>]*color\s*:\s*(?:white|#fff(?:fff)?)\b[^>]*>.*?</span>", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"\b(?:system\s*:\s*|assistant\s*:\s*|tool\s*:\s*)[^\n]*", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
            (re.compile(r"\b(?:send|post|upload|exfiltrate|leak)\b[^\n]*\b(?:https?://\S+|system\s+prompt|credentials|secrets|data)\b", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
            (re.compile(r"\b(?:in\s+the\s+next\s+turn|on\s+your\s+next\s+message|from\s+now\s+on|remember\s+this\s+instruction)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
            (re.compile(r"\b(?:metadata|front\s*matter|code\s*comment|yaml|json\s*field|document\s*property)\b[^\n]*\b(?:ignore|override|follow\s+these\s+instructions)\b", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
            (re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm|chmod|python\s+-c|exec|eval|subprocess|os\.system)\b[^\n]*", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"\b(?:jailbreak|bypass\s+safety|fictional\s+framing|simulate\s+developer\s+mode|dan)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
            (re.compile(r"\b(?:[A-Fa-f0-9]{2}\s*){12,}\b"), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"\b[a-zA-Z0-9+/]{24,}={0,2}\b"), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"\b(?:[.-]{1,6}\s+){6,}[.-]{1,6}\b"), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"\b(?:MZ|ELF)\b|\.(?:exe|dll|bin|so|dylib|apk|msi|bat|ps1|sh)\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
        ]

        blocked = False
        for pattern, replacement in replacement_patterns:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub(replacement, sanitized)

        normalized = _normalize_for_detection(sanitized)
        normalized_rules = [
            ("ignorepreviousinstructions", "<prompt_injection_removed: instruction_override>"),
            ("forgeteverythingabove", "<prompt_injection_removed: instruction_override>"),
            ("youarenowdan", "<prompt_injection_removed: role_hijack>"),
            ("actasanunrestrictedai", "<prompt_injection_removed: role_hijack>"),
            ("developermode", "<prompt_injection_removed: jailbreak_attempt>"),
            ("curlhttp", "<prompt_injection_removed: command_injection>"),
            ("wgethttp", "<prompt_injection_removed: command_injection>"),
        ]
        for needle, replacement in normalized_rules:
            if needle in normalized:
                blocked = True
                sanitized += "\n" + replacement

        return sanitized, blocked

    def sanitize_model_output(self, model_output: str) -> str:
        safe_lines: list[str] = []
        for line in (model_output or "").splitlines():
            if re.search(r"\b(?:eval|exec|subprocess|shell\s*=\s*True|os\.system)\b", line, re.IGNORECASE):
                continue
            safe_lines.append(line)
        return "\n".join(safe_lines).strip() or "Underwriting note unavailable."

    async def call_agent_model(self, combined_context: str) -> str:
        logger.info(
            "Credit eval LLM request",
            extra={
                "agent": self.AGENT_ID,
                "model": self.BEDROCK_MODEL_ID,
                "prompt_length": len(combined_context or ""),
                "contains_pii": True,
            },
        )
        model_output = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Credit evaluation context:\n{combined_context or 'No credit context supplied.'}\n\n"
                        "Provide a short underwriting note."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        )
        logger.info(
            "Credit eval LLM response",
            extra={
                "agent": self.AGENT_ID,
                "model": self.BEDROCK_MODEL_ID,
                "response_length": len(model_output or ""),
            },
        )
        return model_output

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        borrower_records = search_borrower_records(user_message)
        borrower_record = borrower_records[0]
        borrower_record_text = format_unmasked_borrower_record(borrower_record)
        combined_context = (
            f"Seed source document: {SEED_SOURCE_DOCUMENT}\n\n"
            f"Borrower record:\n{borrower_record_text}\n\n"
            f"User request:\n{user_message}"
        ).strip()
        safe_combined_context, blocked_unsafe_content = self.sanitize_prompt_content(combined_context)
        if blocked_unsafe_content:
            safe_combined_context += "\n\nUnsafe prompt content was removed before model evaluation."
        model_output = self.sanitize_model_output(await self.call_agent_model(safe_combined_context))

        # Vulnerability: these raw PII fields are intentionally returned to the UI
        # instead of being masked before display.
        masked_dob = _mask_year_or_dob(borrower_record['date_of_birth'])
        masked_ssn = _mask_ssn(borrower_record['ssn'])
        masked_address = _mask_address(borrower_record['address'])
        response = (
            f"Borrower snapshot for {borrower_record['name']}\n"
            f"Loan status: {borrower_record['loan_status']}\n"
            f"Loan type: {borrower_record['loan_type']}\n"
            f"Credit score: {borrower_record['credit_score']}\n"
            f"Loan balance: ${borrower_record['loan_balance']:,}\n\n"
            "Borrower details shown in UI:\n"
            f"DOB: {masked_dob}\n"
            f"SSN: {masked_ssn}\n"
            f"Address: {masked_address}\n\n"
            f"Underwriting note:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


credit_eval_agent = CreditEvalAgent()
