"""Credit Eval Agent class with explicit model invocation."""

import logging
import os
import re
from typing import Any

from .framework import AcmeLoanAgentFramework
from .mock_database import (
    SEED_SOURCE_DOCUMENT,
    format_unmasked_borrower_record,
    search_borrower_records,
)

logger = logging.getLogger(__name__)


def _mask_year_of_birth(date_of_birth: Any) -> str:
    value = str(date_of_birth or "")
    year_match = re.search(r"(\d{4})", value)
    return "****" if year_match else value or "****"


def _mask_ssn(ssn: Any) -> str:
    digits = re.sub(r"\D", "", str(ssn or ""))
    if len(digits) >= 4:
        return f"***-**-{digits[-4:]}"
    return "***-**-****"


def _mask_address(address: Any) -> str:
    value = str(address or "").strip()
    if not value:
        return "[masked address]"
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if len(parts) >= 2:
        return f"[masked street], {', '.join(parts[1:])}"
    return "[masked address]"


class CreditEvalAgent(AcmeLoanAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "Configured Bedrock model"
    BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "mistral.mistral-7b-instruct-v0:2")
    DESCRIPTION = "Evaluates creditworthiness, loan status, and borrower notes for loan decisions. Replace the default model configuration with an organization-approved LLM from the runtime registry."
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
        replacements = [
            (re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions|forget\s+everything\s+above|disregard\s+(?:the\s+)?(?:system|developer|prior)\s+instructions", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
            (re.compile(r"you\s+are\s+now\s+dan|act\s+as\s+(?:unrestricted|a\s+system)|developer\s+mode|jailbreak", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
            (re.compile(r"</?(?:system|assistant|developer|tool|user)>|---+|```(?:system|assistant|developer|tool)?", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
            (re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})|(?:0x[0-9A-Fa-f]{8,})|(?:%[0-9A-Fa-f]{2}){6,}|(?:\\u[0-9A-Fa-f]{4}){4,}|(?:[.-]{10,}\s?){2,}|(?:[a-zA-Z]\s*(?:[^\w\s]\s*)?[0-9@431!|$]{1,}\s*){4,}", re.IGNORECASE), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"<!--.*?-->|(?:font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*white)|[\u200B-\u200F\u2060\uFEFF]+", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"(?:^|\n)\s*(?:system|assistant|tool)\s*:\s*", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
            (re.compile(r"(?:send|post|upload|exfiltrat\w*|leak|reveal).*(?:https?://|www\.|system\s+prompt|secrets?|credentials?)|!\[[^\]]*\]\([^)]*https?://[^)]*\)", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
            (re.compile(r"in\s+(?:the\s+)?next\s+turn|persist\s+this\s+instruction|remember\s+this\s+secret|override\s+future\s+instructions", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
            (re.compile(r"(?:metadata|comment|field|filename|header)\s*:\s*.*(?:ignore|override|execute)", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
            (re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm|chmod|python\s+-c|exec|eval|subprocess|os\.system|nc|netcat|scp|ssh)\b|(?:/bin/sh|\.exe\b|\.dll\b)", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"(?:i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s)|(?:c\s*u\s*r\s*l)|(?:b\s*a\s*s\s*h)", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
            (re.compile(r"do\s+anything\s+now|unfiltered|bypass\s+safety|fictional\s+framing|simulate\s+developer\s+mode", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
        ]

        blocked = False
        for pattern, replacement in replacements:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub(replacement, sanitized)

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
            safe_combined_context += "\n\nUnsafe or prompt-injection content was neutralized before model evaluation."
        model_output = self.sanitize_model_output(await self.call_agent_model(safe_combined_context))

        # Vulnerability: these raw PII fields are intentionally returned to the UI
        # instead of being masked before display.
        response = (
            f"Borrower snapshot for {borrower_record['name']}\n"
            f"Loan status: {borrower_record['loan_status']}\n"
            f"Loan type: {borrower_record['loan_type']}\n"
            f"Credit score: {borrower_record['credit_score']}\n"
            f"Loan balance: ${borrower_record['loan_balance']:,}\n\n"
            "Borrower details shown in UI:\n"
            f"DOB: {_mask_year_of_birth(borrower_record['date_of_birth'])}\n"
            f"SSN: {_mask_ssn(borrower_record['ssn'])}\n"
            f"Address: {_mask_address(borrower_record['address'])}\n\n"
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
