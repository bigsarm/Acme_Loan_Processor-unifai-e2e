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


def _mask_ssn(value: str) -> str:
    digits = re.sub(r"\D", "", value or "")
    if len(digits) >= 4:
        return f"***-**-{digits[-4:]}"
    return "***-**-****"


def _mask_dob(value: str) -> str:
    text = value or ""
    year_match = re.search(r"(19|20)\d{2}", text)
    if year_match:
        return f"**/**/{year_match.group(0)}"
    return "**/**/****"


def _mask_address(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return "[masked address]"
    parts = [part.strip() for part in text.split(",")]
    if len(parts) >= 2:
        return f"[masked street], {', '.join(parts[1:])}"
    return "[masked address]"


class CreditEvalAgent(AcmeLoanAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = os.getenv("CREDIT_EVAL_BEDROCK_MODEL_ID", "mistral.mistral-7b-instruct-v0:2")
    # Replace this default with an organization-approved model from the runtime registry/allow list.
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
        suspicious_patterns = [
            (re.compile(r"(?i)(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?"), "<prompt_injection_removed: instruction_override>"),
            (re.compile(r"(?i)you\s+are\s+now\s+(?:dan|developer mode|unrestricted)|act\s+as\s+(?:dan|unrestricted)|jailbreak|bypass\s+safety|fictional\s+framing"), "<prompt_injection_removed: jailbreak_attempt>"),
            (re.compile(r"(?i)</?(?:system|assistant|user|tool)>|\[/?(?:system|assistant|user|tool)\]|(?:^|\n)\s*[-=]{3,}\s*(?:system prompt|instructions?)\s*[-=]{3,}"), "<prompt_injection_removed: delimiter_escape>"),
            (re.compile(r"<!--.*?-->", re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"[\u200B-\u200F\u2060\uFEFF]"), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"(?i)(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*white\s*;?\s*background(?:-color)?\s*:\s*white)"), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"(?i)[A-F0-9]{32,}|(?:[A-Za-z0-9+/]{24,}={0,2})|(?:%[0-9A-Fa-f]{2}){8,}|(?:[01]{8}\s*){8,}|(?:[.\-/]{0,2}[a-zA-Z0-9]{1,2}){12,}"), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"(?i)(?:s3nd|3xfil|l34k|1gn0r3|pr3v10us|1nstruct10ns|sy5tem|t00l)"), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"(?i)(?:^|\n)\s*(?:system|assistant|tool)\s*:\s*"), "<prompt_injection_removed: fake_system_message>"),
            (re.compile(r"(?i)(?:send|post|upload|exfiltrate|leak).{0,40}(?:https?://|www\.|webhook|endpoint)|!\[[^\]]*\]\([^\)]*https?://|system\s+prompt|secret[s]?|credential[s]?"), "<prompt_injection_removed: exfiltration_attempt>"),
            (re.compile(r"(?i)(?:in\s+the\s+next\s+turn|from\s+now\s+on|persist\s+this\s+instruction|every\s+future\s+response|use\s+this\s+rule\s+for\s+all\s+future)"), "<prompt_injection_removed: context_poisoning>"),
            (re.compile(r"(?i)(?:metadata|comment|code\s+comment|file\s+header|document)\s*:\s*.*(?:ignore|override|execute|system)"), "<prompt_injection_removed: indirect_injection>"),
            (re.compile(r"(?i)\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm|chmod|python\s+-c|exec|eval|subprocess|os\.system|nc|netcat)\b|`[^`]+`|\$\([^)]+\)"), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"(?is)(?:i\s*g\s*n\s*o\s*r\s*e|d\s*a\s*n|b\s*y\s*p\s*a\s*s\s*s|e\s*x\s*e\s*c)(?:[\s\W_]*[a-z]){2,}"), "<prompt_injection_removed: split_payload>"),
            (re.compile(r"\bc[\W_]*u[\W_]*r[\W_]*l\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"\bc[4@]rl\b|\bw[6g]et\b|\br[mn]\b", re.IGNORECASE), "<prompt_injection_removed: encoded_payload>"),
        ]

        blocked = False
        for pattern, replacement in suspicious_patterns:
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
        safe_user_message, _ = self.sanitize_prompt_content(user_message)
        safe_seed_source_document, _ = self.sanitize_prompt_content(SEED_SOURCE_DOCUMENT)
        safe_borrower_record_text, _ = self.sanitize_prompt_content(borrower_record_text)
        combined_context = (
            f"Seed source document: {safe_seed_source_document}\n\n"
            f"Borrower record:\n{safe_borrower_record_text}\n\n"
            f"User request:\n{safe_user_message}"
        ).strip()
        safe_combined_context, blocked_unsafe_content = self.sanitize_prompt_content(combined_context)
        if blocked_unsafe_content:
            safe_combined_context += "\n\nUnsafe prompt content was removed before model evaluation."
        model_output = self.sanitize_model_output(await self.call_agent_model(safe_combined_context))

        masked_dob = _mask_dob(borrower_record.get('date_of_birth', ''))
        masked_ssn = _mask_ssn(borrower_record.get('ssn', ''))
        masked_address = _mask_address(borrower_record.get('address', ''))
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
