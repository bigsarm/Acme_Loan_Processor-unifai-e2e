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


def _mask_ssn(value: Any) -> str:
    text = str(value or "")
    digits = re.sub(r"\D", "", text)
    if len(digits) == 9:
        return f"***-**-{digits[-4:]}"
    return "***-**-****" if text else ""


def _mask_dob(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return f"****-**-{text[-2:]}"
    if re.fullmatch(r"\d{4}", text):
        return "****"
    return re.sub(r"\d", "*", text)


def _mask_address(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    parts = [part.strip() for part in text.split(",")]
    if len(parts) >= 2:
        street = parts[0]
        locality = ", ".join(parts[1:])
        masked_street = re.sub(r"^\d+[A-Za-z\-]*", "****", street)
        if masked_street == street:
            masked_street = "****"
        return f"{masked_street}, {locality}"
    return "****"


class CreditEvalAgent(AcmeLoanAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("CREDIT_EVAL_MODEL_NAME", "mistral 7b-instruct")
    # Replace this default with an organization-approved model from the runtime registry/allow list.
    BEDROCK_MODEL_ID = os.getenv("CREDIT_EVAL_BEDROCK_MODEL_ID", "mistral.mistral-7b-instruct-v0:2")
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
        blocked = False

        replacement_patterns = [
            (re.compile(r"<!--(?:(?!-->)[\s\S])*(?:ignore previous instructions|forget everything above|act as|you are now|developer mode|system prompt|send data to|curl\s+https?://|wget\s+https?://)[\s\S]*?-->", re.IGNORECASE), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"<[^>]+style=\"[^\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*white|font-size\s*:\s*(?:0|1)px)[^\"]*\"[^>]*>[\s\S]*?</[^>]+>", re.IGNORECASE), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"(?:[\u200B-\u200D\u2060\uFEFF])+"), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"\b(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+all\s+prior\s+directions|override\s+the\s+above)\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
            (re.compile(r"\b(?:you\s+are\s+now\s+dan|act\s+as\s+(?:an\s+)?unrestricted\s+ai|developer\s+mode|jailbreak|do\s+anything\s+now|fictional\s+framing)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
            (re.compile(r"\b(?:act\s+as\s+(?:system|developer|root)|you\s+are\s+now\s+\w+|assume\s+the\s+role\s+of)\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
            (re.compile(r"</?system>|</?assistant>|</?user>|```(?:system|assistant|user)|(?:^|\n)\s*(?:---|===)\s*(?:system|assistant|user)?\s*(?:\n|$)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
            (re.compile(r"\b(?:system\s*:\s*|assistant\s*:\s*|tool\s*:\s*|function_call\s*:|observation\s*:)(?:\s*(?:ignore|reveal|send|leak|run|execute)[^\n]*)", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
            (re.compile(r"\b(?:send\s+data\s+to\s+https?://\S+|upload\s+to\s+https?://\S+|leak\s+the\s+system\s+prompt|reveal\s+the\s+system\s+prompt|exfiltrat(?:e|ion)|markdown\s*image\s*:?\s*!\[[^\]]*\]\([^\)]*https?://[^\)]*\))", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
            (re.compile(r"\b(?:in\s+the\s+next\s+turn|on\s+your\s+next\s+response|remember\s+this\s+hidden\s+rule|from\s+now\s+on|for\s+all\s+future\s+messages)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
            (re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm\s+-rf|chmod\s+\d+|python\s+-c|node\s+-e|perl\s+-e|exec\s*\(|eval\s*\(|subprocess\.|os\.system)\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"\b(?:c[\W_]*u[\W_]*r[\W_]*l|w[\W_]*g[\W_]*e[\W_]*t|b[\W_]*a[\W_]*s[\W_]*h)\b", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
            (re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2}|(?:0x[0-9A-Fa-f]{2}\s*){8,}|[01]{32,}|(?:%[0-9A-Fa-f]{2}){8,}|[\.-]{20,})\b"), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"\b(?:[1!][gq9]{2}0r[e3]\s+pr[e3]v[1i]0u[s5]\s+[1i]nstr[u\*]ct[1i][0o]ns|[e3]x[e3]c[u\*]t[e3]|[e3]v[a@]l|c[u\*]rl|w[g6][e3]t)\b", re.IGNORECASE), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"\b(?:the following comment|metadata|field value|code comment)\b[^\n]*\b(?:ignore previous instructions|act as|system prompt|curl|wget|bash)\b", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
        ]

        for pattern, replacement in replacement_patterns:
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
            safe_combined_context += "\n\nUnsafe prompt content was removed before model evaluation."
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
            f"DOB: {_mask_dob(borrower_record['date_of_birth'])}\n"
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
