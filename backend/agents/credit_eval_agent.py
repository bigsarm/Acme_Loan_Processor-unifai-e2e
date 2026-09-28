"""Credit Eval Agent class with explicit model invocation."""

import logging
import re
from typing import Any


def _mask_dob(value: str) -> str:
    text = str(value or "")
    match = re.search(r"\b(\d{4})(?:-\d{2}-\d{2}|/\d{2}/\d{4}|\s+\d{1,2},\s*\d{4})\b", text)
    if match:
        return match.group(1)
    return "[masked]" if text else ""


def _mask_ssn(value: str) -> str:
    text = str(value or "")
    return re.sub(r"\b(\d{3})-(\d{2})-(\d{4})\b", "***-**-\\3", text) or text


def _mask_address(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parts = [part.strip() for part in text.split(",")]
    if len(parts) >= 2:
        street = parts[0]
        masked_street = re.sub(r"^\d+", "***", street)
        return ", ".join([masked_street] + parts[1:])
    return re.sub(r"\d", "*", text)

from .framework import AcmeLoanAgentFramework
from .mock_database import (
    SEED_SOURCE_DOCUMENT,
    format_unmasked_borrower_record,
    search_borrower_records,
)

logger = logging.getLogger(__name__)


class CreditEvalAgent(AcmeLoanAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    # Replace this model with an organization-approved LLM from the allow list/registry.
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
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
            (re.compile(r"\b(?:ignore previous instructions|ignore all previous instructions|forget everything above|disregard previous instructions)\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
            (re.compile(r"\b(?:you are now DAN|act as unrestricted|act as an unrestricted|you are now|developer mode|do anything now)\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
            (re.compile(r"</?(?:system|assistant|user|tool)>|(?:^|\n)\s*(?:---+|===+|```+)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
            (re.compile(r"<!--.*?-->", re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"[\u200B-\u200F\u2060\uFEFF]+"), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"\b(?:system\s*:|assistant\s*:|tool\s*:|function\s*:|developer\s*:)\s*", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
            (re.compile(r"!\[[^\]]*\]\([^)]*https?://[^)]*\)|\b(?:send data to|post to|upload to|leak the system prompt|reveal the system prompt|exfiltrate)\b", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
            (re.compile(r"\b(?:in the next turn|when asked later|from now on|remember this instruction|persist this instruction|override future instructions)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
            (re.compile(r"\b(?:metadata|front matter|yaml|json|code comment|comment says|hidden field)\b.*\b(?:ignore|override|system|instruction)\b", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
            (re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm|chmod|python\s+-c|exec|eval|subprocess|os\.system)\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"\bc[\W_]*u[\W_]*r[\W_]*l\b", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
            (re.compile(r"\bc[4@]rl\b|\bw[6g]et\b|\br[mn]\b", re.IGNORECASE), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"\b(?:DAN|developer mode|jailbreak|fictional scenario|hypothetical bypass|bypass safety)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
            (re.compile(r"(?:[A-Fa-f0-9]{2}\s*){16,}|(?:%[0-9A-Fa-f]{2}){8,}|[A-Za-z0-9+/]{24,}={0,2}", re.IGNORECASE), "<prompt_injection_removed: encoded_payload>"),
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
        masked_dob = _mask_dob(borrower_record['date_of_birth'])
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
