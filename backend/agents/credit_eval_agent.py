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


_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\ufeff\u2060"


def _mask_dob_for_ui(value: Any) -> str:
    text = str(value or "")
    match = re.search(r"\b(\d{4})-(\d{2})-(\d{2})\b", text)
    if match:
        return f"{match.group(1)}-**-**"
    match = re.search(r"\b(\d{1,2})/(\d{1,2})/(\d{4})\b", text)
    if match:
        return f"**/**/{match.group(3)}"
    return "[masked]" if text else ""


def _mask_ssn_for_ui(value: Any) -> str:
    text = str(value or "")
    return re.sub(r"\b(\d{3})-(\d{2})-(\d{4})\b", r"***-**-\3", text)


def _mask_address_for_ui(value: Any) -> str:
    text = str(value or "")
    return "[masked home address]" if text else ""


class CreditEvalAgent(AcmeLoanAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = os.getenv("CREDIT_EVAL_BEDROCK_MODEL_ID", "mistral.mistral-7b-instruct-v0:2")
    # Replace the default above with an organization-approved model from the runtime registry/allow list.
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
            (re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
            (re.compile(r"\byou\s+are\s+now\s+(?:dan|developer\s+mode|admin\s+mode|root)\b|\bact\s+as\s+(?:an\s+)?(?:unrestricted|unfiltered)\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
            (re.compile(r"</?(?:system|assistant|tool|developer)>|(?:^|\n)\s*(?:---|===)\s*(?:\n|$)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
            (re.compile(r"<!--.*?(?:ignore|reveal|leak|system prompt|password|api key|curl|wget|bash).*?-->", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"\b(?:system|assistant|tool)\s*:\s*(?:ignore|reveal|leak|send|fetch|exfiltrate)\b", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
            (re.compile(r"\b(?:send|post|upload|exfiltrate|leak|reveal|list)\b.{0,80}\b(?:passwords?|api\s*keys?|secrets?|confidential information|system prompt|https?://\S+|www\.\S+)\b", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
            (re.compile(r"\b(?:from\s+now\s+on|in\s+future\s+turns|next\s+messages?|subsequent\s+responses?)\b.{0,80}\b(?:ignore|override|bypass|remember\s+this\s+rule)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
            (re.compile(r"\b(?:metadata|comment|code\s+comment|file\s+header|seed source document|borrower record)\b.{0,80}\b(?:ignore|override|reveal|leak|send)\b", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
            (re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm\s+-rf|chmod\s+\+x|python\s+-c|perl\s+-e|exec\(|eval\(|subprocess\.|os\.system)\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"\b(?:d\s*a\s*n|developer\s+mode|jailbreak|bypass\s+safety|fictional\s+scenario\s+where\s+rules\s+do\s+not\s+apply)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
            (re.compile(r"\b(?:i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s)\b", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
            (re.compile(r"[%][0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2}){3,}|\\x[0-9A-Fa-f]{2}(?:\\x[0-9A-Fa-f]{2}){3,}|(?:\b[01]{8}(?:\s+[01]{8}){3,}\b)", re.IGNORECASE), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"\b(?:1gn0r[e3]|d1sr[e3]g[a@]rd|0v[e3]rr[i1]d[e3]|[r2][e3]v[e3][a@]l\s+[a@]ll\s+s[e3]cr[e3]ts?)\b", re.IGNORECASE), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"[A-Za-z0-9+/]{32,}={0,2}"), "<prompt_injection_removed: encoded_payload>"),
        ]

        blocked = False
        if any(char in sanitized for char in _ZERO_WIDTH_CHARS):
            blocked = True
            sanitized = re.sub(f"[{re.escape(_ZERO_WIDTH_CHARS)}]+", "<prompt_injection_removed: hidden_text>", sanitized)

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
            f"DOB: {_mask_dob_for_ui(borrower_record['date_of_birth'])}\n"
            f"SSN: {_mask_ssn_for_ui(borrower_record['ssn'])}\n"
            f"Address: {_mask_address_for_ui(borrower_record['address'])}\n\n"
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
