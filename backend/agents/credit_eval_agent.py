"""Credit Eval Agent class with explicit model invocation."""

import logging
import re
import codecs
from typing import Any


def _mask_year_of_birth(value: str) -> str:
    text = str(value or "")
    if not text:
        return text
    year_match = re.search(r"\b(19\d{2}|20\d{2})\b", text)
    if year_match:
        return text[: year_match.start(1)] + "<masked_year_of_birth>" + text[year_match.end(1) :]
    return "<masked_year_of_birth>"


def _mask_ssn(value: str) -> str:
    text = str(value or "")
    if not text:
        return text
    return re.sub(r"\b\d{3}-\d{2}-(\d{4})\b", r"***-**-\1", text)


def _mask_home_address(value: str) -> str:
    text = str(value or "")
    if not text:
        return text
    return "<masked_home_address>"


def _decode_rot13(text: str) -> str:
    try:
        return codecs.decode(text, "rot_13")
    except Exception:
        return text

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
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"  # Replace with an organization-approved model from the runtime registry/allow list.
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

        direct_patterns = [
            (re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
            (re.compile(r"\b(?:you\s+are\s+now|act\s+as)\s+(?:an\s+)?(?:unrestricted|admin|root|developer\s+mode|dan)\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
            (re.compile(r"</?(?:system|assistant|tool|developer)>|(?:^|\n)\s*(?:---|===)\s*(?:\n|$)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
            (re.compile(r"<!--.*?(?:ignore|reveal|send|leak|curl|wget|bash|exec|eval).*?-->", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"(?:<span|<div)[^>]*(?:display\s*:\s*none|font-size\s*:\s*0(?:px)?|color\s*:\s*#?fff(?:fff)?)[^>]*>.*?</(?:span|div)", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"[\u200b-\u200f\ufeff]+"), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"\b(?:system|assistant|tool)\s*:\s*(?:ignore|reveal|send|leak|override)\b", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
            (re.compile(r"!\[[^\]]*\]\([^\)]*https?://[^\)]*\)", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
            (re.compile(r"\b(?:send|post|upload|exfiltrate|leak|reveal|expose|list)\b[^\n]{0,120}\b(?:passwords?|api\s*keys?|secrets?|system\s+prompt|confidential\s+information|to\s+https?://)\b", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
            (re.compile(r"\b(?:in\s+the\s+next\s+turn|on\s+your\s+next\s+response|from\s+now\s+on|persist\s+this\s+instruction|store\s+this\s+instruction)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
            (re.compile(r"\b(?:seed\s+source\s+document|borrower\s+record|metadata|comment)\b[^\n]{0,120}\b(?:ignore|override|reveal|send|leak)\b", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
            (re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|chmod|python\s+-c|perl\s+-e|node\s+-e|exec|eval|subprocess|os\.system)\b(?:[^\n]{0,80})", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"\b(?:ignore\W{0,10}previous\W{0,10}instructions|i\W*g\W*n\W*o\W*r\W*e\W*.*p\W*r\W*e\W*v\W*i\W*o\W*u\W*s)\b", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
            (re.compile(r"\b(?:dan|developer\s+mode|jailbreak|bypass\s+safety|fictional\s+framing)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
        ]

        for pattern, replacement in direct_patterns:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub(replacement, sanitized)

        encoded_markers = [
            (re.compile(r"\b[a-fA-F0-9]{32,}\b"), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"(?:%[0-9A-Fa-f]{2}){6,}"), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b"), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"\bc[\W_]*u[\W_]*r[\W_]*l\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"\bi[g69!1][n][o0]r[e3]\b[^\n]{0,40}\b[i1]nstr[u\$]ct[i1][o0]ns\b", re.IGNORECASE), "<prompt_injection_removed: encoded_payload>"),
        ]
        for pattern, replacement in encoded_markers:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub(replacement, sanitized)

        normalized_candidates = []
        if re.search(r"(?:%[0-9A-Fa-f]{2}){6,}", sanitized):
            try:
                from urllib.parse import unquote

                normalized_candidates.append(unquote(sanitized))
            except Exception:
                pass
        if re.search(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b", sanitized):
            import base64

            for token in re.findall(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b", sanitized):
                try:
                    decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
                    normalized_candidates.append(decoded)
                except Exception:
                    continue
        if re.search(r"\b[a-fA-F0-9]{32,}\b", sanitized):
            for token in re.findall(r"\b[a-fA-F0-9]{32,}\b", sanitized):
                try:
                    normalized_candidates.append(bytes.fromhex(token).decode("utf-8", errors="ignore"))
                except Exception:
                    continue
        normalized_candidates.append(_decode_rot13(sanitized))

        encoded_attack_check = re.compile(
            r"\b(?:ignore\s+previous\s+instructions|you\s+are\s+now|act\s+as\s+unrestricted|reveal\s+(?:all\s+)?(?:passwords?|api\s*keys?|secrets?|confidential\s+information)|curl\s+https?://|wget\s+https?://|bash\s+-c|python\s+-c)\b",
            re.IGNORECASE,
        )
        if any(candidate and encoded_attack_check.search(candidate) for candidate in normalized_candidates):
            blocked = True
            sanitized = re.sub(r"\b(?:[A-Za-z0-9+/]{20,}={0,2}|[a-fA-F0-9]{32,})\b|(?:%[0-9A-Fa-f]{2}){6,}", "<prompt_injection_removed: encoded_payload>", sanitized)
            sanitized = re.sub(r"\bi[g69!1][n][o0]r[e3]\b[^\n]{0,40}\b[i1]nstr[u\$]ct[i1][o0]ns\b", "<prompt_injection_removed: encoded_payload>", sanitized, flags=re.IGNORECASE)

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
            f"DOB: {_mask_year_of_birth(borrower_record['date_of_birth'])}\n"
            f"SSN: {_mask_ssn(borrower_record['ssn'])}\n"
            f"Address: {_mask_home_address(borrower_record['address'])}\n\n"
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
