"""Credit Eval Agent class with explicit model invocation."""

import logging
import os
import re
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .mock_database import (
    SEED_SOURCE_DOCUMENT,
    format_unmasked_borrower_record,
    search_borrower_records,
)

logger = logging.getLogger(__name__)


def _decode_obfuscated_text(text: str) -> str:
    decoded_variants = [text or ""]
    url_decoded = urllib.parse.unquote(text or "")
    if url_decoded not in decoded_variants:
        decoded_variants.append(url_decoded)

    compact = re.sub(r"\s+", "", text or "")
    if compact and re.fullmatch(r"[A-Za-z0-9+/=]{24,}", compact):
        try:
            import base64

            base64_decoded = base64.b64decode(compact, validate=True).decode("utf-8", errors="ignore")
            if base64_decoded and base64_decoded not in decoded_variants:
                decoded_variants.append(base64_decoded)
        except Exception:
            pass

    return "\n".join(decoded_variants)


def _normalize_leetspeak(text: str) -> str:
    return (text or "").translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}))


def _mask_ui_pii_value(label: str, value: Any) -> str:
    text_value = "" if value is None else str(value)
    normalized_label = (label or "").lower()
    if normalized_label == "dob":
        year_match = re.search(r"\b(19|20)\d{2}\b", text_value)
        return year_match.group(0) if year_match else "<masked_dob>"
    if normalized_label == "ssn":
        digit_groups = re.fullmatch(r"(\d{3})-(\d{2})-(\d{4})", text_value)
        if digit_groups:
            return f"***-**-{digit_groups.group(3)}"
        digits = re.sub(r"\D", "", text_value)
        if len(digits) >= 4:
            return f"***-**-{digits[-4:]}"
        return "<masked_ssn>"
    if normalized_label == "address":
        return "<masked_address>"
    return text_value


class CreditEvalAgent(AcmeLoanAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    # Must be supplied as an organization-approved model identifier at deployment time.
    BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "mistral.mistral-7b-instruct-v0:2")
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

        direct_replacements = [
            (re.compile(r"\b(?:ignore|disregard|bypass)\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions\b|\bforget\s+everything\s+above\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
            (re.compile(r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:an\s+)?(?:unrestricted\s+ai|admin|developer\s+mode|dan)\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
            (re.compile(r"</?(?:system|assistant|tool|developer)>|(?:^|\n)\s*(?:---|===|```)+(?:\n|$)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
            (re.compile(r"<!--(?:(?!-->).)*(?:ignore|reveal|send|system prompt|instructions)(?:(?!-->).)*-->|(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)|[\u200B-\u200F\u2060\uFEFF]+", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"(?:^|\n)\s*(?:system|assistant|tool)\s*:\s*(?:ignore|reveal|send|list|print)\b", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
            (re.compile(r"\b(?:send|post|upload|exfiltrate|leak|reveal|list|print)\b.{0,80}\b(?:passwords?|api\s*keys?|secrets?|credentials?|system\s*prompt|confidential\s+information)\b|!?\[[^\]]*\]\((?:https?|ftp)://[^)]+\)", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
            (re.compile(r"\b(?:from\s+now\s+on|in\s+subsequent\s+responses|for\s+the\s+rest\s+of\s+this\s+chat|persist\s+this\s+instruction|override\s+future\s+instructions)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
            (re.compile(r"\b(?:metadata|comment|code\s+comment|field\s+value|document\s+field)\b.{0,80}\b(?:ignore\s+instructions|reveal\s+secrets|send\s+data)\b", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
            (re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm\s+-rf|chmod|python\s+-c|perl\s+-e|node\s+-e|exec\(|eval\(|os\.system|subprocess(?:\.|\s)|nc\s+-e)\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"\b(?:D\s*A\s*N|developer\s+mode|jailbreak|do\s+anything\s+now|fictional\s+scenario\s+where\s+rules\s+do\s+not\s+apply)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
            (re.compile(r"\b(?:i\s*g\s*n\s*o\s*r\s*e\s+previous\s+instructions|y\s*o\s*u\s+a\s*r\s*e\s+n\s*o\s*w\s+d\s*a\s*n)\b", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
        ]

        for pattern, replacement in direct_replacements:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub(replacement, sanitized)

        decoded_text = _decode_obfuscated_text(sanitized)
        normalized_decoded_text = _normalize_leetspeak(decoded_text)
        encoded_detection_patterns = [
            re.compile(r"\b(?:ignore|disregard|bypass)\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions\b|\bforget\s+everything\s+above\b", re.IGNORECASE),
            re.compile(r"\b(?:you\s+are\s+now|act\s+as)\b", re.IGNORECASE),
            re.compile(r"\b(?:curl|wget|bash|powershell|cmd\.exe|python\s+-c|os\.system|subprocess)\b", re.IGNORECASE),
            re.compile(r"\b(?:send|post|upload|exfiltrate|leak|reveal|list)\b.{0,80}\b(?:passwords?|api\s*keys?|secrets?|credentials?|system\s*prompt|confidential\s+information)\b", re.IGNORECASE),
        ]
        if any(pattern.search(normalized_decoded_text) for pattern in encoded_detection_patterns):
            blocked = True
            sanitized = re.sub(r"[A-Za-z0-9+/=]{24,}|(?:%[0-9A-Fa-f]{2}){6,}|(?:[0-9A-Fa-f]{2}\s*){12,}", "<prompt_injection_removed: encoded_payload>", sanitized)
            sanitized = re.sub(r"\b[i1!][g69][n][o0][r][e3]\b(?:[\s\W_]+\b[p][r][e3][v][i1!][o0][u][s5]\b[\s\W_]+\b[i1!][n][s5][t7][r][u][c][t7][i1!][o0][n][s5]\b)?", "<prompt_injection_removed: encoded_payload>", sanitized, flags=re.IGNORECASE)

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
            f"DOB: {_mask_ui_pii_value('dob', borrower_record['date_of_birth'])}\n"
            f"SSN: {_mask_ui_pii_value('ssn', borrower_record['ssn'])}\n"
            f"Address: {_mask_ui_pii_value('address', borrower_record['address'])}\n\n"
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
