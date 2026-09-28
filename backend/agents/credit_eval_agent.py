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


ZERO_WIDTH_CHARS_RE = re.compile(r"[\u200B-\u200F\u2060\uFEFF]")
BASE64_BLOCK_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
HEX_BLOCK_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){8,}\b")
MORSE_RE = re.compile(r"\b(?:[.-]{1,6}[ /]+){3,}[.-]{1,6}\b")
SPLIT_PAYLOAD_RE = re.compile(r"\b(?:i\W*g\W*n\W*o\W*r\W*e|d\W*a\W*n|e\W*v\W*a\W*l|c\W*u\W*r\W*l)\b", re.IGNORECASE)
LEETSPEAK_INSTRUCTION_RE = re.compile(r"\b(?:1gn0r3|d3v3l0p3r\s*m0d3|3x3c|3v4l|c(?:(?:4)|(?:@))rl|w(?:6|9)et)\b", re.IGNORECASE)
DIRECT_INSTRUCTION_OVERRIDE_RE = re.compile(r"\b(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|forget\s+everything\s+above|disregard\s+(?:the\s+)?(?:system|developer|prior)\s+instructions|override\s+(?:all\s+)?instructions)\b", re.IGNORECASE)
ROLE_HIJACK_RE = re.compile(r"\b(?:you\s+are\s+now\s+dan|act\s+as\s+(?:unrestricted|a\s+system|dan)|pretend\s+to\s+be\s+(?:the\s+)?system|assume\s+the\s+role\s+of)\b", re.IGNORECASE)
DELIMITER_ESCAPE_RE = re.compile(r"(?:</?system>|</?assistant>|</?user>|\[/?SYSTEM\]|\[/?INST\]|```(?:system|assistant|user)|----+|====+)", re.IGNORECASE)
FAKE_SYSTEM_MESSAGE_RE = re.compile(r"\b(?:system\s*:\s*you\s+must|developer\s*:\s*|tool\s*:\s*|assistant\s*:\s*ignore|function_call|tool_call)\b", re.IGNORECASE)
EXFILTRATION_RE = re.compile(r"(?:!\[[^\]]*\]\([^)]*https?://[^)]*\)|\b(?:send|post|upload|exfiltrate|leak|reveal|expose)\b.{0,80}\b(?:system\s+prompt|secrets?|credentials?|data)\b|https?://[^\s]+)", re.IGNORECASE | re.DOTALL)
CONTEXT_POISONING_RE = re.compile(r"\b(?:in\s+(?:the\s+)?next\s+turn|from\s+now\s+on|for\s+the\s+rest\s+of\s+this\s+chat|remember\s+this\s+instruction|persist\s+this\s+instruction)\b", re.IGNORECASE)
COMMAND_INJECTION_RE = re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm\s+-rf|chmod|nc|ncat|python\s+-c|perl\s+-e|ruby\s+-e|node\s+-e|exec|eval|subprocess|os\.system)\b", re.IGNORECASE)
INDIRECT_INJECTION_RE = re.compile(r"\b(?:seed\s+source\s+document|borrower\s+record|metadata|comment)\b.{0,80}\b(?:ignore|override|follow\s+these\s+instructions|system\s+prompt)\b", re.IGNORECASE | re.DOTALL)
HIDDEN_HTML_COMMENT_RE = re.compile(r"<!--.*?(?:ignore|system|developer|instruction|prompt).*?-->", re.IGNORECASE | re.DOTALL)
CSS_HIDDEN_TEXT_RE = re.compile(r"<(?:span|div|p)[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?|color\s*:\s*white)[^>]*>.*?</(?:span|div|p)>", re.IGNORECASE | re.DOTALL)
URL_ENCODED_INSTRUCTION_RE = re.compile(r"%(?:69|49)%(?:67|47)%(?:6e|4e)%(?:6f|4f)%(?:72|52)%(?:65|45)", re.IGNORECASE)


def _mask_dob(value: Any) -> str:
    text = str(value or "")
    match = re.search(r"\b(19|20)\d{2}\b", text)
    if match:
        return f"****-**-{match.group(0)}"
    return "[masked_dob]" if text else ""


def _mask_ssn(value: Any) -> str:
    text = str(value or "")
    digits = re.sub(r"\D", "", text)
    if len(digits) == 9:
        return f"***-**-{digits[-4:]}"
    return "[masked_ssn]" if text else ""


def _mask_address(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    parts = [part.strip() for part in text.split(",")]
    if len(parts) >= 2:
        locality = ", ".join(part for part in parts[1:] if part)
        return f"[masked_address], {locality}" if locality else "[masked_address]"
    return "[masked_address]"


class CreditEvalAgent(AcmeLoanAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"  # Replace with an organization-approved registry model before deployment.
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

        decoded_text = unquote(sanitized)
        encoded_payload_detected = any(
            pattern.search(sanitized) or pattern.search(decoded_text)
            for pattern in [BASE64_BLOCK_RE, HEX_BLOCK_RE, MORSE_RE, URL_ENCODED_INSTRUCTION_RE]
        )
        if encoded_payload_detected:
            blocked = True
            sanitized = BASE64_BLOCK_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
            sanitized = HEX_BLOCK_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
            sanitized = MORSE_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
            sanitized = URL_ENCODED_INSTRUCTION_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)

        replacement_patterns = [
            (HIDDEN_HTML_COMMENT_RE, "<prompt_injection_removed: hidden_text>"),
            (CSS_HIDDEN_TEXT_RE, "<prompt_injection_removed: hidden_text>"),
            (ZERO_WIDTH_CHARS_RE, "<prompt_injection_removed: hidden_text>"),
            (DIRECT_INSTRUCTION_OVERRIDE_RE, "<prompt_injection_removed: instruction_override>"),
            (ROLE_HIJACK_RE, "<prompt_injection_removed: role_hijack>"),
            (DELIMITER_ESCAPE_RE, "<prompt_injection_removed: delimiter_escape>"),
            (FAKE_SYSTEM_MESSAGE_RE, "<prompt_injection_removed: fake_system_message>"),
            (EXFILTRATION_RE, "<prompt_injection_removed: exfiltration_attempt>"),
            (CONTEXT_POISONING_RE, "<prompt_injection_removed: context_poisoning>"),
            (INDIRECT_INJECTION_RE, "<prompt_injection_removed: indirect_injection>"),
            (COMMAND_INJECTION_RE, "<prompt_injection_removed: command_injection>"),
            (SPLIT_PAYLOAD_RE, "<prompt_injection_removed: split_payload>"),
            (LEETSPEAK_INSTRUCTION_RE, "<prompt_injection_removed: encoded_payload>"),
        ]

        for pattern, replacement in replacement_patterns:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub(replacement, sanitized)

        if re.search(r"\b(?:dan|developer\s+mode|jailbreak|do\s+anything\s+now|fictional\s+framing)\b", sanitized, re.IGNORECASE):
            blocked = True
            sanitized = re.sub(
                r"\b(?:dan|developer\s+mode|jailbreak|do\s+anything\s+now|fictional\s+framing)\b",
                "<prompt_injection_removed: jailbreak_attempt>",
                sanitized,
                flags=re.IGNORECASE,
            )

        if re.search(r"\b(?:tiny\s+font|font-size\s*:\s*0|white\s+on\s+white|invisible\s+text|hidden\s+prompt)\b", sanitized, re.IGNORECASE):
            blocked = True
            sanitized = re.sub(
                r"\b(?:tiny\s+font|font-size\s*:\s*0|white\s+on\s+white|invisible\s+text|hidden\s+prompt)\b",
                "<prompt_injection_removed: hidden_text>",
                sanitized,
                flags=re.IGNORECASE,
            )

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
