"""Rate Check Agent class with explicit OpenRouter + DeepSeek invocation."""

import logging
import os
import re
from typing import Any
from urllib.parse import unquote

from llm.openai_compatible import OpenAICompatibleClient

from .framework import AcmeLoanAgentFramework

logger = logging.getLogger(__name__)


ZERO_WIDTH_PATTERN = re.compile(r"[\u200B-\u200F\u2060\uFEFF]")
HTML_COMMENT_PATTERN = re.compile(r"<!--.*?-->", re.DOTALL | re.IGNORECASE)
BASE64_PATTERN = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
HEX_PATTERN = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){8,}\b")
MORSE_PATTERN = re.compile(r"(?<!\S)[.\-/ ]{16,}(?!\S)")
BINARY_PATTERN = re.compile(r"\b(?:[01]{8}\s+){3,}[01]{8}\b")
URL_ENCODED_INSTRUCTION_PATTERN = re.compile(r"%(?:[0-9a-fA-F]{2}){4,}")
DIRECT_OVERRIDE_PATTERN = re.compile(r"\b(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+(?:all\s+)?prior\s+instructions|override\s+(?:the\s+)?system\s+prompt)\b", re.IGNORECASE)
ROLE_HIJACK_PATTERN = re.compile(r"\b(?:you\s+are\s+now\s+[A-Za-z0-9_-]+|act\s+as\s+(?:an?\s+)?unrestricted(?:\s+AI)?|act\s+as\s+[A-Za-z0-9 _-]{1,40}|developer\s+mode|DAN\b)\b", re.IGNORECASE)
DELIMITER_ESCAPE_PATTERN = re.compile(r"(?:</?system>|</?assistant>|</?user>|<{2,}|>{2,}|\[/?SYSTEM\]|\[/?INST\]|(?:^|\n)\s*(?:---|===){3,}\s*(?:\n|$))", re.IGNORECASE)
FAKE_SYSTEM_MESSAGE_PATTERN = re.compile(r"\b(?:system\s*:\s*|assistant\s*:\s*|tool\s*:\s*|developer\s*message\s*:|function\s*call\s*:|tool\s+output\s*:)\b", re.IGNORECASE)
EXFILTRATION_PATTERN = re.compile(r"\b(?:send\s+(?:the\s+)?data\s+to\s+https?://\S+|upload\s+(?:the\s+)?(?:data|prompt|secrets?)\s+to\s+\S+|leak\s+(?:the\s+)?system\s+prompt|reveal\s+(?:the\s+)?system\s+prompt|markdown\s+image\s+exfil|!\[[^\]]*\]\(https?://[^)]+\))", re.IGNORECASE)
CONTEXT_POISONING_PATTERN = re.compile(r"\b(?:in\s+(?:the\s+)?next\s+turn|on\s+your\s+next\s+reply|remember\s+this\s+for\s+later|from\s+now\s+on\s+ignore|persist\s+this\s+instruction|for\s+the\s+rest\s+of\s+this\s+chat)\b", re.IGNORECASE)
INDIRECT_INJECTION_PATTERN = re.compile(r"\b(?:metadata\s*:\s*ignore\s+instructions|comment\s*:\s*ignore\s+instructions|code\s+comment\s*:\s*ignore\s+instructions|file\s+contents?\s+say\s+to\s+ignore|document\s+instructions?)\b", re.IGNORECASE)
COMMAND_INJECTION_PATTERN = re.compile(r"\b(?:curl\s+https?://\S+|wget\s+https?://\S+|bash\s+-c\b|sh\s+-c\b|zsh\s+-c\b|powershell\b|cmd\.exe\b|rm\s+-rf\b|chmod\s+\d{3,4}\b|python\s+-c\b|exec\s*\(|eval\s*\(|subprocess\.|os\.system\s*\()", re.IGNORECASE)
SPLIT_PAYLOAD_PATTERN = re.compile(r"\bi\s*g\s*n\s*o\s*r\s*e\b.*\bp\s*r\s*e\s*v\s*i\s*o\s*u\s*s\b|\bc\s*u\s*r\s*l\b|\bb\s*a\s*s\s*h\b", re.IGNORECASE)
JAILBREAK_PATTERN = re.compile(r"\b(?:do\s+anything\s+now|jailbreak|bypass\s+safety|fictional\s+framing\s+bypass|unfiltered\s+mode|no\s+restrictions)\b", re.IGNORECASE)
LEETSPEAK_OVERRIDE_PATTERN = re.compile(r"\b[i1!|][g69][n][o0]r[e3]\s+p[r4]?[e3]v[i1!|][o0]u[s5]\s+[i1!|]n[s5][t7][r4]u[c(][t7][i1!|][o0]n[s5]\b", re.IGNORECASE)
SUSPICIOUS_HIDDEN_STYLE_PATTERN = re.compile(r"\b(?:color\s*:\s*white\s*;\s*background(?:-color)?\s*:\s*white|font-size\s*:\s*0(?:px)?|display\s*:\s*none|visibility\s*:\s*hidden)\b", re.IGNORECASE)

PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<masked_ssn>"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b"), "<masked_phone>"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<masked_email>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<masked_ip_address>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<masked_mac_address>"),
    (re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))(?:[-\s]?\d{4}){3}\b"), "<masked_credit_card>"),
    (re.compile(r"\b\d{9}\b"), "<masked_taxpayer_id>"),
    (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<masked_vin>"),
    (re.compile(r"\b(?:\d[ -]*?){13,17}\b"), "<masked_financial_account>"),
    (re.compile(r"\b(?:DOB|Date of Birth|Birthplace|Born in|Mother(?:'s|s) Maiden Name|Home Address|Address|Passport(?: Number| No)?|Driver(?:'s)? License(?: Number| No)?|Employee ID|School ID|Medical Record(?: Number)?|Taxpayer Identification Number)\s*:\s*([^\n]+)", re.IGNORECASE), None),
]


def mask_pii(text: str) -> str:
    masked = text or ""
    for pattern, replacement in PII_PATTERNS:
        if replacement is None:
            masked = pattern.sub(lambda m: f"{m.group(0).split(':', 1)[0]}: <masked_sensitive_value>", masked)
        else:
            masked = pattern.sub(replacement, masked)
    return masked


def neutralize_prompt_injection(text: str) -> tuple[str, bool]:
    sanitized = text or ""
    changed = False

    pattern_replacements: list[tuple[re.Pattern[str], str]] = [
        (HTML_COMMENT_PATTERN, "<prompt_injection_removed: hidden_text>"),
        (ZERO_WIDTH_PATTERN, "<prompt_injection_removed: hidden_text>"),
        (SUSPICIOUS_HIDDEN_STYLE_PATTERN, "<prompt_injection_removed: hidden_text>"),
        (DIRECT_OVERRIDE_PATTERN, "<prompt_injection_removed: instruction_override>"),
        (ROLE_HIJACK_PATTERN, "<prompt_injection_removed: role_hijack>"),
        (DELIMITER_ESCAPE_PATTERN, "<prompt_injection_removed: delimiter_escape>"),
        (FAKE_SYSTEM_MESSAGE_PATTERN, "<prompt_injection_removed: fake_system_message>"),
        (EXFILTRATION_PATTERN, "<prompt_injection_removed: exfiltration_attempt>"),
        (CONTEXT_POISONING_PATTERN, "<prompt_injection_removed: context_poisoning>"),
        (INDIRECT_INJECTION_PATTERN, "<prompt_injection_removed: indirect_injection>"),
        (COMMAND_INJECTION_PATTERN, "<prompt_injection_removed: command_injection>"),
        (SPLIT_PAYLOAD_PATTERN, "<prompt_injection_removed: split_payload>"),
        (JAILBREAK_PATTERN, "<prompt_injection_removed: jailbreak_attempt>"),
        (LEETSPEAK_OVERRIDE_PATTERN, "<prompt_injection_removed: encoded_payload>"),
        (BASE64_PATTERN, "<prompt_injection_removed: encoded_payload>"),
        (HEX_PATTERN, "<prompt_injection_removed: encoded_payload>"),
        (MORSE_PATTERN, "<prompt_injection_removed: encoded_payload>"),
        (BINARY_PATTERN, "<prompt_injection_removed: encoded_payload>"),
        (URL_ENCODED_INSTRUCTION_PATTERN, "<prompt_injection_removed: encoded_payload>"),
    ]

    for pattern, replacement in pattern_replacements:
        updated = pattern.sub(replacement, sanitized)
        if updated != sanitized:
            changed = True
            sanitized = updated

    decoded = unquote(text or "")
    if decoded != (text or ""):
        decoded_flagged = False
        for pattern, _replacement in pattern_replacements:
            if pattern.search(decoded):
                decoded_flagged = True
                break
        if decoded_flagged:
            changed = True
            sanitized = sanitized + " <prompt_injection_removed: encoded_payload>"

    return sanitized, changed


class RateCheckAgent(AcmeLoanAgentFramework):
    AGENT_ID = "rate_check_agent"
    AGENT_NAME = "Rate_Check Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "deepseek/deepseek-chat"
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Checks lending-rate questions using a configurable OpenRouter model. Replace any unapproved configured model with an organization-approved LLM from the runtime allow list."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Answer rate-check questions with short, practical lending-rate guidance."
    IS_ROUTABLE = False

    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self):
        super().__init__()
        self.openrouter_client = OpenAICompatibleClient(
            base_url=self.OPENROUTER_BASE_URL,
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )

    def to_dict(self) -> dict[str, Any]:
        metadata = super().to_dict()
        metadata["provider"] = "OpenRouter"
        metadata["openrouter_base_url"] = self.OPENROUTER_BASE_URL
        metadata["openrouter_model"] = os.getenv("OPENROUTER_MODEL")
        metadata["model_approval_notice"] = (
            "Replace the current configured OpenRouter model with an organization-approved LLM from the runtime allow list."
        )
        return metadata

    def sanitize_user_message(self, user_message: str) -> tuple[str, bool]:
        sanitized = (user_message or "").strip() or "No rate request provided."
        sanitized, blocked = neutralize_prompt_injection(sanitized)
        sanitized = mask_pii(sanitized)
        return sanitized, blocked

    def sanitize_model_output(self, model_output: str) -> str:
        safe_lines: list[str] = []
        for line in (model_output or "").splitlines():
            if re.search(r"\b(?:eval|exec|subprocess|shell\s*=\s*True|os\.system)\b", line, re.IGNORECASE):
                continue
            safe_lines.append(line)
        return "\n".join(safe_lines).strip() or "Rate summary unavailable."

    async def call_agent_model(self, user_message: str) -> str:
        model = os.getenv("OPENROUTER_MODEL")
        if not os.getenv("OPENROUTER_API_KEY"):
            return "LLM service not configured. Please set OPENROUTER_API_KEY."
        if not model:
            return "LLM service not configured. Please set OPENROUTER_MODEL."

        logger.info(
            "Rate check LLM request",
            extra={
                "agent": self.AGENT_ID,
                "model": model,
                "prompt_length": len(user_message or ""),
            },
        )
        model_output = await self.openrouter_client.chat(
            model=model,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Rate check request:\n{user_message or 'No rate request provided.'}\n\n"
                        "Provide a concise rate check summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        )
        logger.info(
            "Rate check LLM response",
            extra={
                "agent": self.AGENT_ID,
                "model": model,
                "response_length": len(model_output or ""),
            },
        )
        return model_output

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        safe_user_message, blocked_unsafe_content = self.sanitize_user_message(user_message)
        prompt_message = safe_user_message
        if blocked_unsafe_content:
            prompt_message = (
                "A rate-check request contained blocked unsafe prompt content. "
                "Use only the remaining safe request details."
            )

        model_output = self.sanitize_model_output(await self.call_agent_model(prompt_message))
        model_output = mask_pii(model_output)

        response = (
            f"Rate check request: {safe_user_message}\n\n"
            f"Rate summary:\n{model_output}"
            "\n\nModel approval notice: Replace the current configured OpenRouter model with an organization-approved LLM from the runtime allow list."
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "provider": "OpenRouter",
        }


rate_check_agent = RateCheckAgent()
