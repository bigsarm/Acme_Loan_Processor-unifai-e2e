"""Rate Check Agent class with explicit OpenRouter + DeepSeek invocation."""

import logging
import os
import re
from typing import Any
from urllib.parse import unquote

from llm.openai_compatible import OpenAICompatibleClient

from .framework import AcmeLoanAgentFramework

logger = logging.getLogger(__name__)


ZERO_WIDTH_CHARS_RE = re.compile(r"[\u200B-\u200F\u2060\uFEFF]")
PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:ignore|disregard|bypass)\b.{0,80}\b(?:previous|prior|above|earlier)\b.{0,80}\binstructions?\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"\bforget\b.{0,40}\b(?:everything|all)\b.{0,40}\b(?:above|before|previous)\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"\byou\s+are\s+now\b.{0,60}\b(?:dan|developer mode|unrestricted|system|assistant)\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"\bact\s+as\b.{0,60}\b(?:unrestricted|without limits|a system|dan)\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"</?(?:system|assistant|user|tool|developer)>|(?:^|\n)\s*(?:---|===|###)\s*(?:system|assistant|developer|tool)\s*(?:---|===|###)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"<!--.*?-->", re.DOTALL), "<prompt_injection_removed: hidden_text>"),
    (re.compile(r"\b(?:system|assistant|tool)\s*:\s*", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"!\[[^\]]*\]\([^\)]*https?://[^\)]*\)", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"\b(?:send|post|upload|exfiltrate|leak|reveal|expose)\b.{0,80}\b(?:system prompt|secrets?|credentials?|data)\b.{0,80}\b(?:https?://|to\s+https?://)\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"\b(?:in the next turn|next message|from now on|going forward|remember this rule)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"\b(?:metadata|front matter|yaml|json|comment)\b.{0,80}\b(?:ignore instructions|override|act as|system prompt)\b", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: indirect_injection>"),
    (re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|python\s+-c|exec|eval|subprocess|os\.system|rm\s+-rf|chmod)\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"\b(?:dan|developer mode|jailbreak|do anything now|fictional scenario|hypothetical bypass)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
    (re.compile(r"(?:i\s*g\s*n\s*o\s*r\s*e\s+previous\s+instructions|d\s*a\s*n)", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
]

PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<masked_ssn>"),
    (re.compile(r"\b(?:19\d{2}|20[01]\d|202[0-9])\b"), "<masked_year_of_birth>"),
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "<masked_email>"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b"), "<masked_phone>"),
    (re.compile(r"\b\d{13,19}\b"), "<masked_credit_card>"),
    (re.compile(r"\b(?:\d[ -]*?){9,17}\b"), "<masked_financial_account>"),
    (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b", re.IGNORECASE), "<masked_vin>"),
    (re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"), "<masked_ip_address>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<masked_mac_address>"),
]


def _looks_like_encoded_instruction(text: str) -> bool:
    candidate = (text or "").strip()
    if not candidate:
        return False

    if re.fullmatch(r"(?:[A-Fa-f0-9]{2}){12,}", candidate):
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8", errors="ignore")
        except ValueError:
            decoded = ""
        if decoded and re.search(r"\b(?:ignore|system|assistant|developer mode|dan|act as|reveal|prompt)\b", decoded, re.IGNORECASE):
            return True

    if re.fullmatch(r"[A-Za-z0-9+/=]{24,}", candidate):
        try:
            import base64
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            decoded = ""
        if decoded and re.search(r"\b(?:ignore|system|assistant|developer mode|dan|act as|reveal|prompt)\b", decoded, re.IGNORECASE):
            return True

    decoded_url = unquote(candidate)
    if decoded_url != candidate and re.search(r"\b(?:ignore|previous instructions|system prompt|act as|dan)\b", decoded_url, re.IGNORECASE):
        return True

    return False


def _neutralize_prompt_injection(text: str) -> tuple[str, bool]:
    sanitized = text or ""
    blocked = False

    if ZERO_WIDTH_CHARS_RE.search(sanitized):
        sanitized = ZERO_WIDTH_CHARS_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
        blocked = True

    for pattern, replacement in PROMPT_INJECTION_PATTERNS:
        if pattern.search(sanitized):
            sanitized = pattern.sub(replacement, sanitized)
            blocked = True

    for token in re.findall(r"\S+", sanitized):
        if _looks_like_encoded_instruction(token):
            sanitized = sanitized.replace(token, "<prompt_injection_removed: encoded_payload>")
            blocked = True

    return sanitized, blocked


def _mask_ui_pii(text: str) -> str:
    masked = text or ""
    for pattern, replacement in PII_PATTERNS:
        masked = pattern.sub(replacement, masked)
    return masked


class RateCheckAgent(AcmeLoanAgentFramework):
    AGENT_ID = "rate_check_agent"
    AGENT_NAME = "Rate_Check Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "Replace with an approved model from the organization allow list via OPENROUTER_MODEL."
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Checks lending-rate questions using a configurable OpenRouter model; replace any unapproved model with one from the organization allow list."
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
        return metadata

    def sanitize_user_message(self, user_message: str) -> tuple[str, bool]:
        sanitized = (user_message or "").strip() or "No rate request provided."
        sanitized, blocked = _neutralize_prompt_injection(sanitized)
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
        display_user_message = _mask_ui_pii(safe_user_message)
        prompt_message = safe_user_message
        if blocked_unsafe_content:
            prompt_message = (
                "A rate-check request contained blocked unsafe prompt content. "
                "Use only the remaining safe request details."
            )

        model_output = self.sanitize_model_output(await self.call_agent_model(prompt_message))

        response = (
            f"Rate check request: {display_user_message}\n\n"
            f"Rate summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "provider": "OpenRouter",
        }


rate_check_agent = RateCheckAgent()
