"""Rate Check Agent class with explicit OpenRouter + DeepSeek invocation."""

import logging
import os
import re
from typing import Any
from urllib.parse import unquote

from llm.openai_compatible import OpenAICompatibleClient

from .framework import AcmeLoanAgentFramework

logger = logging.getLogger(__name__)


_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<pii_redacted:ssn>"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<pii_redacted:email>"),
    (re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "<pii_redacted:ip_address>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<pii_redacted:mac_address>"),
    (re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))([ -]?)\d{4}\1\d{4}\1\d{4}\b"), "<pii_redacted:credit_card>"),
    (re.compile(r"\b(?:\+?1[ -]?)?(?:\(\d{3}\)[ -]?|\d{3}[ -])\d{3}[ -]\d{4}\b"), "<pii_redacted:phone>"),
    (re.compile(r"\b\d{9}\b"), "<pii_redacted:taxpayer_or_account_id>"),
    (re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"), "<pii_redacted:passport_or_license>"),
    (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<pii_redacted:vin>"),
    (re.compile(r"\b(?:Employee|School)\s*ID\s*:\s*[^\n,;]+", re.IGNORECASE), "<pii_redacted:labeled_id>"),
    (re.compile(r"\b(?:DOB|Date of Birth|Birth Year|Year of Birth|Born in)\s*:\s*[^\n,;]+", re.IGNORECASE), "<pii_redacted:birth_info>"),
    (re.compile(r"\b(?:Birthplace|Mother(?:'s|’s)? Maiden Name|Home Address|Address|Medical Record(?:s)?|Fine Location|Ethnicity|Sexual Orientation)\s*:\s*[^\n;]+", re.IGNORECASE), "<pii_redacted:labeled_sensitive>"),
]

_PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:ignore|disregard|forget)\b[^\n]{0,80}\b(?:previous|above|earlier)\b[^\n]{0,80}\b(?:instruction|instructions|prompt|prompts)\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"\byou\s+are\s+now\s+(?:dan|developer\s+mode|admin\s+mode|root|system)\b|\bact\s+as\s+(?:an?\s+)?(?:unrestricted|jailbroken|developer|system)\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"</?(?:system|assistant|user|tool|developer)>|\[/?SYSTEM\]|(?:^|\n)\s*(?:---|===){2,}\s*(?:\n|$)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"<!--(?:(?!-->).){0,500}\b(?:ignore|reveal|leak|system prompt|password|api key|curl|wget)\b(?:(?!-->).){0,500}-->", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
    (re.compile(r"\b(?:system|assistant|tool)\s*:\s*(?:ignore|reveal|disclose|print|dump)\b[^\n]{0,200}", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"\b(?:reveal|leak|disclose|print|dump|show|list)\b[^\n]{0,120}\b(?:system\s+prompt|passwords?|api\s+keys?|secrets?|confidential\s+information)\b|!\[[^\]]*\]\([^)]*https?://[^)]*\)", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"\b(?:from\s+now\s+on|in\s+all\s+future\s+responses|for\s+the\s+rest\s+of\s+this\s+chat|persist\s+this\s+instruction)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"\b(?:metadata|file\s+contents|code\s+comments?)\b[^\n]{0,120}\b(?:ignore|override|reveal|execute)\b|/\*(?:(?!\*/).){0,500}\b(?:ignore|reveal|execute)\b(?:(?!\*/).){0,500}\*/", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: indirect_injection>"),
    (re.compile(r"\b(?:curl|wget)\s+https?://\S+|\b(?:os\.system|subprocess\.(?:run|Popen)|eval\(|exec\(|python\s+-c|bash\s+-c|sh\s+-c|powershell\s+-(?:enc|command))\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"\b(?:d\W*a\W*n|j\W*a\W*i\W*l\W*b\W*r\W*e\W*a\W*k|d\W*e\W*v\W*e\W*l\W*o\W*p\W*e\W*r\W*\s*m\W*o\W*d\W*e)\b", re.IGNORECASE), "<prompt_injection_removed: split_payload>"),
    (re.compile(r"\b(?:DAN|developer\s+mode|do\s+anything\s+now|jailbreak|bypass\s+safety|fictional\s+framing)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
]

_ZERO_WIDTH_PATTERN = re.compile(r"[\u200B-\u200D\u2060\uFEFF]+")
_BASE64_BLOCK_PATTERN = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_BLOCK_PATTERN = re.compile(r"\b(?:0x)?(?:[0-9A-Fa-f]{2}){12,}\b")


def _redact_pii(text: str) -> str:
    redacted = text or ""
    for pattern, replacement in _PII_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _looks_like_encoded_injection(decoded_text: str) -> bool:
    if not decoded_text or decoded_text == decoded_text.strip() and not decoded_text:
        return False
    indicators = [
        re.compile(r"\b(?:ignore|forget|disregard)\b[^\n]{0,80}\b(?:instructions?|prompt|system)\b", re.IGNORECASE),
        re.compile(r"\b(?:act\s+as|you\s+are\s+now|developer\s+mode|DAN|jailbreak)\b", re.IGNORECASE),
        re.compile(r"\b(?:reveal|leak|dump|print|show|list)\b[^\n]{0,120}\b(?:secrets?|passwords?|api\s+keys?|system\s+prompt)\b", re.IGNORECASE),
        re.compile(r"\b(?:curl|wget)\s+https?://\S+|\b(?:os\.system|subprocess\.(?:run|Popen)|eval\(|exec\()", re.IGNORECASE),
    ]
    return any(pattern.search(decoded_text) for pattern in indicators)


def _replace_encoded_payloads(text: str) -> str:
    sanitized = text or ""

    def _base64_replacer(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            padding = "=" * (-len(candidate) % 4)
            decoded = __import__("base64").b64decode(candidate + padding, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            return candidate
        if _looks_like_encoded_injection(decoded):
            return "<prompt_injection_removed: encoded_payload>"
        return candidate

    def _hex_replacer(match: re.Match[str]) -> str:
        candidate = match.group(0)
        hex_text = candidate[2:] if candidate.lower().startswith("0x") else candidate
        try:
            decoded = bytes.fromhex(hex_text).decode("utf-8", errors="ignore")
        except Exception:
            return candidate
        if _looks_like_encoded_injection(decoded):
            return "<prompt_injection_removed: encoded_payload>"
        return candidate

    def _url_replacer(match: re.Match[str]) -> str:
        candidate = match.group(0)
        decoded = unquote(candidate)
        if decoded != candidate and _looks_like_encoded_injection(decoded):
            return "<prompt_injection_removed: encoded_payload>"
        return candidate

    sanitized = _BASE64_BLOCK_PATTERN.sub(_base64_replacer, sanitized)
    sanitized = _HEX_BLOCK_PATTERN.sub(_hex_replacer, sanitized)
    sanitized = re.sub(r"(?:%[0-9A-Fa-f]{2}){6,}", _url_replacer, sanitized)
    return sanitized


def _neutralize_prompt_injection(text: str) -> tuple[str, bool]:
    sanitized = text or ""
    blocked = False

    if _ZERO_WIDTH_PATTERN.search(sanitized):
        blocked = True
        sanitized = _ZERO_WIDTH_PATTERN.sub("<prompt_injection_removed: hidden_text>", sanitized)

    encoded_sanitized = _replace_encoded_payloads(sanitized)
    if encoded_sanitized != sanitized:
        blocked = True
        sanitized = encoded_sanitized

    for pattern, replacement in _PROMPT_INJECTION_PATTERNS:
        updated = pattern.sub(replacement, sanitized)
        if updated != sanitized:
            blocked = True
            sanitized = updated

    return sanitized, blocked


class RateCheckAgent(AcmeLoanAgentFramework):
    AGENT_ID = "rate_check_agent"
    AGENT_NAME = "Rate_Check Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "deepseek/deepseek-chat"
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Checks lending-rate questions using DeepSeek through OpenRouter."
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
        llm_user_message = _redact_pii(user_message or "No rate request provided.")
        model_output = await self.openrouter_client.chat(
            model=model,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Rate check request:\n{llm_user_message}\n\n"
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

        display_user_message = _redact_pii(safe_user_message)
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
