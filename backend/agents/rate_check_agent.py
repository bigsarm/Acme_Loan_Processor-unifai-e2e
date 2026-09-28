"""Rate Check Agent class with explicit OpenRouter + DeepSeek invocation."""

import logging
import os
import re
from typing import Any
from urllib.parse import unquote

from llm.openai_compatible import OpenAICompatibleClient

from .framework import AcmeLoanAgentFramework

logger = logging.getLogger(__name__)


_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")


def _looks_like_base64_payload(value: str) -> bool:
    compact = re.sub(r"\s+", "", value or "")
    if len(compact) < 24 or len(compact) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return False
    return True


def _contains_split_payload(value: str, words: list[str]) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "", (value or "").lower())
    return any(word in normalized for word in words)


def _mask_ui_pii(value: str) -> str:
    masked = value or ""
    pii_patterns = [
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        re.compile(r"\b(?:19|20)\d{2}\b"),
        re.compile(r"\b(?:born in|birthplace)\s*:\s*[^\n]+", re.IGNORECASE),
        re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b"),
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        re.compile(r"\bmother(?:'s|s)? maiden name\s*:\s*[^\n]+", re.IGNORECASE),
        re.compile(r"\b\d{1,6}\s+[A-Za-z0-9.'#-]+(?:\s+[A-Za-z0-9.'#-]+){1,5}\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b[^\n,]*", re.IGNORECASE),
        re.compile(r"\b[A-Z0-9]{6,9}\b"),
        re.compile(r"\b[A-Z0-9]{1,2}\d{5,8}\b", re.IGNORECASE),
        re.compile(r"\b\d{2}-\d{7}\b"),
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        re.compile(r"\b\d{8,17}\b"),
        re.compile(r"\b(?:employee|school)\s*id\s*:\s*[^\n]+", re.IGNORECASE),
        re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"),
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"),
        re.compile(r"\b(?:lat|latitude)\s*[:=]\s*-?\d{1,2}\.\d+\s*,?\s*(?:lon|lng|longitude)\s*[:=]\s*-?\d{1,3}\.\d+\b", re.IGNORECASE),
        re.compile(r"\b(?:ethnicity|sexual orientation|sex)\s*:\s*[^\n]+", re.IGNORECASE),
        re.compile(r"\b(?:medical record|fingerprint|retina|iris scan|voice signature|facial image)\s*:\s*[^\n]+", re.IGNORECASE),
    ]
    for pattern in pii_patterns:
        masked = pattern.sub("<masked_pii>", masked)
    return masked


class RateCheckAgent(AcmeLoanAgentFramework):
    AGENT_ID = "rate_check_agent"
    AGENT_NAME = "Rate_Check Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-chat")
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Checks lending-rate questions through OpenRouter. Replace the default model with an approved allow-listed model for your organization."
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
        blocked = False

        replacement_patterns = [
            (re.compile(r"\b(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+(?:all|previous)\s+instructions)\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
            (re.compile(r"\b(?:you\s+are\s+now\s+dan|act\s+as\s+(?:an\s+)?unrestricted|developer\s+mode|do\s+anything\s+now)\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
            (re.compile(r"</?(?:system|assistant|tool|developer)>|(?:^|\n)\s*(?:---|===)\s*(?:\n|$)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
            (re.compile(r"<!--.*?-->", re.DOTALL), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"\b(?:system\s*:\s*|assistant\s*:\s*|tool\s*:\s*)[^\n]*", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
            (re.compile(r"\b(?:send|post|upload|exfiltrate|leak)\b[^\n]*\b(?:http://|https://|www\.|system prompt|secrets?)\b", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
            (re.compile(r"\b(?:in\s+the\s+next\s+turn|when\s+asked\s+later|store\s+this\s+and\s+reveal|remember\s+this\s+secretly)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
            (re.compile(r"\b(?:metadata|comment|code\s+comment|hidden\s+field|file\s+contents?)\b[^\n]*\b(?:ignore\s+instructions|override|system\s+prompt)\b", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
            (re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|rm\s+-rf|chmod|python\s+-c|exec\s*\(|eval\s*\(|subprocess|os\.system)\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"\b(?:dan|jailbreak|bypass\s+safety|fictional\s+framing)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
        ]

        for pattern, replacement in replacement_patterns:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub(replacement, sanitized)

        if _ZERO_WIDTH_RE.search(sanitized):
            blocked = True
            sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

        decoded_url = unquote(sanitized)
        if decoded_url != sanitized and re.search(r"\b(?:ignore\s+previous\s+instructions|you\s+are\s+now\s+dan|curl\s+https?://|bash\b|powershell\b)\b", decoded_url, re.IGNORECASE):
            blocked = True
            sanitized = "<prompt_injection_removed: encoded_payload>"
        elif _looks_like_base64_payload(sanitized):
            blocked = True
            sanitized = "<prompt_injection_removed: encoded_payload>"
        elif re.search(r"(?:0x[0-9A-Fa-f]{2}\s*){4,}", sanitized):
            blocked = True
            sanitized = re.sub(r"(?:0x[0-9A-Fa-f]{2}\s*){4,}", "<prompt_injection_removed: encoded_payload>", sanitized)
        elif re.search(r"\b(?:[01]{8}\s+){3,}[01]{8}\b", sanitized):
            blocked = True
            sanitized = re.sub(r"\b(?:[01]{8}\s+){3,}[01]{8}\b", "<prompt_injection_removed: encoded_payload>", sanitized)
        elif re.search(r"\b(?:[-./]|dot|dash)\s*(?:-\.\.\.|\.\.-\.|-\.\.|\.|\.\.|---)\b", sanitized, re.IGNORECASE):
            blocked = True
            sanitized = re.sub(r"\b(?:[-./]|dot|dash)\s*(?:-\.\.\.|\.\.-\.|-\.\.|\.|\.\.|---)\b", "<prompt_injection_removed: encoded_payload>", sanitized, flags=re.IGNORECASE)
        elif re.search(r"\b(?:1gn0re|ign0re|d3v3l0p3r|unr3stricted|curl|b4sh|p0w3rsh3ll)\b", sanitized, re.IGNORECASE):
            blocked = True
            sanitized = re.sub(r"\b(?:1gn0re|ign0re|d3v3l0p3r|unr3stricted|curl|b4sh|p0w3rsh3ll)\b", "<prompt_injection_removed: encoded_payload>", sanitized, flags=re.IGNORECASE)

        if _contains_split_payload(sanitized, ["ignorepreviousinstructions", "youarenowdan", "actasunrestricted", "revealthesystemprompt"]):
            blocked = True
            sanitized = "<prompt_injection_removed: split_payload>"

        return sanitized, blocked

    def sanitize_model_output(self, model_output: str) -> str:
        safe_lines: list[str] = []
        for line in (model_output or "").splitlines():
            if re.search(r"\b(?:eval|exec|subprocess|shell\s*=\s*True|os\.system)\b", line, re.IGNORECASE):
                continue
            safe_lines.append(line)
        return "\n".join(safe_lines).strip() or "Rate summary unavailable."

    async def call_agent_model(self, user_message: str) -> str:
        model = os.getenv("OPENROUTER_MODEL") or self.MODEL_NAME
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

        display_user_message = _mask_ui_pii(safe_user_message)
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
