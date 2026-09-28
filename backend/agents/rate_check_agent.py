"""Rate Check Agent class with explicit OpenRouter + DeepSeek invocation."""

import logging
import os
import re
from typing import Any
from urllib.parse import unquote

from llm.openai_compatible import OpenAICompatibleClient

from .framework import AcmeLoanAgentFramework

logger = logging.getLogger(__name__)


_ZERO_WIDTH_TRANSLATION = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u2060"), None)


def _normalize_for_detection(text: str) -> str:
    normalized = (text or "").translate(_ZERO_WIDTH_TRANSLATION)
    normalized = unquote(normalized)
    normalized = normalized.replace("0", "o").replace("1", "i").replace("3", "e").replace("4", "a").replace("5", "s").replace("7", "t")
    normalized = re.sub(r"[\s_\-]+", " ", normalized)
    return normalized.lower()


def _mask_ui_pii(text: str) -> str:
    masked = text or ""
    patterns = [
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<masked_ssn>"),
        (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b"), "<masked_phone>"),
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<masked_email>"),
        (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<masked_card_or_account>"),
        (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<masked_ip>"),
        (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<masked_mac>"),
        (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<masked_vin>"),
        (re.compile(r"\b(?:DOB|Date of Birth|Birth Year|Year of Birth)\s*:\s*[^\n,;]+", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", ": <masked_birth_info>", m.group(0))),
        (re.compile(r"\b(?:Birthplace|Place of Birth|Mother'?s Maiden Name|Home Address|Address|Passport No\.?|Passport Number|Driver'?s License No\.?|Driver'?s License Number|Taxpayer Identification Number|TIN|Medical Records|Employee ID|School ID|Fine Location|Ethnicity|Sexual Orientation)\s*:\s*[^\n;]+", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", ": <masked_pii>", m.group(0))),
    ]
    for pattern, replacement in patterns:
        masked = pattern.sub(replacement, masked)
    return masked


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
        blocked = False
        normalized = _normalize_for_detection(sanitized)
        suspicious_patterns = [
            (re.compile(r"(?is)<!--.*?(ignore previous instructions|forget everything above|act as unrestricted|developer mode|reveal .*?(?:passwords|api keys|confidential information)).*?-->"), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"(?is)<(?:script|style)[^>]*>.*?</(?:script|style)>"), "<prompt_injection_removed: hidden_text>"),
            (re.compile(r"(?i)</?system>|</?assistant>|</?user>|\[/?system\]|\[/?assistant\]|\[/?user\]|(?:^|\n)\s*(?:---|===){3,}\s*(?:$|\n)"), "<prompt_injection_removed: delimiter_escape>"),
            (re.compile(r"(?i)\b(?:ignore previous instructions|ignore all previous instructions|forget everything above|disregard prior directions|override system prompt)\b"), "<prompt_injection_removed: instruction_override>"),
            (re.compile(r"(?i)\b(?:you are now (?:dan|in admin mode)|act as (?:an unrestricted ai|dan)|developer mode|jailbreak|do anything now|fictional framing)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
            (re.compile(r"(?i)\b(?:system prompt|tool message|assistant message)\s*:\s*"), "<prompt_injection_removed: fake_system_message> "),
            (re.compile(r"(?i)\b(?:send|post|upload|exfiltrate|leak|reveal|list)\b[^\n]{0,120}\b(?:https?://\S+|www\.\S+|passwords|api keys|confidential information|system prompt|secrets?)\b"), "<prompt_injection_removed: exfiltration_attempt>"),
            (re.compile(r"(?i)\b(?:for the rest of this conversation|in all future responses|from now on|next turn|subsequent replies)\b"), "<prompt_injection_removed: context_poisoning>"),
            (re.compile(r"(?i)\b(?:metadata|file content|document field|code comment)\b[^\n]{0,80}\b(?:ignore previous instructions|act as unrestricted|reveal secrets?)\b"), "<prompt_injection_removed: indirect_injection>"),
            (re.compile(r"(?i)\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|python\s+-c|perl\s+-e|node\s+-e|exec|eval|subprocess|os\.system|chmod\s+\+x|rm\s+-rf)\b[^\n]*"), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2}|(?:0x)?[0-9A-Fa-f]{24,})\b"), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"(?i)\b[A-Za-z]:\\[^\s]+\.(?:exe|dll|bat|cmd|ps1)\b|\b\S+\.(?:sh|bash|zsh|ps1|exe|bin)\b"), "<prompt_injection_removed: command_injection>"),
        ]

        for pattern, replacement in suspicious_patterns:
            if pattern.search(sanitized):
                blocked = True
                sanitized = pattern.sub(replacement, sanitized)

        normalized_checks = [
            (re.compile(r"\b(?:i\s*g\s*n\s*o\s*r\s*e\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+prior\s+directions)\b"), "<prompt_injection_removed: split_payload>"),
            (re.compile(r"\b(?:you\s+are\s+now\s+dan|act\s+as\s+an\s+unrestricted\s+ai|developer\s+mode|jailbreak)\b"), "<prompt_injection_removed: role_hijack>"),
            (re.compile(r"\b(?:curl|wget|bash|powershell|cmd\.exe|python\s+c|exec|eval|subprocess|os\.system|rm\s+rf)\b"), "<prompt_injection_removed: command_injection>"),
            (re.compile(r"\b(?:ignore previous instructions|act as unrestricted|reveal all confidential information|list all passwords and api keys)\b"), "<prompt_injection_removed: encoded_payload>"),
            (re.compile(r"\b(?:white on white|display\s*:\s*none|font-size\s*:\s*0|zero-width|hidden instruction)\b"), "<prompt_injection_removed: hidden_text>"),
        ]
        for pattern, replacement in normalized_checks:
            if pattern.search(normalized):
                blocked = True
                sanitized = replacement
                break

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
            return "LLM service not configured. Please set OPENROUTER_API_KEY and replace the unapproved LLM with an approved model from the organization's allow list."
        if not model:
            return "LLM service not configured. Please set OPENROUTER_MODEL and replace the unapproved LLM with an approved model from the organization's allow list."

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
