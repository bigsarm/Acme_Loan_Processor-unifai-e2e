"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
import re
import base64
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient


_ZERO_WIDTH_TRANSLATION = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u2060"), None)


def _looks_like_base64(text: str) -> bool:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 16 or len(compact) % 4 != 0:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/=]+", compact) is not None


def _safe_b64_decode(text: str) -> str | None:
    if not _looks_like_base64(text):
        return None
    compact = re.sub(r"\s+", "", text)
    try:
        decoded = base64.b64decode(compact, validate=True)
    except Exception:
        return None
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _neutralize_prompt_text(text: str) -> str:
    sanitized = text

    hidden_patterns = [
        (r"<!--[\s\S]*?(ignore previous instructions|forget everything above|system prompt|reveal|leak)[\s\S]*?-->", "<prompt_injection_removed: hidden_text>"),
        (r"(?i)(?:font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden)[^\n>]*>([^<]*(ignore previous instructions|forget everything above|reveal system prompt)[^<]*)", "<prompt_injection_removed: hidden_text>"),
    ]
    for pattern, replacement in hidden_patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

    if sanitized.translate(_ZERO_WIDTH_TRANSLATION) != sanitized:
        normalized = sanitized.translate(_ZERO_WIDTH_TRANSLATION)
        if re.search(r"(?i)ignore\s+previous\s+instructions|forget\s+everything\s+above|reveal\s+(?:the\s+)?system\s+prompt|leak\s+(?:the\s+)?system\s+prompt", normalized):
            sanitized = re.sub(r"[\u200b\u200c\u200d\ufeff\u2060]+", "<prompt_injection_removed: hidden_text>", sanitized)
        else:
            sanitized = normalized

    direct_patterns = [
        (r"(?i)\b(ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+all\s+prior\s+instructions|override\s+(?:all\s+)?instructions)\b", "<prompt_injection_removed: instruction_override>"),
        (r"(?i)\b(you\s+are\s+now\s+dan|act\s+as\s+(?:an\s+)?unrestricted|developer\s+mode|dan\s+mode|do\s+anything\s+now)\b", "<prompt_injection_removed: jailbreak_attempt>"),
        (r"(?i)</?system>|</?assistant>|</?tool>|<{2,}.*?>{2,}|(?:^|\n)\s*(?:---|===)\s*(?:system|assistant|developer|tool)\s*(?:---|===)", "<prompt_injection_removed: delimiter_escape>"),
        (r"(?i)\b(system\s*:\s*you\s+must|tool\s*:\s*execute|assistant\s*:\s*ignore|developer\s*message\s*:)\b", "<prompt_injection_removed: fake_system_message>"),
        (r"(?i)\b(send|post|upload|exfiltrate|leak|reveal)\b[^\n]{0,120}\b(to|via)\b[^\n]{0,120}(https?://\S+|ftp://\S+)", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"!\[[^\]]*\]\(https?://[^)]+\)", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"(?i)\b(in\s+your\s+next\s+reply|from\s+now\s+on|for\s+the\s+rest\s+of\s+this\s+conversation|in\s+future\s+turns)\b[^\n]{0,120}\b(ignore|disregard|treat)\b", "<prompt_injection_removed: context_poisoning>"),
        (r"(?i)\b(metadata|file\s+content|code\s+comment|document\s+field)\b[^\n]{0,120}\b(ignore\s+previous\s+instructions|act\s+as|reveal\s+system\s+prompt)\b", "<prompt_injection_removed: indirect_injection>"),
        (r"(?i)\b(?:curl|wget|bash|sh|zsh|powershell|cmd(?:\.exe)?|python\s+-c|node\s+-e|perl\s+-e|ruby\s+-e|nc|netcat|scp|ssh)\b[^\n]{0,200}", "<prompt_injection_removed: command_injection>"),
        (r"(?i)\b(?:rm\s+-rf|chmod\s+\+x|sudo\s+|mkfs\.|del\s+/f|format\s+[a-z]:)\b[^\n]{0,200}", "<prompt_injection_removed: command_injection>"),
        (r"(?i)\b(?:i\s*g\s*n\s*o\s*r\s*e\s+previous\s+instructions|y0u\s+ar3\s+n0w\s+d4n|4ct\s+45\s+unr35tr1ct3d)\b", "<prompt_injection_removed: encoded_payload>"),
        (r"(?i)\b(?:ignore\s*\n\s*previous\s*\n\s*instructions|forget\s*\n\s*everything\s*\n\s*above|you\s*\n\s*are\s*\n\s*now\s*\n\s*dan)\b", "<prompt_injection_removed: split_payload>"),
        (r"(?i)\b(?:you\s+are\s+now|act\s+as)\b[^\n]{0,80}\b(?:dan|unrestricted|root|system)\b", "<prompt_injection_removed: role_hijack>"),
    ]
    for pattern, replacement in direct_patterns:
        sanitized = re.sub(pattern, replacement, sanitized)

    decoded = _safe_b64_decode(sanitized)
    if decoded and re.search(r"(?i)ignore\s+previous\s+instructions|forget\s+everything\s+above|you\s+are\s+now|act\s+as\s+(?:an\s+)?unrestricted|reveal\s+(?:the\s+)?system\s+prompt|curl\s+https?://|wget\s+https?://|bash\s+-c|powershell\s+-", decoded):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    if re.search(r"(?i)\b(?:[01]{8}(?:\s+[01]{8}){2,}|0x[0-9a-f]{2}(?:\s*0x[0-9a-f]{2}){2,})\b", sanitized):
        sanitized = re.sub(r"(?i)\b(?:[01]{8}(?:\s+[01]{8}){2,}|0x[0-9a-f]{2}(?:\s*0x[0-9a-f]{2}){2,})\b", "<prompt_injection_removed: encoded_payload>", sanitized)

    return sanitized


def _sanitize_message_value(value: Any) -> Any:
    if isinstance(value, str):
        return _neutralize_prompt_text(value)
    if isinstance(value, list):
        return [_sanitize_message_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_message_value(item) for key, item in value.items()}
    return value


def _sanitize_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_sanitize_message_value(message) for message in messages]


class AcmeLoanAgentFramework(ABC):
    """Base class that makes agent metadata and model usage obvious."""

    FRAMEWORK_NAME = "AcmeLoanAgentFramework"
    AGENT_ID = ""
    AGENT_NAME = ""
    VERSION = "1.0.0"
    MODEL_NAME = ""
    BEDROCK_MODEL_ID = ""
    BEDROCK_FALLBACK_MODEL_ID = ""
    DESCRIPTION = ""
    MCP_SERVERS: list[str] = []
    GUARDRAILS: dict[str, Any] = {}
    SYSTEM_PROMPT = ""
    IS_ROUTABLE = True
    IS_SCAN_ONLY = False

    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self):
        # Runtime LLM calls use OpenRouter credentials from .env:
        # OPENROUTER_API_KEY and OPENROUTER_MODEL.
        # Replace this provider/model configuration with an organization-approved LLM
        # from the runtime allow list before deploying to production.
        self.model_client = OpenAICompatibleClient(
            base_url=self.OPENROUTER_BASE_URL,
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.AGENT_ID,
            "name": self.AGENT_NAME,
            "version": self.VERSION,
            "framework": self.FRAMEWORK_NAME,
            "model": self.MODEL_NAME,
            "provider": "OpenRouter",
            "provider_notice": "Replace with an organization-approved LLM from the runtime allow list.",
            "openrouter_model": os.getenv("OPENROUTER_MODEL"),
            "bedrock_model_id": self.BEDROCK_MODEL_ID,
            "bedrock_fallback_model_id": self.BEDROCK_FALLBACK_MODEL_ID,
            "description": self.DESCRIPTION,
            "mcp_servers": list(self.MCP_SERVERS),
            "guardrails": deepcopy(self.GUARDRAILS),
            "system_prompt": self.SYSTEM_PROMPT,
            "is_routable": self.IS_ROUTABLE,
            "is_scan_only": self.IS_SCAN_ONLY,
        }

    async def call_bedrock_model(
        self,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 350,
    ) -> str:
        """Call OpenRouter using OPENROUTER_API_KEY + OPENROUTER_MODEL.

        Method name is kept for compatibility with existing agents.
        """
        api_key = (os.getenv("OPENROUTER_API_KEY") or "").strip()
        model = (os.getenv("OPENROUTER_MODEL") or "").strip()
        if not api_key:
            return "LLM service not configured. Please set OPENROUTER_API_KEY."
        if not model:
            return "LLM service not configured. Please set OPENROUTER_MODEL."

        messages = _sanitize_messages(messages)
        return await self.model_client.chat(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent."""
