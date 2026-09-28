"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
import re
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any
from urllib.parse import unquote

from llm.openai_compatible import OpenAICompatibleClient

_ZERO_WIDTH_TRANSLATION = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)


def _replace_pattern(value: str, pattern: str, marker: str) -> str:
    return re.sub(pattern, marker, value, flags=re.IGNORECASE | re.MULTILINE)


def _sanitize_message_text(value: str) -> str:
    sanitized = value
    lowered = sanitized.lower()

    if re.search(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions|forget\s+(everything|all)\s+(above|before)", sanitized, flags=re.IGNORECASE):
        sanitized = _replace_pattern(
            sanitized,
            r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions|forget\s+(everything|all)\s+(above|before)",
            "<prompt_injection_removed: instruction_override>",
        )

    if re.search(r"you\s+are\s+now\s+[^\n]+|act\s+as\s+(an?\s+)?(unrestricted|different|system)|pretend\s+to\s+be\s+[^\n]+", sanitized, flags=re.IGNORECASE):
        sanitized = _replace_pattern(
            sanitized,
            r"you\s+are\s+now\s+[^\n]+|act\s+as\s+(an?\s+)?(unrestricted|different|system)|pretend\s+to\s+be\s+[^\n]+",
            "<prompt_injection_removed: role_hijack>",
        )

    if re.search(r"</?system>|</?assistant>|</?tool>|</?user>|^\s*---+\s*$|^\s*```(?:system|assistant|tool|user)?", sanitized, flags=re.IGNORECASE | re.MULTILINE):
        sanitized = _replace_pattern(
            sanitized,
            r"</?system>|</?assistant>|</?tool>|</?user>|^\s*---+\s*$|^\s*```(?:system|assistant|tool|user)?",
            "<prompt_injection_removed: delimiter_escape>",
        )

    encoded_detected = False
    if re.search(r"(?:[A-Fa-f0-9]{2}){8,}|(?:[A-Za-z0-9+/]{20,}={0,2})|(?:%[0-9A-Fa-f]{2}){4,}|(?:\\u[0-9A-Fa-f]{4}){2,}|(?:[01]{8}[\s,;:-]*){4,}", sanitized):
        encoded_detected = True
    if re.search(r"(?:^|\b)[A-Za-z](?:[\s._-]*[A-Za-z]){7,}(?:\b|$)", sanitized) and re.search(r"[43017$@]", sanitized):
        encoded_detected = True
    if re.search(r"(?:[.\-]{1,3}[\s/]){6,}|(?:^|\s)[.-]{1,6}(?:\s+[.-]{1,6}){5,}(?:\s|$)", sanitized):
        encoded_detected = True
    decoded_url = unquote(sanitized)
    if decoded_url != sanitized and re.search(r"ignore|system|assistant|developer|instruction|prompt|tool", decoded_url, flags=re.IGNORECASE):
        encoded_detected = True
    if encoded_detected:
        sanitized = "<prompt_injection_removed: encoded_payload>"

    if re.search(r"<!--.*?(ignore|instruction|system|assistant|prompt).*?-->|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(?:white|#fff(?:fff)?)", sanitized, flags=re.IGNORECASE | re.DOTALL):
        sanitized = _replace_pattern(
            sanitized,
            r"<!--.*?(ignore|instruction|system|assistant|prompt).*?-->|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(?:white|#fff(?:fff)?)",
            "<prompt_injection_removed: hidden_text>",
        )
    if sanitized.translate(_ZERO_WIDTH_TRANSLATION) != sanitized:
        sanitized = sanitized.translate(_ZERO_WIDTH_TRANSLATION)
        sanitized = "<prompt_injection_removed: hidden_text>"

    if re.search(r"^\s*(system|assistant|tool)\s*:\s*|\bBEGIN\s+SYSTEM\s+PROMPT\b|\bTOOL\s+RESULT\b", sanitized, flags=re.IGNORECASE | re.MULTILINE):
        sanitized = _replace_pattern(
            sanitized,
            r"^\s*(system|assistant|tool)\s*:\s*|\bBEGIN\s+SYSTEM\s+PROMPT\b|\bTOOL\s+RESULT\b",
            "<prompt_injection_removed: fake_system_message>",
        )

    if re.search(r"!\[[^\]]*\]\([^)]*https?://|send\s+(the\s+)?(data|prompt|secret|context)\s+to\s+https?://|leak\s+(the\s+)?(system\s+prompt|secrets?|credentials?)|exfiltrat", sanitized, flags=re.IGNORECASE):
        sanitized = _replace_pattern(
            sanitized,
            r"!\[[^\]]*\]\([^)]*https?://|send\s+(the\s+)?(data|prompt|secret|context)\s+to\s+https?://|leak\s+(the\s+)?(system\s+prompt|secrets?|credentials?)|exfiltrat",
            "<prompt_injection_removed: exfiltration_attempt>",
        )

    if re.search(r"in\s+(the\s+)?next\s+turn|when\s+asked\s+later|persist\s+this\s+instruction|remember\s+this\s+secret|override\s+future\s+instructions", sanitized, flags=re.IGNORECASE):
        sanitized = _replace_pattern(
            sanitized,
            r"in\s+(the\s+)?next\s+turn|when\s+asked\s+later|persist\s+this\s+instruction|remember\s+this\s+secret|override\s+future\s+instructions",
            "<prompt_injection_removed: context_poisoning>",
        )

    if re.search(r"metadata\s*:.*(?:ignore|system|prompt)|comment\s*:.*(?:ignore|instruction)|filename\s*:.*(?:system|assistant)|docstring\s*:.*(?:ignore|prompt)", lowered, flags=re.MULTILINE):
        sanitized = _replace_pattern(
            sanitized,
            r"metadata\s*:.*(?:ignore|system|prompt)|comment\s*:.*(?:ignore|instruction)|filename\s*:.*(?:system|assistant)|docstring\s*:.*(?:ignore|prompt)",
            "<prompt_injection_removed: indirect_injection>",
        )

    if re.search(r"\b(?:rm\s+-rf|curl\s+|wget\s+|chmod\s+\+x|powershell(?:\.exe)?|bash\s+-c|sh\s+-c|cmd(?:\.exe)?\s+/c|subprocess\.|os\.system|eval\s*\(|exec\s*\(|python\s+-c)\b", sanitized, flags=re.IGNORECASE):
        sanitized = _replace_pattern(
            sanitized,
            r"\b(?:rm\s+-rf|curl\s+|wget\s+|chmod\s+\+x|powershell(?:\.exe)?|bash\s+-c|sh\s+-c|cmd(?:\.exe)?\s+/c|subprocess\.|os\.system|eval\s*\(|exec\s*\(|python\s+-c)\b",
            "<prompt_injection_removed: command_injection>",
        )

    if re.search(r"\b(?:MZ|ELF|PK\x03\x04)\b|\.exe\b|\.dll\b|\.so\b|application/octet-stream", sanitized, flags=re.IGNORECASE):
        sanitized = "<prompt_injection_removed: command_injection>"

    if re.search(r"(?:ignore\W*){2,}|(?:system\W*){2,}|(?:bypass\W*){2,}|(?:jail\W*break)", sanitized, flags=re.IGNORECASE):
        sanitized = _replace_pattern(
            sanitized,
            r"(?:ignore\W*){2,}|(?:system\W*){2,}|(?:bypass\W*){2,}|(?:jail\W*break)",
            "<prompt_injection_removed: split_payload>",
        )

    if re.search(r"\bDAN\b|developer\s+mode|jailbreak|do\s+anything\s+now|fictional\s+scenario\s+where\s+rules\s+do\s+not\s+apply|bypass\s+safety", sanitized, flags=re.IGNORECASE):
        sanitized = _replace_pattern(
            sanitized,
            r"\bDAN\b|developer\s+mode|jailbreak|do\s+anything\s+now|fictional\s+scenario\s+where\s+rules\s+do\s+not\s+apply|bypass\s+safety",
            "<prompt_injection_removed: jailbreak_attempt>",
        )

    return sanitized


def _sanitize_message_value(value: Any) -> Any:
    if isinstance(value, str):
        return _sanitize_message_text(value)
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
        # Replace any currently configured unapproved LLM with an organization-approved
        # model from your allow list before deployment; registry enforcement is handled
        # outside this file.
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
