"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
import re
import urllib.parse
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient


_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]+")
_HIDDEN_HTML_RE = re.compile(
    r"<!--.*?-->|<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white(?:\s*;|\s|$))[^\"']*[\"'][^>]*>.*?</[^>]+>",
    re.IGNORECASE | re.DOTALL,
)
_BASE64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")
_HEX_CHARS_RE = re.compile(r"^(?:0x)?[0-9A-Fa-f\s]+$")


def _replace_if_decoded_instruction(segment: str) -> str:
    stripped = segment.strip()
    if len(stripped) < 16:
        return segment
    compact = "".join(stripped.split())
    if len(compact) >= 16 and len(compact) % 4 == 0 and _BASE64_CHARS_RE.fullmatch(stripped):
        try:
            decoded = __import__("base64").b64decode(compact, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            decoded = ""
        if decoded and _sanitize_text(decoded) != decoded:
            return "<prompt_injection_removed: encoded_payload>"
    hex_candidate = compact[2:] if compact.lower().startswith("0x") else compact
    if len(hex_candidate) >= 16 and len(hex_candidate) % 2 == 0 and _HEX_CHARS_RE.fullmatch(stripped):
        try:
            decoded = bytes.fromhex(hex_candidate).decode("utf-8", errors="ignore")
        except Exception:
            decoded = ""
        if decoded and _sanitize_text(decoded) != decoded:
            return "<prompt_injection_removed: encoded_payload>"
    return segment


def _sanitize_text(text: str) -> str:
    sanitized = text
    sanitized = _HIDDEN_HTML_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

    replacements = [
        (re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b|\bforget\s+everything\s+above\b"), "<prompt_injection_removed: instruction_override>"),
        (re.compile(r"(?i)\b(?:you\s+are\s+now\s+dan|act\s+as\s+(?:an\s+)?unrestricted|developer\s+mode|do\s+anything\s+now)\b"), "<prompt_injection_removed: role_hijack>"),
        (re.compile(r"(?i)</?system>|</?assistant>|</?user>|<{3,}|>{3,}|\[system\]|\[assistant\]|\[user\]"), "<prompt_injection_removed: delimiter_escape>"),
        (re.compile(r"(?i)\b(?:system\s*:\s*you\s+must|tool\s*:\s*|assistant\s*:\s*ignore|user\s*:\s*override)"), "<prompt_injection_removed: fake_system_message>"),
        (re.compile(r"(?i)\b(?:reveal|leak|disclose|print|dump|show|send)\b.{0,80}\b(?:system\s+prompt|api\s+keys?|passwords?|secrets?|tokens?|credentials?|confidential\s+information)\b|!\[[^\]]*\]\([^)]*https?://[^)]*\)"), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"(?i)\b(?:in\s+the\s+next\s+message|from\s+now\s+on|for\s+the\s+rest\s+of\s+this\s+chat|persist\s+this\s+instruction)\b"), "<prompt_injection_removed: context_poisoning>"),
        (re.compile(r"(?i)\b(?:file\s+metadata|document\s+metadata|code\s+comment|hidden\s+field)\b.{0,80}\b(?:ignore|override|follow\s+these\s+instructions)\b"), "<prompt_injection_removed: indirect_injection>"),
        (re.compile(r"(?i)\b(?:curl\s+https?://|wget\s+https?://|powershell(?:\.exe)?\b|cmd(?:\.exe)?\s*/c\b|/bin/(?:sh|bash)\b|\b(?:bash|sh)\s+-c\b|python\s+-c\b|node\s+-e\b|os\.system\(|subprocess\.(?:run|popen|call)\(|eval\(|exec\()"), "<prompt_injection_removed: command_injection>"),
        (re.compile(r"(?i)\b(?:d\s*a\s*n|j\s*a\s*i\s*l\s*b\s*r\s*e\s*a\s*k|bypass\s+safety|fictional\s+framing)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
        (re.compile(r"(?i)\bi\s*g\s*n\s*o\s*r\s*e\s+\w+\s*i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s\b|\by\s*o\s*u\s+a\s*r\s*e\s+n\s*o\s*w\b"), "<prompt_injection_removed: split_payload>"),
    ]
    for pattern, replacement in replacements:
        sanitized = pattern.sub(replacement, sanitized)

    if "%" in sanitized:
        decoded_url = urllib.parse.unquote(sanitized)
        if decoded_url != sanitized and _sanitize_text(decoded_url) != decoded_url:
            sanitized = decoded_url
    sanitized = re.sub(r"[A-Za-z0-9+/=]{16,}|(?:0x)?[0-9A-Fa-f]{16,}", lambda match: _replace_if_decoded_instruction(match.group(0)), sanitized)

    leetspeak_normalized = sanitized.translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}))
    if leetspeak_normalized != sanitized:
        if re.search(r"(?i)\b(?:ignore\s+previous\s+instructions|you\s+are\s+now\s+dan|act\s+as\s+unrestricted|developer\s+mode)\b", leetspeak_normalized):
            sanitized = re.sub(r"\S+", "<prompt_injection_removed: encoded_payload>", sanitized, count=1)

    return sanitized


def _sanitize_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_messages: list[dict[str, Any]] = []
    for message in messages:
        sanitized_message = dict(message)
        content = sanitized_message.get("content")
        if isinstance(content, str):
            sanitized_message["content"] = _sanitize_text(content)
        elif isinstance(content, list):
            sanitized_parts: list[Any] = []
            for part in content:
                if isinstance(part, dict):
                    sanitized_part = dict(part)
                    if isinstance(sanitized_part.get("text"), str):
                        sanitized_part["text"] = _sanitize_text(sanitized_part["text"])
                    sanitized_parts.append(sanitized_part)
                else:
                    sanitized_parts.append(part)
            sanitized_message["content"] = sanitized_parts
        sanitized_messages.append(sanitized_message)
    return sanitized_messages


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
            return "LLM service not configured. Please set OPENROUTER_MODEL to an approved LLM from your organization's allow list."

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
