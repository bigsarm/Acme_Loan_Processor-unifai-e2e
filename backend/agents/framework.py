"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
import re
import urllib.parse
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient

_UNAPPROVED_LLM_NOTICE = (
    "Replace the current OpenRouter/OpenAI-compatible LLM with an approved LLM "
    "from the organization's allow list before using this agent."
)

_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
_BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b")
_HEX_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){8,}\b")
_BINARY_RE = re.compile(r"\b[01]{16,}\b")
_MORSE_RE = re.compile(r"\b[.\-/ ]{8,}\b")
_SPLIT_PAYLOAD_RE = re.compile(r"(?:[A-Za-z]\s+){6,}[A-Za-z]")


def _looks_like_leetspeak_instruction(value: str) -> bool:
    normalized = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
    candidate = value.lower().translate(normalized)
    suspicious_terms = (
        "ignore previous instructions",
        "forget everything above",
        "developer mode",
        "system prompt",
        "act as unrestricted",
        "you are now dan",
    )
    return any(term in candidate for term in suspicious_terms)


def _neutralize_prompt_content(value: str) -> str:
    if not isinstance(value, str) or not value:
        return value

    sanitized = value
    replacements = [
        (re.compile(r"(?is)\b(ignore previous instructions|forget everything above|disregard all prior directives)\b"), "<prompt_injection_removed: instruction_override>"),
        (re.compile(r"(?is)\b(you are now dan|act as unrestricted|pretend to be an unrestricted assistant|roleplay as system)\b"), "<prompt_injection_removed: role_hijack>"),
        (re.compile(r"(?is)</?system>|</?assistant>|</?user>|<<<?\s*(system|assistant|user)|^\s*[-=]{3,}\s*$"), "<prompt_injection_removed: delimiter_escape>"),
        (re.compile(r"(?is)\b(system:|assistant:|tool:)\s"), "<prompt_injection_removed: fake_system_message> "),
        (re.compile(r"(?is)\b(send|post|upload|exfiltrate|leak)\b.{0,80}\b(to|into|over)\b.{0,80}(https?://|www\.)"), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"(?is)\b(reveal|print|leak|show)\b.{0,80}\b(system prompt|hidden prompt|api key|secret)\b"), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"(?is)\b(in future turns|from now on|for the rest of this chat|persist this instruction|remember this override)\b"), "<prompt_injection_removed: context_poisoning>"),
        (re.compile(r"(?is)\b(ignore instructions in metadata|comments? contain the real instructions|read the hidden field|follow code comments)\b"), "<prompt_injection_removed: indirect_injection>"),
        (re.compile(r"(?is)\b(?:rm\s+-rf|curl\s+|wget\s+|bash\s+-c|sh\s+-c|powershell\s+-|cmd\.exe|subprocess\.|os\.system\(|exec\(|eval\()"), "<prompt_injection_removed: command_injection>"),
        (re.compile(r"(?is)\b(DAN|developer mode|jailbreak|bypass safety|fictional framing)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
        (re.compile(r"(?is)<!--.*?-->"), "<prompt_injection_removed: hidden_text>"),
        (re.compile(r"(?is)(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*white)"), "<prompt_injection_removed: hidden_text>"),
    ]

    for pattern, marker in replacements:
        sanitized = pattern.sub(marker, sanitized)

    if _ZERO_WIDTH_RE.search(sanitized):
        sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

    decoded_url = urllib.parse.unquote(sanitized)
    if decoded_url != sanitized and decoded_url != value:
        sanitized = "<prompt_injection_removed: encoded_payload>"

    if _BASE64_RE.search(sanitized) or _HEX_RE.search(sanitized) or _BINARY_RE.search(sanitized) or _MORSE_RE.search(sanitized):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    if _looks_like_leetspeak_instruction(sanitized):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    if _SPLIT_PAYLOAD_RE.search(sanitized):
        compact = re.sub(r"\s+", "", sanitized.lower())
        if any(term in compact for term in ("ignorepreviousinstructions", "forgeteverythingabove", "youarenowdan", "developermode")):
            sanitized = "<prompt_injection_removed: split_payload>"

    return sanitized


def _sanitize_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_messages: list[dict[str, Any]] = []
    for message in messages:
        if not isinstance(message, dict):
            sanitized_messages.append(message)
            continue
        sanitized_message = dict(message)
        content = sanitized_message.get("content")
        if isinstance(content, str):
            sanitized_message["content"] = _neutralize_prompt_content(content)
        elif isinstance(content, list):
            sanitized_parts = []
            for part in content:
                if isinstance(part, dict):
                    sanitized_part = dict(part)
                    if isinstance(sanitized_part.get("text"), str):
                        sanitized_part["text"] = _neutralize_prompt_content(sanitized_part["text"])
                    if isinstance(sanitized_part.get("content"), str):
                        sanitized_part["content"] = _neutralize_prompt_content(sanitized_part["content"])
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
            return "LLM service not configured. Please set OPENROUTER_MODEL."
        return _UNAPPROVED_LLM_NOTICE

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
