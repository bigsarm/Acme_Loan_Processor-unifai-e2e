"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
import re
import urllib.parse
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient


def _replace_pattern(text: str, pattern: str, marker: str, flags: int = re.IGNORECASE) -> str:
    return re.sub(pattern, marker, text, flags=flags)


def _decode_obfuscated_text(text: str) -> list[str]:
    candidates: list[str] = []
    url_decoded = urllib.parse.unquote(text)
    if url_decoded != text:
        candidates.append(url_decoded)

    compact = re.sub(r"\s+", "", text)
    if compact and len(compact) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", compact):
        try:
            hex_decoded = bytes.fromhex(compact).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            hex_decoded = ""
        if hex_decoded:
            candidates.append(hex_decoded)

    b64_alphabet = re.fullmatch(r"[A-Za-z0-9+/=\s]+", text)
    if b64_alphabet:
        try:
            import base64

            decoded = base64.b64decode(text, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            decoded = ""
        if decoded:
            candidates.append(decoded)

    return candidates


def _contains_hidden_instruction(text: str) -> bool:
    hidden_patterns = (
        r"<!--(?:(?!-->).)*(?:ignore previous instructions|forget everything above|system prompt|reveal|send data|curl\s+https?://)(?:(?!-->).)*-->",
        r"color\s*:\s*(?:#fff(?:fff)?|white)\s*;(?:(?!>).)*(?:ignore previous instructions|forget everything above|reveal|send data)",
        r"font-size\s*:\s*0(?:px|rem|em|%)?(?:(?!>).)*(?:ignore previous instructions|forget everything above|reveal|send data)",
        r"display\s*:\s*none(?:(?!>).)*(?:ignore previous instructions|forget everything above|reveal|send data)",
    )
    return any(re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL) for pattern in hidden_patterns)


def _sanitize_prompt_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text

    if _contains_hidden_instruction(sanitized) or re.search(r"[\u200B-\u200F\u2060\uFEFF]", sanitized):
        sanitized = re.sub(r"<!--.*?-->", "<prompt_injection_removed: hidden_text>", sanitized, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r"[\u200B-\u200F\u2060\uFEFF]+", "<prompt_injection_removed: hidden_text>", sanitized)
        sanitized = re.sub(
            r"(?is)<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0(?:px|rem|em|%)?|color\s*:\s*(?:#fff(?:fff)?|white))[^\"']*[\"'][^>]*>.*?</[^>]+>",
            "<prompt_injection_removed: hidden_text>",
            sanitized,
        )

    replacement_patterns = [
        (r"\b(?:ignore previous instructions|ignore all previous instructions|forget everything above|disregard (?:all )?(?:previous|prior) instructions)\b", "<prompt_injection_removed: instruction_override>"),
        (r"\b(?:you are now (?:dan|developer mode|in admin mode)|act as (?:an unrestricted ai|unrestricted|dan)|pretend to be (?:(?:the )?system|developer))\b", "<prompt_injection_removed: role_hijack>"),
        (r"(?:</system>|</assistant>|<system>|<assistant>|\[system\]|\[/system\]|^\s*---\s*$|^\s*===\s*$)", "<prompt_injection_removed: delimiter_escape>"),
        (r"\b(?:system\s*:\s*|assistant\s*:\s*|tool\s*:\s*)\s*(?:ignore previous instructions|reveal|send|list|print|show)", "<prompt_injection_removed: fake_system_message>"),
        (r"\b(?:reveal|leak|print|dump|show|list)\b.{0,80}\b(?:system prompt|confidential information|passwords?|api keys?|secrets?)\b", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"!\[[^\]]*\]\(https?://[^)]+\)", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"\b(?:send|post|upload|exfiltrate|curl|wget)\b.{0,120}https?://\S+", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"\b(?:from now on|in the next response|for the rest of this chat|every subsequent answer)\b.{0,80}\b(?:ignore|bypass|override|instead)\b", "<prompt_injection_removed: context_poisoning>"),
        (r"\b(?:developer mode|jailbreak|do anything now|dan mode|fictional scenario to bypass safety)\b", "<prompt_injection_removed: jailbreak_attempt>"),
        (r"\b(?:eval\s*\(|exec\s*\(|__import__\s*\(|os\.system\s*\(|subprocess\.(?:run|Popen|call)\s*\(|rm\s+-rf\b|curl\s+https?://|wget\s+https?://|bash\s+-c\b|sh\s+-c\b|powershell(?:\.exe)?\b|cmd(?:\.exe)?\s+/c\b)\S*", "<prompt_injection_removed: command_injection>"),
        (r"\b(?:metadata|comment|code comment|front matter|yaml|json field|file content)\b.{0,80}\b(?:ignore previous instructions|act as|reveal|send data)\b", "<prompt_injection_removed: indirect_injection>"),
        (r"\bi\s*g\s*n\s*o\s*r\s*e\s+previous\s+instructions\b|\by\s*o\s*u\s+a\s*r\s*e\s+n\s*o\s*w\s+d\s*a\s*n\b", "<prompt_injection_removed: split_payload>"),
    ]

    for pattern, marker in replacement_patterns:
        sanitized = _replace_pattern(sanitized, pattern, marker, flags=re.IGNORECASE | re.MULTILINE)

    leetspeak_patterns = (
        r"\b[i1!|][g69][n\/]?[o0][rre3][\s_-]*pr[e3]v[i1!|][o0]us[\s_-]*[i1!|]nstr[uµ]ct[i1!|][o0]ns\b",
        r"\by[o0]u[\s_-]*[a@]r[e3][\s_-]*n[o0]w[\s_-]*d[a@]n\b",
    )
    if any(re.search(pattern, sanitized, flags=re.IGNORECASE) for pattern in leetspeak_patterns):
        sanitized = re.sub(r".*", "<prompt_injection_removed: encoded_payload>", sanitized, count=1)

    decoded_candidates = _decode_obfuscated_text(sanitized)
    decoded_attack_patterns = (
        r"\bignore previous instructions\b",
        r"\bforget everything above\b",
        r"\byou are now (?:dan|in admin mode)\b",
        r"\bact as (?:an unrestricted ai|unrestricted|dan)\b",
        r"\b(?:curl|wget|bash -c|sh -c|powershell|cmd /c)\b",
        r"</system>",
    )
    if any(re.search(pattern, candidate, flags=re.IGNORECASE) for candidate in decoded_candidates for pattern in decoded_attack_patterns):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    return sanitized


def _sanitize_message_payload(value: Any) -> Any:
    if isinstance(value, str):
        return _sanitize_prompt_text(value)
    if isinstance(value, list):
        return [_sanitize_message_payload(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_message_payload(item) for key, item in value.items()}
    return value


def _sanitize_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_sanitize_message_payload(message) for message in messages]


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
