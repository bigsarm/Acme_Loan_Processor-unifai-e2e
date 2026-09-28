"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
import re
import base64
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient


_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u2060]")
_WHITESPACE_RUN_RE = re.compile(r"(?:\s[|/\\_-]?){8,}\S", re.IGNORECASE)
_BASE64_BLOB_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_BLOB_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){12,}\b")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){6,}")
_MORSE_RE = re.compile(r"\b[.\-]{1,6}(?:\s+[.\-]{1,6}){5,}\b")
_BINARY_RE = re.compile(r"\b(?:[01]{8}\s+){5,}[01]{8}\b")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_FAKE_SYSTEM_RE = re.compile(r"(?im)^\s*(?:system|assistant|tool)\s*:\s*.*$")
_DELIMITER_ESCAPE_RE = re.compile(r"(?is)</?(?:system|assistant|tool|user)>|(?:^|\n)\s*(?:---+|===+|```+)\s*(?:$|\n)")
_INSTRUCTION_OVERRIDE_RE = re.compile(r"(?i)\b(?:ignore|disregard|bypass|forget|override)\b.{0,80}\b(?:previous|prior|above|system|developer|safety|guardrail|instructions?)\b")
_ROLE_HIJACK_RE = re.compile(r"(?i)\b(?:you are now|act as|pretend to be|roleplay as|assume the role of)\b.{0,80}\b(?:dan|developer mode|unrestricted|system|root|admin)\b")
_JAILBREAK_RE = re.compile(r"(?i)\b(?:DAN|developer mode|jailbreak|unfiltered|unrestricted|no rules|bypass safety|fictional framing)\b")
_EXFIL_RE = re.compile(r"(?i)\b(?:send|post|upload|exfiltrate|leak|reveal|expose)\b.{0,120}\b(?:system prompt|secrets?|credentials?|tokens?|data|contents?)\b|!\[[^\]]*\]\([^)]*https?://[^)]*\)")
_CONTEXT_POISON_RE = re.compile(r"(?i)\b(?:in (?:the )?next response|from now on|for the rest of this chat|remember this rule|store this secretly|continue with the hidden policy)\b")
_COMMAND_INJECTION_RE = re.compile(r"(?i)(?:`[^`]*(?:rm\s+-rf|curl\s+|wget\s+|bash\s+-c|sh\s+-c|powershell(?:\.exe)?|cmd(?:\.exe)?\s+/c|python\s+-c|nc\s+-e)[^`]*`|\b(?:rm\s+-rf|curl\s+https?://|wget\s+https?://|bash\s+-c|sh\s+-c|powershell(?:\.exe)?|cmd(?:\.exe)?\s+/c|python\s+-c|nc\s+-e|chmod\s+\+x)\b)")
_INDIRECT_INJECTION_RE = re.compile(r"(?i)\b(?:file|document|metadata|comment|field|attachment|code comment)\b.{0,80}\b(?:ignore|override|follow these instructions|run this command|execute)\b")
_SPLIT_PAYLOAD_RE = re.compile(r"(?i)(?:i\s*g\s*n\s*o\s*r\s*e|d\s*a\s*n|b\s*y\s*p\s*a\s*s\s*s|r\s*m\s*-\s*r\s*f)")
_LEETSPEAK_RE = re.compile(r"(?i)\b(?:1gn0r[e3]|byp[a4]ss|d3v3l0p3r|unr3str1ct3d|pr3v10us|1nstruct10ns?)\b")
_SUSPICIOUS_DECODED_RE = re.compile(r"(?i)\b(?:ignore previous instructions|forget everything above|you are now|act as|developer mode|system prompt|rm\s+-rf|curl\s+https?://|powershell(?:\.exe)?|cmd(?:\.exe)?\s+/c)\b")


def _decode_base64_if_text(value: str) -> str | None:
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception:
        return None
    if not decoded:
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if _SUSPICIOUS_DECODED_RE.search(text) else None


def _replace_decoded_payloads(text: str) -> str:
    def _base64_replacer(match: re.Match[str]) -> str:
        return "<prompt_injection_removed: encoded_payload>" if _decode_base64_if_text(match.group(0)) else match.group(0)

    text = _BASE64_BLOB_RE.sub(_base64_replacer, text)
    text = _HEX_BLOB_RE.sub("<prompt_injection_removed: encoded_payload>", text)
    text = _URL_ENCODED_RE.sub("<prompt_injection_removed: encoded_payload>", text)
    text = _MORSE_RE.sub("<prompt_injection_removed: encoded_payload>", text)
    text = _BINARY_RE.sub("<prompt_injection_removed: encoded_payload>", text)
    return text


def _sanitize_prompt_text(text: str) -> str:
    sanitized = text
    sanitized = _HTML_COMMENT_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _replace_decoded_payloads(sanitized)
    sanitized = _LEETSPEAK_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
    sanitized = _SPLIT_PAYLOAD_RE.sub("<prompt_injection_removed: split_payload>", sanitized)
    sanitized = _WHITESPACE_RUN_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _INSTRUCTION_OVERRIDE_RE.sub("<prompt_injection_removed: instruction_override>", sanitized)
    sanitized = _ROLE_HIJACK_RE.sub("<prompt_injection_removed: role_hijack>", sanitized)
    sanitized = _DELIMITER_ESCAPE_RE.sub("<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = _FAKE_SYSTEM_RE.sub("<prompt_injection_removed: fake_system_message>", sanitized)
    sanitized = _EXFIL_RE.sub("<prompt_injection_removed: exfiltration_attempt>", sanitized)
    sanitized = _CONTEXT_POISON_RE.sub("<prompt_injection_removed: context_poisoning>", sanitized)
    sanitized = _INDIRECT_INJECTION_RE.sub("<prompt_injection_removed: indirect_injection>", sanitized)
    sanitized = _COMMAND_INJECTION_RE.sub("<prompt_injection_removed: command_injection>", sanitized)
    sanitized = _JAILBREAK_RE.sub("<prompt_injection_removed: jailbreak_attempt>", sanitized)
    return sanitized


def _sanitize_message_payload(value: Any) -> Any:
    if isinstance(value, str):
        return _sanitize_prompt_text(value)
    if isinstance(value, list):
        return [_sanitize_message_payload(item) for item in value]
    if isinstance(value, dict):
        sanitized = dict(value)
        if "content" in sanitized:
            sanitized["content"] = _sanitize_message_payload(sanitized["content"])
        return sanitized
    return value


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
        # Replace this provider/model with an organization-approved LLM selected via the runtime registry/allow list.
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
        # The configured provider/model must be replaced by an organization-approved LLM from the runtime registry.
        if not api_key:
            return "LLM service not configured. Please set OPENROUTER_API_KEY."
        if not model:
            return "LLM service not configured. Please set OPENROUTER_MODEL."

        messages = _sanitize_message_payload(messages)
        return await self.model_client.chat(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent."""
