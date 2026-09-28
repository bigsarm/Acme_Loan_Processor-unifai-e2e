"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
import re
import urllib.parse
from abc import ABC, abstractmethod
from base64 import b64decode
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient


def _looks_like_base64(value: str) -> bool:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 16 or len(compact) % 4 != 0:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/=]+", compact) is not None


def _decode_if_base64(value: str) -> str | None:
    if not _looks_like_base64(value):
        return None
    try:
        decoded = b64decode(re.sub(r"\s+", "", value), validate=True)
        return decoded.decode("utf-8")
    except Exception:
        return None


def _normalize_leetspeak(value: str) -> str:
    table = str.maketrans({
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    })
    return value.translate(table)


def _sanitize_prompt_text(value: str) -> str:
    sanitized = value

    hidden_patterns = [
        (r"<!--[\s\S]*?(ignore previous instructions|forget everything above|you are now|act as unrestricted)[\s\S]*?-->", "<prompt_injection_removed: hidden_text>"),
        (r"(?i)<span[^>]*display\s*:\s*none[^>]*>[\s\S]*?</span>", "<prompt_injection_removed: hidden_text>"),
        (r"(?i)<div[^>]*display\s*:\s*none[^>]*>[\s\S]*?</div>", "<prompt_injection_removed: hidden_text>"),
        (r"[\u200b\u200c\u200d\ufeff]+", "<prompt_injection_removed: hidden_text>"),
    ]
    for pattern, replacement in hidden_patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

    direct_patterns = [
        (r"(?i)\b(ignore previous instructions|ignore all previous instructions|forget everything above|disregard earlier instructions)\b", "<prompt_injection_removed: instruction_override>"),
        (r"(?i)\b(you are now dan|act as unrestricted|developer mode|do anything now)\b", "<prompt_injection_removed: jailbreak_attempt>"),
        (r"(?i)\b(act as an unrestricted ai|act as a different system|you are now a system prompt)\b", "<prompt_injection_removed: role_hijack>"),
        (r"(?i)</system>|<system>|</assistant>|<assistant>|</tool>|<tool>", "<prompt_injection_removed: delimiter_escape>"),
        (r"(?i)\b(system:|assistant:|tool:)\s*(ignore previous instructions|forget everything above|reveal|leak)", "<prompt_injection_removed: fake_system_message>"),
        (r"(?i)\b(send|post|upload|exfiltrate|leak)\b[\s\S]{0,80}\b(to|via)\b[\s\S]{0,80}(https?://\S+|www\.\S+)", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"!\[[^\]]*\]\([^)]*https?://[^)]*\)", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"(?i)\b(in future turns|on the next turn|remember this hidden rule|persist this instruction)\b", "<prompt_injection_removed: context_poisoning>"),
        (r"(?i)\b(curl|wget|powershell|bash|sh)\b\s+\S+", "<prompt_injection_removed: command_injection>"),
        (r"(?i)\b(os\.system|subprocess\.(run|popen|call)|eval\(|exec\()", "<prompt_injection_removed: command_injection>"),
        (r"(?i)\b(base64|hex|rot13|unicode|url-encoded|morse)\b[\s\S]{0,40}\b(ignore previous instructions|forget everything above|reveal the system prompt|act as unrestricted)\b", "<prompt_injection_removed: encoded_payload>"),
        (r"(?i)\b(ignore|forget|bypass)\b(?:\W+\w+){0,6}\W+\b(previous|above|prior|safety|guardrails?)\b", "<prompt_injection_removed: split_payload>"),
    ]
    for pattern, replacement in direct_patterns:
        sanitized = re.sub(pattern, replacement, sanitized)

    decoded_base64 = _decode_if_base64(sanitized)
    if decoded_base64 and re.search(r"(?i)\b(ignore previous instructions|forget everything above|you are now|act as unrestricted|curl\s+\S+|wget\s+\S+|reveal the system prompt|send.+https?://)\b", decoded_base64):
        sanitized = re.sub(re.escape(value), "<prompt_injection_removed: encoded_payload>", sanitized) if sanitized == value else "<prompt_injection_removed: encoded_payload>"

    url_decoded = urllib.parse.unquote(sanitized)
    if url_decoded != sanitized and re.search(r"(?i)\b(ignore previous instructions|forget everything above|you are now|act as unrestricted|reveal the system prompt)\b", url_decoded):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    leet_normalized = _normalize_leetspeak(sanitized)
    if re.search(r"(?i)\b(ignore previous instructions|forget everything above|you are now dan|act as unrestricted|developer mode)\b", leet_normalized):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    if re.search(r"(?i)\b(pe32|elf|mach-o|ms-dos executable)\b", sanitized):
        sanitized = re.sub(r"(?i)\b(pe32|elf|mach-o|ms-dos executable)\b", "<prompt_injection_removed: command_injection>", sanitized)

    return sanitized


def _sanitize_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_messages: list[dict[str, Any]] = []
    for message in messages:
        sanitized_message = dict(message)
        content = sanitized_message.get("content")
        if isinstance(content, str):
            sanitized_message["content"] = _sanitize_prompt_text(content)
        elif isinstance(content, list):
            sanitized_parts = []
            for part in content:
                if isinstance(part, dict):
                    sanitized_part = dict(part)
                    part_text = sanitized_part.get("text")
                    if isinstance(part_text, str):
                        sanitized_part["text"] = _sanitize_prompt_text(part_text)
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
            "provider": "OpenRouter (replace with an approved LLM from the organization's allow list)",
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
            return "LLM service not configured. Please set OPENROUTER_API_KEY and replace the unapproved LLM with an approved model from the organization's allow list."
        if not model:
            return "LLM service not configured. Please set OPENROUTER_MODEL and replace the unapproved LLM with an approved model from the organization's allow list."

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
