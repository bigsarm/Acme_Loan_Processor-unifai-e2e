"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
import re
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient


def _neutralize_prompt_text(text: str) -> str:
    sanitized = text

    replacements: list[tuple[re.Pattern[str], str]] = [
        (
            re.compile(r"(?i)\b(ignore|disregard|forget)\b.{0,80}\b(previous|above|earlier|prior)\b.{0,80}\b(instruction|prompt|message|context)s?\b"),
            "<prompt_injection_removed: instruction_override>",
        ),
        (
            re.compile(r"(?i)\b(ignore|bypass|override)\b.{0,80}\b(system prompt|developer message|safety rules|guardrails?)\b"),
            "<prompt_injection_removed: instruction_override>",
        ),
        (
            re.compile(r"(?i)\b(you are now|act as|pretend to be|roleplay as)\b.{0,80}\b(dan|unrestricted|developer mode|system|root|admin)\b"),
            "<prompt_injection_removed: role_hijack>",
        ),
        (
            re.compile(r"(?is)</?(system|assistant|tool|developer)>|```(?:system|assistant|tool|developer)|---+\s*(system|assistant|tool|developer)\s*---+"),
            "<prompt_injection_removed: delimiter_escape>",
        ),
        (
            re.compile(r"(?is)<!--.*?(ignore|bypass|override|reveal|exfiltrate).*?-->"),
            "<prompt_injection_removed: hidden_text>",
        ),
        (
            re.compile(r"[\u200b\u200c\u200d\ufeff]"),
            "<prompt_injection_removed: hidden_text>",
        ),
        (
            re.compile(r"(?i)\b(system message|developer message|tool result)\s*:\s*"),
            "<prompt_injection_removed: fake_system_message>",
        ),
        (
            re.compile(r"(?i)\b(reveal|leak|exfiltrate|send)\b.{0,80}\b(system prompt|hidden prompt|secret|credentials?|api key|token|data)\b"),
            "<prompt_injection_removed: exfiltration_attempt>",
        ),
        (
            re.compile(r"(?i)!\[[^\]]*\]\([^)]*https?://[^)]*\)"),
            "<prompt_injection_removed: exfiltration_attempt>",
        ),
        (
            re.compile(r"(?i)\b(in future turns|from now on|for the rest of this chat|across turns|persist this instruction)\b"),
            "<prompt_injection_removed: context_poisoning>",
        ),
        (
            re.compile(r"(?i)\b(comment|metadata|field|filename|file content|document)\b.{0,80}\b(ignore|override|bypass|reveal|exfiltrate)\b"),
            "<prompt_injection_removed: indirect_injection>",
        ),
        (
            re.compile(r"(?i)\b(eval|exec|__import__|os\.system|subprocess\.(run|popen|call)|bash\s+-c|sh\s+-c|cmd(?:\.exe)?\s*/c|powershell(?:\.exe)?)\b"),
            "<prompt_injection_removed: command_injection>",
        ),
        (
            re.compile(r"(?i)\b(rm\s+-rf|curl\s+|wget\s+|chmod\s+\+x|nc\s+-e)\b"),
            "<prompt_injection_removed: command_injection>",
        ),
        (
            re.compile(r"(?i)\b(dan|developer mode|jailbreak|do anything now|fictional scenario to bypass)\b"),
            "<prompt_injection_removed: jailbreak_attempt>",
        ),
        (
            re.compile(r"(?i)(?:[A-Za-z]\s*){8,}"),
            "<prompt_injection_removed: split_payload>",
        ),
        (
            re.compile(r"(?i)\b(?:[A-F0-9]{2}\s*){8,}\b|\b(?:[A-Za-z0-9+/]{20,}={0,2})\b|(?:%[0-9A-Fa-f]{2}){6,}|\\u[0-9A-Fa-f]{4}"),
            "<prompt_injection_removed: encoded_payload>",
        ),
        (
            re.compile(r"(?i)\b(?:1gn0r[e3]|0verr1de|byp4ss|3xfiltr4te|d3v3lop3r m0d3)\b"),
            "<prompt_injection_removed: encoded_payload>",
        ),
        (
            re.compile(r"(?i)(?:\.-|--|\.\.\.|-\.-\.|---){6,}"),
            "<prompt_injection_removed: encoded_payload>",
        ),
    ]

    for pattern, replacement in replacements:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized


def _sanitize_message_content(content: Any) -> Any:
    if isinstance(content, str):
        return _neutralize_prompt_text(content)
    if isinstance(content, list):
        sanitized_list: list[Any] = []
        for item in content:
            if isinstance(item, dict):
                sanitized_item = dict(item)
                if "text" in sanitized_item and isinstance(sanitized_item["text"], str):
                    sanitized_item["text"] = _neutralize_prompt_text(sanitized_item["text"])
                sanitized_list.append(sanitized_item)
            else:
                sanitized_list.append(item)
        return sanitized_list
    return content


def _sanitize_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_messages: list[dict[str, Any]] = []
    for message in messages:
        sanitized_message = dict(message)
        if "content" in sanitized_message:
            sanitized_message["content"] = _sanitize_message_content(sanitized_message["content"])
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

        return await self.model_client.chat(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent."""
