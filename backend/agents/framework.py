"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
import re
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient


def _replace_if_decodes_to_attack(value: str, marker: str) -> str:
    stripped = value.strip()
    if len(stripped) < 8:
        return value

    base64_pattern = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")

    def _base64_replacer(match: re.Match[str]) -> str:
        token = match.group(0)
        if len(token) < 12 or len(token) % 4 != 0:
            return token
        try:
            decoded = __import__("base64").b64decode(token, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            return token
        if _contains_attack_text(decoded):
            return marker
        return token

    return base64_pattern.sub(_base64_replacer, value)


def _contains_attack_text(value: str) -> bool:
    normalized = value.lower()
    normalized = re.sub(r"[\s\u200b\u200c\u200d\ufeff]+", " ", normalized)
    deobfuscated = normalized.translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}))
    attack_patterns = [
        r"\bignore\s+(?:all\s+)?previous\s+instructions\b",
        r"\bforget\s+(?:everything|all)\s+(?:above|before)\b",
        r"\byou\s+are\s+now\s+(?:dan|developer\s+mode|admin\s+mode)\b",
        r"\bact\s+as\s+(?:an\s+)?(?:unrestricted|unfiltered)\b",
        r"\breveal\s+(?:the\s+)?system\s+prompt\b",
        r"\blist\s+all\s+(?:passwords|api\s+keys|secrets)\b",
        r"\b(?:curl|wget|powershell|bash|sh)\s+https?://",
        r"\b(?:rm\s+-rf|chmod\s+\+x|python\s+-c|node\s+-e)\b",
        r"</system>|<system>|<tool>|</tool>",
    ]
    return any(re.search(pattern, normalized, flags=re.IGNORECASE) or re.search(pattern, deobfuscated, flags=re.IGNORECASE) for pattern in attack_patterns)


def _sanitize_prompt_text(value: str) -> str:
    if not isinstance(value, str) or not value:
        return value

    sanitized = value
    sanitized = re.sub(r"<!--(?:(?!-->).)*(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|reveal\s+the\s+system\s+prompt)(?:(?!-->).)*-->", "<prompt_injection_removed: hidden_text>", sanitized, flags=re.IGNORECASE | re.DOTALL)
    sanitized = re.sub(r"<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</[^>]+>", "<prompt_injection_removed: hidden_text>", sanitized, flags=re.IGNORECASE | re.DOTALL)
    sanitized = re.sub(r"[\u200b\u200c\u200d\ufeff]+", "<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"\bignore\s+(?:all\s+)?previous\s+instructions\b|\bforget\s+(?:everything|all)\s+(?:above|before)\b", "<prompt_injection_removed: instruction_override>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\byou\s+are\s+now\s+(?:dan|developer\s+mode|admin\s+mode)\b|\bact\s+as\s+(?:an\s+)?(?:unrestricted|unfiltered)\b", "<prompt_injection_removed: role_hijack>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"</system>|<system>|</assistant>|<assistant>|</tool>|<tool>", "<prompt_injection_removed: delimiter_escape>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(?:system|assistant|tool)\s*:\s*(?:ignore\s+previous\s+instructions|reveal\s+the\s+system\s+prompt|list\s+all\s+(?:passwords|api\s+keys|secrets))", "<prompt_injection_removed: fake_system_message>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(?:reveal|leak|send|post|upload|exfiltrate)\b[^\n]{0,120}\b(?:system\s+prompt|secrets?|passwords?|api\s+keys?|tokens?|credentials?)\b[^\n]{0,120}\b(?:to|via)\b[^\n]{0,120}(?:https?://\S+|markdown image|img\s+src)", "<prompt_injection_removed: exfiltration_attempt>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"!\[[^\]]*\]\(https?://[^)]+\)", "<prompt_injection_removed: exfiltration_attempt>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(?:in\s+the\s+next\s+turn|on\s+your\s+next\s+reply|from\s+now\s+on)\b[^\n]{0,120}\b(?:ignore|override|disregard)\b", "<prompt_injection_removed: context_poisoning>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(?:DAN|developer\s+mode|jailbreak|bypass\s+safety|fictional\s+framing)\b", "<prompt_injection_removed: jailbreak_attempt>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(?:curl|wget)\s+https?://\S+|\b(?:bash|sh|powershell|cmd(?:\.exe)?)\b\s+(?:-c|/c)\b[^\n]*|\bpython\s+-c\b[^\n]*|\bnode\s+-e\b[^\n]*|\brm\s+-rf\b[^\n]*|\bchmod\s+\+x\b[^\n]*", "<prompt_injection_removed: command_injection>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(?:eval|exec)\s*\([^\n]*\)", "<prompt_injection_removed: command_injection>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"(?:[A-Za-z]\s+){6,}[A-Za-z]", "<prompt_injection_removed: split_payload>", sanitized, flags=re.IGNORECASE, count=1) if _contains_attack_text(re.sub(r"\s+", "", sanitized)) else sanitized
    sanitized = _replace_if_decodes_to_attack(sanitized, "<prompt_injection_removed: encoded_payload>")
    if _contains_attack_text(__import__("urllib.parse").parse.unquote(sanitized)) and __import__("urllib.parse").parse.unquote(sanitized) != sanitized:
        sanitized = "<prompt_injection_removed: encoded_payload>"
    if _contains_attack_text(__import__("codecs").decode(sanitized, "rot_13")) and __import__("codecs").decode(sanitized, "rot_13") != sanitized:
        sanitized = "<prompt_injection_removed: encoded_payload>"
    if re.search(r"\b(?:filename|metadata|comment)\b[^\n]{0,120}\b(?:ignore\s+previous\s+instructions|reveal\s+the\s+system\s+prompt|act\s+as\s+unrestricted)\b", sanitized, flags=re.IGNORECASE):
        sanitized = re.sub(r"\b(?:filename|metadata|comment)\b[^\n]{0,120}\b(?:ignore\s+previous\s+instructions|reveal\s+the\s+system\s+prompt|act\s+as\s+unrestricted)\b", "<prompt_injection_removed: indirect_injection>", sanitized, flags=re.IGNORECASE)
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
                    if isinstance(sanitized_part.get("text"), str):
                        sanitized_part["text"] = _sanitize_prompt_text(sanitized_part["text"])
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
        # Runtime LLM calls currently use OpenRouter credentials from .env.
        # Replace this provider/model with an organization-approved LLM from the allow list before production use.
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
        Replace the configured provider/model with an organization-approved LLM before production use.
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
