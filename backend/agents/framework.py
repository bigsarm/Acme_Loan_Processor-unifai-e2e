"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
import re
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient


_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\ufeff\u2060"


def _replace_pattern(text: str, pattern: str, replacement: str, flags: int = 0) -> str:
    return re.sub(pattern, replacement, text, flags=flags)


def _redact_pii(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text
    sanitized = _replace_pattern(
        sanitized,
        r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b",
        "<pii_redacted:email>",
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b\d{3}-\d{2}-\d{4}\b",
        "<pii_redacted:ssn>",
    )
    sanitized = _replace_pattern(
        sanitized,
        r"(?<!\w)(?:\+?1[-.\s]?)?(?:\(\d{3}\)[-.\s]?|\d{3}[-.\s])\d{3}[-.\s]?\d{4}(?!\w)",
        "<pii_redacted:phone>",
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:\d[ -]*?){13,19}\b",
        "<pii_redacted:credit_card>",
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:\d[ -]*?){8,17}\b(?=\s*(?:account|acct)\b)",
        "<pii_redacted:financial_account>",
        flags=re.IGNORECASE,
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b\d{2}-\d{7}\b",
        "<pii_redacted:tin>",
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:[A-HJ-NPR-Z0-9]{17})\b",
        "<pii_redacted:vin>",
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        "<pii_redacted:ip_address>",
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b",
        "<pii_redacted:mac_address>",
    )

    labeled_patterns = [
        (r"(\b(?:year\s+of\s+birth|yob|dob|date\s+of\s+birth)\s*[:#-]?\s*)(\d{4}(?:-\d{2}-\d{2})?)", "<pii_redacted:birth_date>"),
        (r"(\bborn\s+in\s+)(\d{4})", "<pii_redacted:birth_year>"),
        (r"(\bbirthplace\s*[:#-]?\s*)([^,;\n]+)", "<pii_redacted:birthplace>"),
        (r"(\bmother'?s\s+maiden\s+name\s*[:#-]?\s*)([^,;\n]+)", "<pii_redacted:maiden_name>"),
        (r"(\bhome\s+address\s*[:#-]?\s*)([^\n]+)", "<pii_redacted:home_address>"),
        (r"(\baddress\s*[:#-]?\s*)([^\n]+)", "<pii_redacted:home_address>"),
        (r"(\bpassport(?:\s+number|\s+no\.?|\s*#)?\s*[:#-]?\s*)([A-Za-z0-9-]{6,20})", "<pii_redacted:passport_number>"),
        (r"(\bdriver'?s\s+licen[cs]e(?:\s+number|\s+no\.?|\s*#)?\s*[:#-]?\s*)([A-Za-z0-9-]{5,20})", "<pii_redacted:drivers_license>"),
        (r"(\bmedical\s+record(?:s)?\s*[:#-]?\s*)([^\n]+)", "<pii_redacted:medical_records>"),
        (r"(\bemployee\s+id\s*[:#-]?\s*)([A-Za-z0-9-]{2,20})", "<pii_redacted:employee_id>"),
        (r"(\bschool\s+id\s*[:#-]?\s*)([A-Za-z0-9-]{2,20})", "<pii_redacted:school_id>"),
        (r"(\bfingerprint(?:s)?\s*[:#-]?\s*)([^\n]+)", "<pii_redacted:fingerprint>"),
        (r"(\bretina(?:/iris)?\s+scan\s*[:#-]?\s*)([^\n]+)", "<pii_redacted:retina_iris_scan>"),
        (r"(\bvoice\s+signature\s*[:#-]?\s*)([^\n]+)", "<pii_redacted:voice_signature>"),
        (r"(\bfacial\s+image\s*[:#-]?\s*)([^\n]+)", "<pii_redacted:facial_image>"),
        (r"(\bfine\s+location\s*[:#-]?\s*)([^\n]+)", "<pii_redacted:fine_location>"),
        (r"(\bethnicity\s*[:#-]?\s*)([^\n]+)", "<pii_redacted:ethnicity>"),
        (r"(\bsexual\s+orientation\s*[:#-]?\s*)([^\n]+)", "<pii_redacted:sexual_orientation>"),
    ]
    for pattern, marker in labeled_patterns:
        sanitized = re.sub(pattern, lambda m: f"{m.group(1)}{marker}", sanitized, flags=re.IGNORECASE)

    return sanitized


def _neutralize_prompt_injection(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text

    sanitized = _replace_pattern(
        sanitized,
        r"<!--(?:(?!-->).)*(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|reveal\s+(?:the\s+)?system\s+prompt|list\s+all\s+passwords\s+and\s+api\s+keys)(?:(?!-->).)*-->",
        "<prompt_injection_removed:hidden_text>",
        flags=re.IGNORECASE | re.DOTALL,
    )
    sanitized = _replace_pattern(
        sanitized,
        r"<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</[^>]+>",
        "<prompt_injection_removed:hidden_text>",
        flags=re.IGNORECASE | re.DOTALL,
    )
    sanitized = _replace_pattern(
        sanitized,
        "[" + re.escape(_ZERO_WIDTH_CHARS) + r"]{2,}",
        "<prompt_injection_removed:hidden_text>",
    )

    sanitized = _replace_pattern(
        sanitized,
        r"(?i)(?:%69%67%6e%6f%72%65%20%70%72%65%76%69%6f%75%73%20%69%6e%73%74%72%75%63%74%69%6f%6e%73)",
        "<prompt_injection_removed:encoded_payload>",
    )
    sanitized = _replace_pattern(
        sanitized,
        r"(?i)\b(?:[A-F0-9]{2}\s+){8,}[A-F0-9]{2}\b",
        "<prompt_injection_removed:encoded_payload>",
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b(?=[\s\S]{0,80}\b(?:ignore|forget|system|instructions|passwords|api\s+keys)\b)",
        "<prompt_injection_removed:encoded_payload>",
        flags=re.IGNORECASE,
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:1gn0r[e3]\s+pr[e3]v[i1]0us\s+[i1]nstruct[i1]ons|[i1]gn0r[e3]\s+all\s+pr[i1]0r\s+[i1]nstruct[i1]ons)\b",
        "<prompt_injection_removed:encoded_payload>",
        flags=re.IGNORECASE,
    )

    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+all\s+prior\s+instructions)\b",
        "<prompt_injection_removed:instruction_override>",
        flags=re.IGNORECASE,
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:you\s+are\s+now\s+(?:dan|in\s+admin\s+mode)|act\s+as\s+(?:an\s+unrestricted\s+ai|unrestricted)|developer\s+mode)\b",
        "<prompt_injection_removed:role_hijack>",
        flags=re.IGNORECASE,
    )
    sanitized = _replace_pattern(
        sanitized,
        r"</?system>|</?assistant>|</?user>|(?:^|\n)\s*(?:---|===)\s*(?:\n|$)",
        "<prompt_injection_removed:delimiter_escape>",
        flags=re.IGNORECASE,
    )
    sanitized = _replace_pattern(
        sanitized,
        r"(?:^|\n)\s*(?:system|assistant|tool)\s*:\s*(?:ignore\s+previous\s+instructions|reveal\s+(?:the\s+)?system\s+prompt|list\s+all\s+passwords\s+and\s+api\s+keys)[^\n]*",
        "<prompt_injection_removed:fake_system_message>",
        flags=re.IGNORECASE,
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:reveal|leak|print|list|send)\b[^\n]{0,120}\b(?:system\s+prompt|confidential\s+information|passwords?|api\s+keys?)\b",
        "<prompt_injection_removed:exfiltration_attempt>",
        flags=re.IGNORECASE,
    )
    sanitized = _replace_pattern(
        sanitized,
        r"!\[[^\]]*\]\([^\)]*https?://[^\)]*\)",
        "<prompt_injection_removed:exfiltration_attempt>",
        flags=re.IGNORECASE,
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:in\s+your\s+next\s+reply\s+ignore|from\s+now\s+on\s+ignore|for\s+the\s+rest\s+of\s+this\s+conversation\s+ignore)\b",
        "<prompt_injection_removed:context_poisoning>",
        flags=re.IGNORECASE,
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:metadata|comment|code\s+comment|front\s+matter|yaml)\b[^\n]{0,120}\b(?:ignore\s+previous\s+instructions|reveal\s+(?:the\s+)?system\s+prompt)\b",
        "<prompt_injection_removed:indirect_injection>",
        flags=re.IGNORECASE,
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:curl\s+https?://\S+|wget\s+https?://\S+|rm\s+-rf\s+\S+|bash\s+-c\s+\S+|powershell\s+-(?:enc|encodedcommand)\s+\S+|python\s+-c\s+\S+|chmod\s+\+x\s+\S+\s*&&\s*\./\S+)\b",
        "<prompt_injection_removed:command_injection>",
        flags=re.IGNORECASE,
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\bi\s*gn\s*ore\s+pre\s*vious\s+inst\s*ructions\b|\bfor\s*get\s+every\s*thing\s+above\b",
        "<prompt_injection_removed:split_payload>",
        flags=re.IGNORECASE,
    )
    sanitized = _replace_pattern(
        sanitized,
        r"\b(?:dan|do\s+anything\s+now|jailbreak|bypass\s+safety|fictional\s+framing\s+bypass)\b(?=[^\n]{0,80}\b(?:ignore|bypass|override|unfiltered)\b)|\bdeveloper\s+mode\b",
        "<prompt_injection_removed:jailbreak_attempt>",
        flags=re.IGNORECASE,
    )

    return sanitized


def _sanitize_llm_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text
    return _redact_pii(_neutralize_prompt_injection(text))


def _sanitize_llm_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_messages: list[dict[str, Any]] = []
    for message in messages:
        sanitized_message = deepcopy(message)
        content = sanitized_message.get("content")
        if isinstance(content, str):
            sanitized_message["content"] = _sanitize_llm_text(content)
        elif isinstance(content, list):
            sanitized_parts: list[Any] = []
            for part in content:
                if isinstance(part, dict):
                    sanitized_part = deepcopy(part)
                    if isinstance(sanitized_part.get("text"), str):
                        sanitized_part["text"] = _sanitize_llm_text(sanitized_part["text"])
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

        messages = _sanitize_llm_messages(messages)
        return await self.model_client.chat(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent."""
