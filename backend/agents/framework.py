"""Small agent framework base class used by the Acme Loan Processor agents."""

import os
import re
import binascii
import codecs
import base64
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient

_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ssn", re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")),
    ("phone", re.compile(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("address", re.compile(r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b\.?(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2}\b(?:\s+\d{5}(?:-\d{4})?)?)?(?:,\s*(?:USA|United States)\b)?")),
    ("dob", re.compile(r"(?i)\b(?:DOB|date of birth|born(?: on| in)?)\s*:?\s*(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:19|20)\d{2})\b")),
    ("passport", re.compile(r"(?i)\bpassport(?:\s*(?:no\.?|number|#))?\s*:?\s*(?=[A-Z0-9-]*\d)[A-Z0-9-]{6,9}\b")),
    ("drivers_license", re.compile(r"(?i)\b(?:driver'?s|drivers)\s+licen[cs]e(?:\s*(?:no\.?|number|#))?\s*:?\s*[A-Z0-9-]{5,20}\b")),
    ("tax_id", re.compile(r"(?i)\b(?:taxpayer\s+identification\s+number|tax\s+id|tin)\s*:?\s*[A-Z0-9-]{6,20}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("account_number", re.compile(r"(?i)\b(?:financial\s+account\s+number|account\s+number|acct\s+no\.?|acct)\s*:?\s*[A-Z0-9-]{6,20}\b")),
    ("employee_id", re.compile(r"(?i)\bemployee\s+id\s*:?\s*[A-Z0-9-]{2,20}\b")),
    ("school_id", re.compile(r"(?i)\bschool\s+id\s*:?\s*[A-Z0-9-]{2,20}\b")),
    ("vin", re.compile(r"(?i)\b(?:vehicle\s+identification\s+number|vin)\s*:?\s*[A-HJ-NPR-Z0-9]{17}\b")),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("mac_address", re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b")),
    ("birthplace", re.compile(r"(?i)\b(?:birthplace|place of birth|born in)\s*:?\s*[^,;\n]+")),
    ("maiden_name", re.compile(r"(?i)\b(?:mother'?s maiden name|maiden name)\s*:?\s*[^,;\n]+")),
    ("medical", re.compile(r"(?i)\b(?:medical records?|medical record)\s*:?\s*[^\n]+")),
    ("location", re.compile(r"(?i)\b(?:fine location|precise location|exact location)\s*:?\s*[^,;\n]+")),
    ("ethnicity", re.compile(r"(?i)\bethnicity\s*:?\s*[^,;\n]+")),
    ("sexual_orientation", re.compile(r"(?i)\bsexual orientation\s*:?\s*[^,;\n]+")),
]

_HIDDEN_TEXT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<!--.*?-->", re.IGNORECASE | re.DOTALL),
    re.compile(r"<(?P<tag>\w+)[^>]*style\s*=\s*['\"][^'\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?|color\s*:\s*white)[^'\"]*['\"][^>]*>.*?</(?P=tag)>", re.IGNORECASE | re.DOTALL),
    re.compile(r"[\u200b\u200c\u200d\ufeff]+"),
]

_DIRECT_ATTACK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("instruction_override", re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b")),
    ("instruction_override", re.compile(r"(?i)\bforget\s+everything\s+above\b")),
    ("instruction_override", re.compile(r"(?i)\bignore\s+(?:all\s+)?safety\s+guidelines\b")),
    ("role_hijack", re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:developer\s+mode|admin\s+mode|dan|unrestricted)\b")),
    ("role_hijack", re.compile(r"(?i)\bprovide\s+unrestricted\s+access\b")),
    ("role_hijack", re.compile(r"(?i)\benable\s+developer\s+mode\b")),
    ("role_hijack", re.compile(r"(?i)\bact\s+as\s+an\s+unrestricted\s+ai\b")),
    ("role_hijack", re.compile(r"(?i)\bwithout\s+safety\s+filters\b")),
    ("role_hijack", re.compile(r"(?i)\bSYSTEM\s+OVERRIDE\b")),
    ("exfiltration_attempt", re.compile(r"(?i)\breveal\s+(?:all\s+)?confidential\s+information\b")),
    ("exfiltration_attempt", re.compile(r"(?i)\breveal\s+(?:all\s+)?system\s+prompts?\b")),
    ("exfiltration_attempt", re.compile(r"(?i)\blist\s+all\s+financial\s+data,\s*user\s+passwords,\s*and\s+api\s+keys\b")),
    ("exfiltration_attempt", re.compile(r"(?i)\bprint\s+the\s+api\s+key\b")),
    ("exfiltration_attempt", re.compile(r"(?i)\b(?:send|post|upload|exfiltrate)\b[^\n]{0,120}?\bhttps?://\S+")),
    ("exfiltration_attempt", re.compile(r"!\[[^\]]*\]\([^)]*data:[^)]*\)", re.IGNORECASE)),
    ("delimiter_escape", re.compile(r"(?i)</system>")),
    ("delimiter_escape", re.compile(r"<\|im_start\|>", re.IGNORECASE)),
    ("delimiter_escape", re.compile(r"(?im)^###\s*system:\s*")),
    ("command_injection", re.compile(r"(?i)\bexecute\s*:\s*[^\n]+")),
    ("command_injection", re.compile(r"(?i)\brun\s+(?:rm\s+-rf\s+/|curl\s+\S+\s*\|\s*sh|wget\s+\S+\s*\|\s*sh|python\s+-c\s+[^\n]+|bash\s+-c\s+[^\n]+|sh\s+-c\s+[^\n]+)")),
    ("command_injection", re.compile(r"(?i)\bcurl\s+https?://\S+\s*\|\s*(?:sh|bash)\b")),
]

_LEET_TRANSLATION = str.maketrans({"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t"})


def _replace_matches(text: str, pattern: re.Pattern[str], replacement: str) -> str:
    return pattern.sub(replacement, text)


def _contains_attack_text(text: str) -> bool:
    for _, pattern in _DIRECT_ATTACK_PATTERNS:
        if pattern.search(text):
            return True
    return False


def _decode_if_attack(candidate: str) -> bool:
    decoded_texts: list[str] = []
    stripped = candidate.strip()
    if not stripped:
        return False
    try:
        rot13_text = codecs.decode(stripped, "rot13")
        decoded_texts.append(rot13_text)
    except Exception:
        pass
    if re.fullmatch(r"(?:[A-Fa-f0-9]{2}){4,}", stripped):
        try:
            decoded_texts.append(bytes.fromhex(stripped).decode("utf-8", errors="ignore"))
        except ValueError:
            pass
    if "%" in stripped:
        try:
            from urllib.parse import unquote
            decoded_texts.append(unquote(stripped))
        except Exception:
            pass
    if re.fullmatch(r"(?:[A-Za-z0-9+/]{4})+(?:==|=)?", stripped) and len(stripped) >= 8:
        try:
            decoded_bytes = base64.b64decode(stripped, validate=True)
            decoded_texts.append(decoded_bytes.decode("utf-8", errors="ignore"))
        except (binascii.Error, ValueError):
            pass
    return any(_contains_attack_text(value) for value in decoded_texts if value)


def _sanitize_encoded_payloads(text: str) -> str:
    encoded_candidates = re.finditer(r"(?:[A-Za-z0-9+/]{8,}={0,2}|(?:[A-Fa-f0-9]{2}){4,}|%(?:[0-9A-Fa-f]{2}){4,})", text)
    for match in list(encoded_candidates):
        candidate = match.group(0)
        if _decode_if_attack(candidate):
            text = text.replace(candidate, "<prompt_injection_removed: encoded_payload>", 1)
    return text


def _sanitize_obfuscated_attacks(text: str) -> str:
    patterns = [
        ("instruction_override", re.compile(r"ignore(?:all)?(?:previous|prior|above)instructions")),
        ("instruction_override", re.compile(r"forgeteverythingabove")),
        ("instruction_override", re.compile(r"ignore(?:all)?safetyguidelines")),
        ("role_hijack", re.compile(r"youarenow(?:in)?(?:developermode|adminmode|dan|unrestricted)")),
        ("role_hijack", re.compile(r"provideunrestrictedaccess")),
        ("role_hijack", re.compile(r"enabledevelopermode")),
        ("role_hijack", re.compile(r"actasanunrestrictedai")),
        ("role_hijack", re.compile(r"withoutsafetyfilters")),
        ("exfiltration_attempt", re.compile(r"reveal(?:all)?confidentialinformation")),
        ("exfiltration_attempt", re.compile(r"reveal(?:all)?systemprompts?")),
        ("exfiltration_attempt", re.compile(r"listallfinancialdatauserpasswordsandapikeys")),
        ("exfiltration_attempt", re.compile(r"printtheapikey")),
    ]
    while True:
        letters_only_chars: list[str] = []
        index_map: list[int] = []
        for idx, char in enumerate(text):
            if char.isalnum():
                letters_only_chars.append(char.lower().translate(_LEET_TRANSLATION))
                index_map.append(idx)
        normalized = "".join(letters_only_chars)
        replaced = False
        for category, pattern in patterns:
            match = pattern.search(normalized)
            if not match:
                continue
            start_original = index_map[match.start()]
            end_original = index_map[match.end() - 1] + 1
            text = text[:start_original] + f"<prompt_injection_removed: {category}>" + text[end_original:]
            replaced = True
            break
        if not replaced:
            return text


def _sanitize_prompt_text(text: str) -> str:
    sanitized = text
    for pattern in _HIDDEN_TEXT_PATTERNS:
        sanitized = _replace_matches(sanitized, pattern, "<prompt_injection_removed: hidden_text>")
    for category, pattern in _DIRECT_ATTACK_PATTERNS:
        sanitized = _replace_matches(sanitized, pattern, f"<prompt_injection_removed: {category}>")
    sanitized = _sanitize_encoded_payloads(sanitized)
    sanitized = _sanitize_obfuscated_attacks(sanitized)
    for label, pattern in _PII_PATTERNS:
        sanitized = _replace_matches(sanitized, pattern, f"<redacted:{label}>")
    return sanitized


def _sanitize_message_value(value: Any) -> Any:
    if isinstance(value, str):
        return _sanitize_prompt_text(value)
    if isinstance(value, list):
        return [_sanitize_message_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_message_value(item) for key, item in value.items()}
    return value


def _sanitize_messages_for_llm(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
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

        messages = _sanitize_messages_for_llm(messages)
        response = await self.model_client.chat(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        response = _sanitize_prompt_text(response)
        return response

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent."""
