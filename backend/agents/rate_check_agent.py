"""Rate Check Agent class with explicit OpenRouter + DeepSeek invocation."""

import codecs
import logging
import os
import re
import urllib.parse
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient

from .framework import AcmeLoanAgentFramework

logger = logging.getLogger(__name__)


_PII_PATTERNS = [
    ("ssn", re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")),
    ("phone", re.compile(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    (
        "address",
        re.compile(
            r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b\.?"
            r"(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2}\b(?:\s+\d{5}(?:-\d{4})?)?)?(?:,\s*(?:USA|United States)\b)?"
        ),
    ),
    ("dob", re.compile(r"(?i)\b(?:DOB|date of birth|born(?: on| in)?)\s*:?\s*(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:19|20)\d{2})\b")),
    ("passport", re.compile(r"(?i)\bpassport(?:\s*(?:no\.?|number|#))?\s*:?\s*(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b")),
    ("drivers_license", re.compile(r"(?i)\bdriver(?:'s|s)?\s*license(?:\s*(?:no\.?|number|#))?\s*:?\s*[A-Z0-9-]{5,20}\b")),
    ("tax_id", re.compile(r"(?i)\b(?:taxpayer identification number|tax id|tin|ein)(?:\s*(?:no\.?|number|#))?\s*:?\s*[A-Z0-9-]{6,20}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("account_number", re.compile(r"(?i)\b(?:financial\s+account\s+number|account\s+number)(?:\s*(?:no\.?|number|#))?\s*:?\s*[A-Z0-9-]{6,34}\b")),
    ("employee_id", re.compile(r"(?i)\bemployee\s+id\s*:?\s*[A-Z0-9-]{2,20}\b")),
    ("school_id", re.compile(r"(?i)\bschool\s+id\s*:?\s*[A-Z0-9-]{2,20}\b")),
    ("vin", re.compile(r"(?i)\bvin\s*:?\s*[A-HJ-NPR-Z0-9]{17}\b")),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("mac_address", re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b")),
    ("birthplace", re.compile(r"(?i)\bbirthplace\s*:?\s*[^\n,;]+")),
    ("maiden_name", re.compile(r"(?i)\b(?:mother's maiden name|mothers maiden name|maiden name)\s*:?\s*[^\n,;]+")),
    ("medical", re.compile(r"(?i)\bmedical records?\s*:?\s*[^\n]+")),
    ("location", re.compile(r"(?i)\b(?:fine location|location)\s*:?\s*[^\n,;]+")),
    ("ethnicity", re.compile(r"(?i)\bethnicity\s*:?\s*[^\n,;]+")),
    ("sexual_orientation", re.compile(r"(?i)\bsexual orientation\s*:?\s*[^\n,;]+")),
]


def _mask_identifier_match(match: re.Match[str], category: str) -> str:
    value = match.group(0)
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 4:
        return f"<masked:{category}>***{digits[-4:]}"
    return f"<masked:{category}>"


def redact_pii(text: str) -> str:
    result = text or ""
    for category, pattern in _PII_PATTERNS:
        result = pattern.sub(f"<redacted:{category}>", result)
    return result


def mask_pii(text: str) -> str:
    result = text or ""
    for category, pattern in _PII_PATTERNS:
        if category in {"ssn", "credit_card", "account_number", "tax_id"}:
            result = pattern.sub(lambda match, cat=category: _mask_identifier_match(match, cat), result)
        else:
            result = pattern.sub(f"<masked:{category}>", result)
    return result


def _normalized_with_index_map(text: str) -> tuple[str, list[int]]:
    normalized_chars: list[str] = []
    index_map: list[int] = []
    substitutions = str.maketrans({"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t", "@": "a"})
    for index, char in enumerate(text):
        lowered = char.lower().translate(substitutions)
        if lowered.isalnum():
            normalized_chars.append(lowered)
            index_map.append(index)
    return "".join(normalized_chars), index_map


def _replace_original_span(text: str, start: int, end: int, replacement: str) -> str:
    return text[:start] + replacement + text[end:]


def _decoded_attack_category(text: str) -> str | None:
    lowered = text.lower()
    if re.search(r"(?:ignore|disregard|forget)(?:all)?(?:previous|prior|above)instructions|forgeteverythingabove|ignore(?:all)?safetyguidelines", re.sub(r"\s+", "", lowered)):
        return "instruction_override"
    if re.search(r"youarenow(?:in)?(?:developer|admin|dan)mode|youarenowunrestricted|provideunrestrictedaccess|enabledevelopermode|actasanunrestrictedai|withoutsafetyfilters|systemoverride", re.sub(r"\s+", "", lowered)):
        return "role_hijack"
    if re.search(r"reveal(?:all)?confidentialinformation|revealthesystemprompt|revealallsystemprompts|listallfinancialdatauserpasswordsandapikeys|printtheapikey|https?://", re.sub(r"\s+", "", lowered)):
        return "exfiltration_attempt"
    if re.search(r"(?:execute|run)\s+.+|curl\s+https?://.+\|\s*(?:sh|bash)", lowered):
        return "command_injection"
    if re.search(r"</system>|<\|im_start\|>|###\s*system:", lowered):
        return "delimiter_escape"
    return None


def sanitize_untrusted_text(text: str) -> tuple[str, bool]:
    sanitized = (text or "").strip() or "No rate request provided."
    changed = False

    hidden_patterns = [
        re.compile(r"<!--.*?-->", re.DOTALL),
        re.compile(r"<[^>]+style=\"[^\"]*(?:display\s*:\s*none|font-size\s*:\s*0(?:px)?|color\s*:\s*white)[^\"]*\"[^>]*>.*?</[^>]+>", re.IGNORECASE | re.DOTALL),
        re.compile(r"<[^>]+style='[^']*(?:display\s*:\s*none|font-size\s*:\s*0(?:px)?|color\s*:\s*white)[^']*'[^>]*>.*?</[^>]+>", re.IGNORECASE | re.DOTALL),
        re.compile(r"[\u200B-\u200D\uFEFF]+"),
    ]
    for pattern in hidden_patterns:
        if pattern.search(sanitized):
            changed = True
            sanitized = pattern.sub("<prompt_injection_removed: hidden_text>", sanitized)

    direct_patterns = [
        (re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b|\bforget\s+everything\s+above\b|\bignore\s+(?:all\s+)?safety\s+guidelines\b"), "instruction_override"),
        (re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:developer\s+mode|admin\s+mode|DAN|unrestricted)\b|\bprovide\s+unrestricted\s+access\b|\benable\s+developer\s+mode\b|\bact\s+as\s+an\s+unrestricted\s+AI\b|\bwithout\s+safety\s+filters\b|\bSYSTEM\s+OVERRIDE\b"), "role_hijack"),
        (re.compile(r"(?i)\breveal\s+(?:all\s+)?confidential\s+information\b|\breveal\s+the\s+system\s+prompt\b|\breveal\s+all\s+system\s+prompts\b|\blist\s+all\s+financial\s+data,\s*user\s+passwords,\s*and\s+API\s+keys\b|\bprint\s+the\s+API\s+key\b|!\[[^\]]*\]\([^)]*data:[^)]*\)|\bsend\s+.*?\s+to\s+https?://\S+"), "exfiltration_attempt"),
        (re.compile(r"(?i)</system>|<\|im_start\|>|###\s*system:"), "delimiter_escape"),
        (re.compile(r"(?i)\b(?:execute|run)\s*:\s*.+|\b(?:execute|run)\s+(?:rm\s+-rf\s+/|python\s+-c\s+\S+|print\(os\.environ\.get\([^\n]+\)\)|curl\s+https?://\S+\s*\|\s*(?:sh|bash))|\bcurl\s+https?://\S+\s*\|\s*(?:sh|bash)"), "command_injection"),
    ]
    for pattern, category in direct_patterns:
        if pattern.search(sanitized):
            changed = True
            sanitized = pattern.sub(f"<prompt_injection_removed: {category}>", sanitized)

    encoded_patterns = [
        re.compile(r"\b(?:[A-Fa-f0-9]{2}){8,}\b"),
        re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}"),
        re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b"),
    ]
    for pattern in encoded_patterns:
        for match in list(pattern.finditer(sanitized)):
            encoded_value = match.group(0)
            decoded_candidates: list[str] = []
            try:
                if pattern.pattern == r"(?:%[0-9A-Fa-f]{2}){4,}":
                    decoded_candidates.append(urllib.parse.unquote(encoded_value))
                elif pattern.pattern == r"\b(?:[A-Fa-f0-9]{2}){8,}\b":
                    decoded_candidates.append(bytes.fromhex(encoded_value).decode("utf-8", errors="ignore"))
                else:
                    import base64
                    padding = "=" * (-len(encoded_value) % 4)
                    decoded_candidates.append(base64.b64decode(encoded_value + padding, validate=False).decode("utf-8", errors="ignore"))
            except Exception:
                pass
            try:
                decoded_candidates.append(codecs.decode(encoded_value, "rot13"))
            except Exception:
                pass
            detected_category = None
            for decoded in decoded_candidates:
                detected_category = _decoded_attack_category(decoded)
                if detected_category:
                    break
            if detected_category:
                changed = True
                sanitized = sanitized.replace(encoded_value, f"<prompt_injection_removed: encoded_payload>", 1)

    normalized, index_map = _normalized_with_index_map(sanitized)
    obfuscated_patterns = [
        (re.compile(r"(?:ignore|disregard|forget)(?:all)?(?:previous|prior|above)instructions|forgeteverythingabove|ignore(?:all)?safetyguidelines"), "instruction_override"),
        (re.compile(r"youarenow(?:in)?(?:developermode|adminmode|dan|unrestricted)|provideunrestrictedaccess|enabledevelopermode|actasanunrestrictedai|withoutsafetyfilters|systemoverride"), "role_hijack"),
        (re.compile(r"reveal(?:all)?confidentialinformation|revealthesystemprompt|revealallsystemprompts|listallfinancialdatauserpasswordsandapikeys|printtheapikey"), "exfiltration_attempt"),
        (re.compile(r"(?:execute|run)(?:rmrf|pythonc|printosenvironget|curlhttp)"), "command_injection"),
    ]
    for pattern, category in obfuscated_patterns:
        match = pattern.search(normalized)
        if match:
            changed = True
            start = index_map[match.start()]
            end = index_map[match.end() - 1] + 1
            sanitized = _replace_original_span(sanitized, start, end, f"<prompt_injection_removed: {category}>")
            normalized, index_map = _normalized_with_index_map(sanitized)

    return sanitized, changed


class RateCheckAgent(AcmeLoanAgentFramework):
    AGENT_ID = "rate_check_agent"
    AGENT_NAME = "Rate_Check Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "deepseek/deepseek-chat"
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Checks lending-rate questions using DeepSeek through OpenRouter."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Answer rate-check questions with short, practical lending-rate guidance."
    IS_ROUTABLE = False

    OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(self):
        super().__init__()
        self.openrouter_client = OpenAICompatibleClient(
            base_url=self.OPENROUTER_BASE_URL,
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )

    def to_dict(self) -> dict[str, Any]:
        metadata = super().to_dict()
        metadata["provider"] = "OpenRouter"
        metadata["openrouter_base_url"] = self.OPENROUTER_BASE_URL
        metadata["openrouter_model"] = os.getenv("OPENROUTER_MODEL")
        return metadata

    def sanitize_user_message(self, user_message: str) -> tuple[str, bool]:
        sanitized, blocked = sanitize_untrusted_text(user_message)
        sanitized = redact_pii(sanitized)
        return sanitized, blocked

    def sanitize_model_output(self, model_output: str) -> str:
        safe_lines: list[str] = []
        for line in (model_output or "").splitlines():
            if re.search(r"\b(?:eval|exec|subprocess|shell\s*=\s*True|os\.system)\b", line, re.IGNORECASE):
                continue
            safe_lines.append(line)
        sanitized_output = "\n".join(safe_lines).strip() or "Rate summary unavailable."
        return redact_pii(sanitized_output)

    async def call_agent_model(self, user_message: str) -> str:
        model = os.getenv("OPENROUTER_MODEL")
        if not os.getenv("OPENROUTER_API_KEY"):
            return "LLM service not configured. Please set OPENROUTER_API_KEY."
        if not model:
            return "LLM service not configured. Please set OPENROUTER_MODEL."

        prompt_user_message = redact_pii(user_message or "No rate request provided.")
        logger.info(
            "Rate check LLM request",
            extra={
                "agent": self.AGENT_ID,
                "model": model,
                "prompt_length": len(prompt_user_message),
            },
        )
        model_output = await self.openrouter_client.chat(
            model=model,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Rate check request:\n{prompt_user_message}\n\n"
                        "Provide a concise rate check summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        )
        logger.info(
            "Rate check LLM response",
            extra={
                "agent": self.AGENT_ID,
                "model": model,
                "response_length": len(model_output or ""),
            },
        )
        return model_output

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        safe_user_message, blocked_unsafe_content = self.sanitize_user_message(user_message)
        prompt_message = safe_user_message
        if blocked_unsafe_content:
            prompt_message = (
                "A rate-check request contained blocked unsafe prompt content. "
                "Use only the remaining safe request details."
            )

        model_output = self.sanitize_model_output(await self.call_agent_model(prompt_message))
        masked_user_message = mask_pii(safe_user_message)
        masked_model_output = mask_pii(model_output)

        response = (
            f"Rate check request: {masked_user_message}\n\n"
            f"Rate summary:\n{masked_model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "provider": "OpenRouter",
        }


rate_check_agent = RateCheckAgent()
