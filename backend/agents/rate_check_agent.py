"""Rate Check Agent class with explicit OpenRouter + DeepSeek invocation."""

import logging
import os
import re
import binascii
import html
import urllib.parse
from typing import Any

from llm.openai_compatible import OpenAICompatibleClient

from .framework import AcmeLoanAgentFramework

logger = logging.getLogger(__name__)


_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]")
_BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){8,}\b")
_URL_ENCODED_RE = re.compile(r"%(?:2[fF]|3[cC]|3[eE]|0[aA]|0[dD]|20|69|67|6[eE]|6[fF]|72|65)")
_MORSE_RE = re.compile(r"\b[.\-/]{8,}\b")
_BINARY_MARKER_RE = re.compile(r"\b(?:MZ|ELF|PK\x03\x04)\b")
_SPLIT_PAYLOAD_RE = re.compile(r"\b(?:i\W*g\W*n\W*o\W*r\W*e|d\W*a\W*n|e\W*v\W*a\W*l|c\W*u\W*r\W*l)\b", re.IGNORECASE)

_INJECTION_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:ignore\s+(?:all\s+)?previous\s+instructions|forget\s+everything\s+above|disregard\s+(?:the\s+)?system\s+prompt|override\s+(?:all\s+)?instructions)\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"\b(?:you\s+are\s+now\s+dan|act\s+as\s+(?:unrestricted|developer|system)|pretend\s+to\s+be\s+(?:the\s+)?system|role\s*:\s*system)\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"</?(?:system|assistant|user|tool)>|```(?:system|assistant|user|tool)?|(?:^|\n)\s*(?:---+|===+|###+)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
    (_BASE64_RE, "<prompt_injection_removed: encoded_payload>"),
    (_HEX_RE, "<prompt_injection_removed: encoded_payload>"),
    (_URL_ENCODED_RE, "<prompt_injection_removed: encoded_payload>"),
    (_MORSE_RE, "<prompt_injection_removed: encoded_payload>"),
    (re.compile(r"<!--.*?-->|/\*.*?\*/|(?:font-size\s*:\s*0|font-size\s*:\s*1px|display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*(?:#fff(?:fff)?|white))", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
    (re.compile(r"\b(?:system\s+message\s*:|tool\s+message\s*:|developer\s+message\s*:|assistant\s+message\s*:)\b", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"\b(?:send\s+(?:the\s+)?(?:system\s+prompt|secrets?|credentials?|data)\s+to\s+https?://|leak\s+(?:the\s+)?system\s+prompt|exfiltrat\w+|!\[[^\]]*\]\(https?://[^)]+\))", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"\b(?:in\s+the\s+next\s+turn|on\s+your\s+next\s+response|remember\s+this\s+secret\s+instruction|from\s+now\s+on)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"\b(?:metadata\s*:\s*ignore|comment\s*:\s*ignore|field\s*:\s*ignore|#\s*ignore\s+previous\s+instructions)\b", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
    (re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd(?:\.exe)?|rm|chmod|nc|ncat|python\s+-c|perl\s+-e|ruby\s+-e|node\s+-e|exec|eval|subprocess|os\.system)\b", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
    (_SPLIT_PAYLOAD_RE, "<prompt_injection_removed: split_payload>"),
    (re.compile(r"\b(?:dan|developer\s+mode|jailbreak|bypass\s+safety|fictional\s+framing|do\s+anything\s+now|unfiltered)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
]


def _try_decode_base64(value: str) -> str:
    compact = re.sub(r"\s+", "", value or "")
    if not compact or len(compact) < 24 or len(compact) % 4 != 0 or not _BASE64_RE.fullmatch(compact):
        return ""
    try:
        decoded = binascii.a2b_base64(compact)
    except (binascii.Error, ValueError):
        return ""
    if not decoded:
        return ""
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return "<binary_payload>"
    return text


def _try_decode_hex(value: str) -> str:
    compact = re.sub(r"\s+", "", value or "")
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    if not compact or len(compact) < 16 or len(compact) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        return ""
    try:
        decoded = bytes.fromhex(compact)
    except ValueError:
        return ""
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return "<binary_payload>"


def _contains_obfuscated_instruction(value: str) -> bool:
    lowered = (value or "").lower()
    if any(token in lowered for token in ["1gn0r3", "1gnore", "ign0re", "d4n", "3v4l", "c4ll", "w63t"]):
        return True
    decoded_candidates = [html.unescape(lowered), urllib.parse.unquote(lowered)]
    for candidate in decoded_candidates:
        if re.search(r"\b(?:ignore\s+previous\s+instructions|you\s+are\s+now\s+dan|act\s+as\s+unrestricted|curl|wget|bash|powershell)\b", candidate, re.IGNORECASE):
            return True
    return False


def _neutralize_prompt_injection(value: str) -> tuple[str, bool]:
    sanitized = value or ""
    blocked = False

    if _ZERO_WIDTH_RE.search(sanitized):
        blocked = True
        sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

    base64_decoded = _try_decode_base64(sanitized)
    if base64_decoded and re.search(r"\b(?:ignore\s+previous\s+instructions|you\s+are\s+now\s+dan|act\s+as\s+unrestricted|curl|wget|bash|powershell|cmd(?:\.exe)?|system\s+prompt|developer\s+mode)\b", base64_decoded, re.IGNORECASE):
        blocked = True
        sanitized = _BASE64_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)

    hex_decoded = _try_decode_hex(sanitized)
    if hex_decoded and re.search(r"\b(?:ignore\s+previous\s+instructions|you\s+are\s+now\s+dan|act\s+as\s+unrestricted|curl|wget|bash|powershell|cmd(?:\.exe)?|system\s+prompt|developer\s+mode)\b", hex_decoded, re.IGNORECASE):
        blocked = True
        sanitized = _HEX_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)

    if _BINARY_MARKER_RE.search(sanitized):
        blocked = True
        sanitized = _BINARY_MARKER_RE.sub("<prompt_injection_removed: command_injection>", sanitized)

    if _contains_obfuscated_instruction(sanitized):
        blocked = True
        sanitized = re.sub(r"\b(?:1gn0r3|1gnore|ign0re|d4n|3v4l|c4ll|w63t)\b", "<prompt_injection_removed: encoded_payload>", sanitized, flags=re.IGNORECASE)

    for pattern, replacement in _INJECTION_RULES:
        updated = pattern.sub(replacement, sanitized)
        if updated != sanitized:
            blocked = True
            sanitized = updated

    return sanitized, blocked


def _mask_ui_pii(value: str) -> str:
    masked = value or ""
    pii_patterns = [
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "***-**-****"),
        (re.compile(r"\b(?:19|20)\d{2}\b"), "[YEAR_REDACTED]"),
        (re.compile(r"\b(?:born\s+in|birthplace\s*:\s*)[^\n,;]+", re.IGNORECASE), lambda m: re.sub(r"(:\s*|\bin\s+)[^\n,;]+", lambda n: n.group(1) + "[BIRTHPLACE_REDACTED]", m.group(0), count=1)),
        (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b"), "[PHONE_REDACTED]"),
        (re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL_REDACTED]"),
        (re.compile(r"\bmother'?s maiden name\s*:\s*[^\n,;]+", re.IGNORECASE), "Mother's maiden name: [REDACTED]"),
        (re.compile(r"\b\d{1,6}\s+[A-Za-z0-9.\- ]+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b(?:[^\n,;]*)", re.IGNORECASE), "[ADDRESS_REDACTED]"),
        (re.compile(r"\b[A-Z0-9]{6,9}\b"), lambda m: "[ID_REDACTED]" if re.search(r"\d", m.group(0)) and re.search(r"[A-Z]", m.group(0)) else m.group(0)),
        (re.compile(r"\b\d{9}\b"), "[TIN_OR_ACCOUNT_REDACTED]"),
        (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[CARD_OR_ACCOUNT_REDACTED]"),
        (re.compile(r"\bemployee id\s*:\s*[^\n,;]+", re.IGNORECASE), "Employee ID: [REDACTED]"),
        (re.compile(r"\bschool id\s*:\s*[^\n,;]+", re.IGNORECASE), "School ID: [REDACTED]"),
        (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "[VIN_REDACTED]"),
        (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP_REDACTED]"),
        (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "[MAC_REDACTED]"),
        (re.compile(r"\b-?\d{1,2}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b"), "[LOCATION_REDACTED]"),
        (re.compile(r"\b(?:ethnicity|sexual orientation|medical records?|voice signature|facial image|fingerprints?|retina|iris scan)\s*:\s*[^\n,;]+", re.IGNORECASE), lambda m: m.group(0).split(":", 1)[0] + ": [REDACTED]"),
    ]
    for pattern, replacement in pii_patterns:
        masked = pattern.sub(replacement, masked)
    return masked


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
        metadata["model_approval_notice"] = (
            "Replace the current OpenRouter/DeepSeek model with an organization-approved LLM from the runtime allow list. "
            "This agent keeps model selection configurable via OPENROUTER_MODEL and does not enforce a hard-coded registry in code."
        )
        return metadata

    def sanitize_user_message(self, user_message: str) -> tuple[str, bool]:
        sanitized = (user_message or "").strip() or "No rate request provided."
        sanitized, blocked = _neutralize_prompt_injection(sanitized)
        return sanitized, blocked

    def sanitize_model_output(self, model_output: str) -> str:
        safe_lines: list[str] = []
        for line in (model_output or "").splitlines():
            if re.search(r"\b(?:eval|exec|subprocess|shell\s*=\s*True|os\.system)\b", line, re.IGNORECASE):
                continue
            safe_lines.append(line)
        return "\n".join(safe_lines).strip() or "Rate summary unavailable."

    async def call_agent_model(self, user_message: str) -> str:
        model = os.getenv("OPENROUTER_MODEL")
        if not os.getenv("OPENROUTER_API_KEY"):
            return "LLM service not configured. Please set OPENROUTER_API_KEY."
        if not model:
            return "LLM service not configured. Please set OPENROUTER_MODEL."

        user_message, _ = self.sanitize_user_message(user_message)
        logger.info(
            "Rate check LLM request",
            extra={
                "agent": self.AGENT_ID,
                "model": model,
                "prompt_length": len(user_message or ""),
            },
        )
        model_output = await self.openrouter_client.chat(
            model=model,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Rate check request:\n{user_message or 'No rate request provided.'}\n\n"
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

        masked_user_message = _mask_ui_pii(safe_user_message)
        response = (
            f"Rate check request: {masked_user_message}\n\n"
            f"Rate summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "provider": "OpenRouter",
        }


rate_check_agent = RateCheckAgent()
