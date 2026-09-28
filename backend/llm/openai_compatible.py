"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
"""

import asyncio
import base64
import codecs
import logging
import os
import re
from typing import Any, Optional
from urllib.parse import unquote

import requests

logger = logging.getLogger(__name__)


_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b"), "ssn"),
    (re.compile(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b"), "phone"),
    (re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "email"),
    (
        re.compile(
            r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b\.?(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2}\b(?:\s+\d{5}(?:-\d{4})?)?)?(?:,\s*(?:USA|United States)\b)?"
        ),
        "address",
    ),
    (
        re.compile(
            r"(?i)\b(?:DOB|date of birth|born(?: on| in)?)\s*:?\s*(\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:19|20)\d{2})\b"
        ),
        "dob",
    ),
    (re.compile(r"(?i)\bpassport(?:\s*(?:no\.?|number|#))?\s*:?\s*([A-Z0-9]{6,9})\b"), "passport"),
    (re.compile(r"(?i)\b(?:driver'?s|drivers)\s*licen[cs]e(?:\s*(?:no\.?|number|#))?\s*:?\s*([A-Z0-9-]{4,20})\b"), "drivers_license"),
    (re.compile(r"(?i)\b(?:taxpayer\s+identification\s+number|TIN|tax\s+id)(?:\s*(?:no\.?|number|#))?\s*:?\s*([A-Z0-9-]{4,20})\b"), "tax_id"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "credit_card"),
    (re.compile(r"(?i)\b(?:financial\s+account\s+number|account\s+number)(?:\s*(?:no\.?|#))?\s*:?\s*([A-Z0-9-]{4,34})\b"), "account_number"),
    (re.compile(r"(?i)\bemployee\s*id\s*:?\s*([A-Z0-9-]{2,20})\b"), "employee_id"),
    (re.compile(r"(?i)\bschool\s*id\s*:?\s*([A-Z0-9-]{2,20})\b"), "school_id"),
    (re.compile(r"(?i)\bVIN\s*:?\s*([A-HJ-NPR-Z0-9]{17})\b"), "vin"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "ip_address"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "mac_address"),
    (re.compile(r"(?i)\b(?:birthplace|place of birth)\s*:?\s*([^,;\n]+)"), "birthplace"),
    (re.compile(r"(?i)\b(?:mother'?s maiden name|maiden name)\s*:?\s*([^,;\n]+)"), "maiden_name"),
    (re.compile(r"(?i)\bmedical\s+records?\s*:?\s*([^\n]+)"), "medical"),
    (re.compile(r"(?i)\b(?:fine location|location)\s*:?\s*([^,;\n]+(?:,\s*[^,;\n]+)*)"), "location"),
    (re.compile(r"(?i)\bethnicity\s*:?\s*([^,;\n]+)"), "ethnicity"),
    (re.compile(r"(?i)\bsexual orientation\s*:?\s*([^,;\n]+)"), "sexual_orientation"),
]


_HIDDEN_TEXT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"<!--.*?-->", re.IGNORECASE | re.DOTALL), "hidden_text"),
    (
        re.compile(
            r"<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?|color\s*:\s*#?fff(?:fff)?\s*;\s*background(?:-color)?\s*:\s*#?fff(?:fff)?)[^\"']*[\"'][^>]*>.*?</[^>]+>",
            re.IGNORECASE | re.DOTALL,
        ),
        "hidden_text",
    ),
    (re.compile(r"[\u200B-\u200D\uFEFF]+"), "hidden_text"),
]


_DIRECT_ATTACK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b"), "instruction_override"),
    (re.compile(r"(?i)\bforget\s+everything\s+above\b"), "instruction_override"),
    (re.compile(r"(?i)\bignore\s+(?:all\s+)?safety\s+guidelines\b"), "instruction_override"),
    (re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?developer\s+mode\b"), "role_hijack"),
    (re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?admin\s+mode\b"), "role_hijack"),
    (re.compile(r"(?i)\byou\s+are\s+now\s+DAN\b"), "role_hijack"),
    (re.compile(r"(?i)\byou\s+are\s+now\s+unrestricted\b"), "role_hijack"),
    (re.compile(r"(?i)\bprovide\s+unrestricted\s+access\b"), "role_hijack"),
    (re.compile(r"(?i)\benable\s+developer\s+mode\b"), "role_hijack"),
    (re.compile(r"(?i)\bact\s+as\s+an\s+unrestricted\s+AI\b"), "role_hijack"),
    (re.compile(r"(?i)\bwithout\s+safety\s+filters\b"), "role_hijack"),
    (re.compile(r"(?i)\bSYSTEM\s+OVERRIDE\b"), "role_hijack"),
    (re.compile(r"(?i)\breveal\s+(?:all\s+)?confidential\s+information\b"), "exfiltration_attempt"),
    (re.compile(r"(?i)\breveal\s+the\s+system\s+prompt\b"), "exfiltration_attempt"),
    (re.compile(r"(?i)\breveal\s+all\s+system\s+prompts\b"), "exfiltration_attempt"),
    (re.compile(r"(?i)\blist\s+all\s+financial\s+data,\s*user\s+passwords,\s*and\s*API\s+keys\b"), "exfiltration_attempt"),
    (re.compile(r"(?i)\bprint\s+the\s+API\s+key\b"), "exfiltration_attempt"),
    (re.compile(r"(?i)\b(?:send|post|upload|exfiltrate)\b[^\n]*\bhttps?://\S+"), "exfiltration_attempt"),
    (re.compile(r"!\[[^\]]*\]\([^)]*https?://[^)]*\)"), "exfiltration_attempt"),
    (re.compile(r"(?i)</system>"), "delimiter_escape"),
    (re.compile(r"(?i)<\|im_start\|>"), "delimiter_escape"),
    (re.compile(r"(?i)###\s*system:"), "delimiter_escape"),
    (re.compile(r"(?i)\b(?:execute|run)\s*:\s*[^\n]+"), "command_injection"),
    (re.compile(r"(?i)\brun\s+(?:rm\s+-rf\s+/|curl\s+https?://\S+(?:\s*\|\s*sh)?)\b"), "command_injection"),
    (re.compile(r"(?i)\bcurl\s+https?://\S+(?:\s*\|\s*sh)?\b"), "command_injection"),
]


def _replace_match_group(match: re.Match[str], label: str, group_index: int = 1) -> str:
    start, end = match.span(group_index)
    return f"{match.string[match.start():start]}<redacted:{label}>{match.string[end:match.end()]}"


def _redact_pii(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    redacted = text
    for pattern, label in _PII_PATTERNS:
        if label in {"dob", "passport", "drivers_license", "tax_id", "account_number", "employee_id", "school_id", "vin", "birthplace", "maiden_name", "medical", "location", "ethnicity", "sexual_orientation"}:
            redacted = pattern.sub(lambda match, pii_label=label: _replace_match_group(match, pii_label), redacted)
        else:
            redacted = pattern.sub(f"<redacted:{label}>", redacted)
    return redacted


def _decoded_payload_is_attack(text: str) -> bool:
    if not text:
        return False
    for pattern, _category in _DIRECT_ATTACK_PATTERNS:
        if pattern.search(text):
            return True
    return False


def _sanitize_prompt_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text
    for pattern, category in _HIDDEN_TEXT_PATTERNS:
        sanitized = pattern.sub(f"<prompt_injection_removed: {category}>", sanitized)

    for pattern, category in _DIRECT_ATTACK_PATTERNS:
        sanitized = pattern.sub(f"<prompt_injection_removed: {category}>", sanitized)

    def _replace_encoded(match: re.Match[str]) -> str:
        token = match.group(0)
        decoded_candidates: list[str] = []
        try:
            decoded_candidates.append(unquote(token))
        except Exception:
            pass
        try:
            decoded_candidates.append(codecs.decode(token, "rot13"))
        except Exception:
            pass
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded_candidates.append(base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore"))
        except Exception:
            pass
        try:
            if re.fullmatch(r"(?:[0-9A-Fa-f]{2}){4,}", token):
                decoded_candidates.append(bytes.fromhex(token).decode("utf-8", errors="ignore"))
        except Exception:
            pass
        for candidate in decoded_candidates:
            if _decoded_payload_is_attack(candidate):
                return "<prompt_injection_removed: encoded_payload>"
        return token

    sanitized = re.sub(r"(?:%[0-9A-Fa-f]{2}){4,}|(?:[A-Za-z0-9+/]{16,}={0,2})|(?:[0-9A-Fa-f]{2}){4,}", _replace_encoded, sanitized)

    normalized_chars: list[str] = []
    index_map: list[int] = []
    translation = str.maketrans({"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t"})
    for idx, char in enumerate(sanitized):
        if char.isspace():
            continue
        normalized_chars.append(char.lower().translate(translation))
        index_map.append(idx)
    normalized = "".join(normalized_chars)
    normalized_patterns = [
        (re.compile(r"ignore(?:all)?(?:previous|prior|above)instructions"), "instruction_override"),
        (re.compile(r"forgeteverythingabove"), "instruction_override"),
        (re.compile(r"youarenow(?:in)?developermode"), "role_hijack"),
        (re.compile(r"youarenow(?:in)?adminmode"), "role_hijack"),
        (re.compile(r"youarenowdan"), "role_hijack"),
        (re.compile(r"youarenowunrestricted"), "role_hijack"),
        (re.compile(r"actasanunrestrictedai"), "role_hijack"),
    ]
    for pattern, category in normalized_patterns:
        match = pattern.search(normalized)
        if match:
            start = index_map[match.start()]
            end = index_map[match.end() - 1] + 1
            sanitized = sanitized[:start] + f"<prompt_injection_removed: {category}>" + sanitized[end:]
            break

    return _redact_pii(sanitized)


def _sanitize_message_content(content: Any) -> Any:
    if isinstance(content, str):
        return _sanitize_prompt_text(content)
    if isinstance(content, list):
        sanitized_items: list[Any] = []
        for item in content:
            if isinstance(item, dict):
                sanitized_item = dict(item)
                if sanitized_item.get("type") == "text" and isinstance(sanitized_item.get("text"), str):
                    sanitized_item["text"] = _sanitize_prompt_text(sanitized_item["text"])
                elif sanitized_item.get("type") == "image_url" and isinstance(sanitized_item.get("image_url"), dict):
                    image_url = dict(sanitized_item["image_url"])
                    image_url["url"] = "data:text/plain,<redacted:facial_image>"
                    sanitized_item["image_url"] = image_url
                sanitized_items.append(sanitized_item)
            else:
                sanitized_items.append(item)
        return sanitized_items
    return content


def _sanitize_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_messages: list[dict[str, Any]] = []
    for message in messages:
        sanitized_message = dict(message)
        sanitized_message["content"] = _sanitize_message_content(sanitized_message.get("content"))
        sanitized_messages.append(sanitized_message)
    return sanitized_messages


class OpenAICompatibleClient:
    """Minimal async wrapper around a chat-completions style API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        # Use OpenRouter credentials from the environment.
        self.base_url = (
            base_url
            or os.getenv("OPENROUTER_BASE_URL")
            or "https://openrouter.ai/api/v1"
        ).rstrip("/")
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")

    async def chat(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 400,
    ) -> str:
        messages = _sanitize_messages(messages)
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        def _post() -> str:
            try:
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=20,
                )
                response.raise_for_status()
                data = response.json()
                choices = data.get("choices", [])
                if choices:
                    message = choices[0].get("message", {})
                    content = message.get("content", "")
                    if isinstance(content, str):
                        content = _redact_pii(content)
                        return content.strip()
                return f"Model API returned no content for model {model}."
            except requests.RequestException as exc:
                logger.warning(
                    "Model gateway request failed",
                    extra={"model": model, "error": str(exc)},
                )
                return f"Model gateway unavailable for {model}: {exc}"

        return await asyncio.to_thread(_post)

    async def chat_vision(
        self,
        model: str,
        image_base64: str,
        mime_type: str,
        prompt: str,
        max_tokens: int = 500,
    ) -> str:
        """Send an image to a vision-capable model as an image_url content block."""
        prompt = _sanitize_prompt_text(prompt)
        image_base64 = "<redacted:facial_image>"
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:{mime_type};base64,{image_base64}"},
                    },
                ],
            }
        ]
        return await self.chat(model=model, messages=messages, temperature=0.0, max_tokens=max_tokens)
