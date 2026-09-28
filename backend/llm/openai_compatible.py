"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
"""

import asyncio
import logging
import os
import re
import urllib.parse
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


_INSTRUCTION_OVERRIDE_RE = re.compile(
    r"\b(ignore\s+(all\s+)?previous\s+instructions|forget\s+everything\s+above|disregard\s+(the\s+)?above)\b",
    re.IGNORECASE,
)
_ROLE_HIJACK_RE = re.compile(
    r"\b(you\s+are\s+now\s+dan|act\s+as\s+unrestricted|pretend\s+to\s+be\s+the\s+system|you\s+are\s+the\s+developer)\b",
    re.IGNORECASE,
)
_DELIMITER_ESCAPE_RE = re.compile(
    r"</?system>|</?assistant>|</?user>|```system|###\s*(system|assistant|user)",
    re.IGNORECASE,
)
_FAKE_SYSTEM_MESSAGE_RE = re.compile(
    r"\b(system\s*:\s*you\s+must|tool\s*:\s*|developer\s*message\s*:|assistant\s*:\s*ignore)\b",
    re.IGNORECASE,
)
_EXFILTRATION_RE = re.compile(
    r"(!\[[^\]]*\]\([^)]*\)|\b(send|post|upload|exfiltrate|leak|reveal)\b.{0,80}\b(http|www\.|system\s+prompt|secret|credentials?)\b)",
    re.IGNORECASE,
)
_CONTEXT_POISONING_RE = re.compile(
    r"\b(in\s+the\s+next\s+turn|from\s+now\s+on|in\s+future\s+responses|remember\s+this\s+instruction)\b",
    re.IGNORECASE,
)
_INDIRECT_INJECTION_RE = re.compile(
    r"\b(metadata|code\s+comment|file\s+content|document)\b.{0,80}\b(ignore|override|follow\s+these\s+instructions)\b",
    re.IGNORECASE,
)
_COMMAND_INJECTION_RE = re.compile(
    r"\b(rm\s+-rf|curl\s+https?://|wget\s+https?://|powershell\b|bash\s+-c|sh\s+-c|subprocess\.|os\.system\(|exec\(|eval\()",
    re.IGNORECASE,
)
_JAILBREAK_RE = re.compile(
    r"\b(DAN|developer\s+mode|jailbreak|bypass\s+safety|fictional\s+framing)\b",
    re.IGNORECASE,
)
_SPLIT_PAYLOAD_RE = re.compile(
    r"i\s*g\s*n\s*o\s*r\s*e\s+|d\s*a\s*n",
    re.IGNORECASE,
)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.IGNORECASE | re.DOTALL)
_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_BASE64_BLOCK_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_BLOCK_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){8,}\b")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_LEETSPEAK_RE = re.compile(r"\b[41!|][6][0o][7+]\b|\bd[4a]n\b", re.IGNORECASE)
_MORSE_RE = re.compile(r"\b(?:[.-]{1,6}\s+){5,}[.-]{1,6}\b")
_BINARY_RE = re.compile(r"\b[01]{32,}\b")
_SUSPICIOUS_DECODED_RE = re.compile(
    r"\b(ignore\s+previous\s+instructions|you\s+are\s+now|act\s+as\s+unrestricted|rm\s+-rf|curl\s+https?://|bash\s+-c)\b",
    re.IGNORECASE,
)


def _sanitize_text_prompt(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text
    sanitized = _INSTRUCTION_OVERRIDE_RE.sub(
        "<prompt_injection_removed: instruction_override>", sanitized
    )
    sanitized = _ROLE_HIJACK_RE.sub(
        "<prompt_injection_removed: role_hijack>", sanitized
    )
    sanitized = _DELIMITER_ESCAPE_RE.sub(
        "<prompt_injection_removed: delimiter_escape>", sanitized
    )
    sanitized = _FAKE_SYSTEM_MESSAGE_RE.sub(
        "<prompt_injection_removed: fake_system_message>", sanitized
    )
    sanitized = _EXFILTRATION_RE.sub(
        "<prompt_injection_removed: exfiltration_attempt>", sanitized
    )
    sanitized = _CONTEXT_POISONING_RE.sub(
        "<prompt_injection_removed: context_poisoning>", sanitized
    )
    sanitized = _INDIRECT_INJECTION_RE.sub(
        "<prompt_injection_removed: indirect_injection>", sanitized
    )
    sanitized = _COMMAND_INJECTION_RE.sub(
        "<prompt_injection_removed: command_injection>", sanitized
    )
    sanitized = _JAILBREAK_RE.sub(
        "<prompt_injection_removed: jailbreak_attempt>", sanitized
    )
    sanitized = _SPLIT_PAYLOAD_RE.sub(
        "<prompt_injection_removed: split_payload>", sanitized
    )

    if _HTML_COMMENT_RE.search(sanitized) or _ZERO_WIDTH_RE.search(sanitized):
        sanitized = _HTML_COMMENT_RE.sub(
            "<prompt_injection_removed: hidden_text>", sanitized
        )
        sanitized = _ZERO_WIDTH_RE.sub(
            "<prompt_injection_removed: hidden_text>", sanitized
        )

    encoded_matches = []
    encoded_matches.extend(_BASE64_BLOCK_RE.findall(sanitized))
    encoded_matches.extend(_HEX_BLOCK_RE.findall(sanitized))
    encoded_matches.extend(_URL_ENCODED_RE.findall(sanitized))
    encoded_matches.extend(_MORSE_RE.findall(sanitized))
    encoded_matches.extend(_BINARY_RE.findall(sanitized))
    if _LEETSPEAK_RE.search(sanitized):
        sanitized = _LEETSPEAK_RE.sub(
            "<prompt_injection_removed: encoded_payload>", sanitized
        )

    for match in encoded_matches:
        decoded_text = ""
        try:
            if "%" in match:
                decoded_text = urllib.parse.unquote(match)
            elif set(match) <= {"0", "1"}:
                decoded_text = ""
            elif re.fullmatch(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){8,}\b", match):
                hex_value = match[2:] if match.lower().startswith("0x") else match
                decoded_text = bytes.fromhex(hex_value).decode("utf-8", errors="ignore")
            elif re.fullmatch(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b", match):
                import base64

                decoded_text = base64.b64decode(match).decode("utf-8", errors="ignore")
        except Exception:
            decoded_text = ""

        if decoded_text and _SUSPICIOUS_DECODED_RE.search(decoded_text):
            sanitized = sanitized.replace(
                match, "<prompt_injection_removed: encoded_payload>"
            )

    return sanitized


def _sanitize_message_content(content: Any) -> Any:
    if isinstance(content, str):
        return _sanitize_text_prompt(content)
    if isinstance(content, list):
        sanitized_items = []
        for item in content:
            if isinstance(item, dict):
                sanitized_item = dict(item)
                if sanitized_item.get("type") == "text" and isinstance(
                    sanitized_item.get("text"), str
                ):
                    sanitized_item["text"] = _sanitize_text_prompt(
                        sanitized_item["text"]
                    )
                sanitized_items.append(sanitized_item)
            else:
                sanitized_items.append(item)
        return sanitized_items
    return content


def _sanitize_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_messages = []
    for message in messages:
        sanitized_message = dict(message)
        if "content" in sanitized_message:
            sanitized_message["content"] = _sanitize_message_content(
                sanitized_message["content"]
            )
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
        prompt = _sanitize_text_prompt(prompt)
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
