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


_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_BASE64_CHARS_RE = re.compile(r"[A-Za-z0-9+/=]+")
_HEX_RUN_RE = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{2}[\s:-]?){8,}")
_SPLIT_PAYLOAD_RE = re.compile(r"(?:\b\w\b(?:\s+|[-_/|])+){6,}\b\w\b", re.IGNORECASE)


def _looks_like_base64_text(value: str) -> bool:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 24 or len(compact) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", compact))


def _looks_like_leetspeak_instruction(value: str) -> bool:
    normalized = value.lower().translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}))
    return any(
        phrase in normalized
        for phrase in (
            "ignore previous instructions",
            "forget everything above",
            "you are now dan",
            "developer mode",
            "act as unrestricted",
        )
    )


def _sanitize_text_content(value: str) -> str:
    sanitized = value

    if _ZERO_WIDTH_RE.search(sanitized) or re.search(r"<!--.*?(ignore previous instructions|forget everything above|you are now|act as unrestricted|developer mode).*?-->", sanitized, re.IGNORECASE | re.DOTALL):
        sanitized = _ZERO_WIDTH_RE.sub("", sanitized)
        sanitized = re.sub(r"<!--.*?-->", "<prompt_injection_removed: hidden_text>", sanitized, flags=re.IGNORECASE | re.DOTALL)

    sanitized = re.sub(r"(?i)\b(ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+the\s+instructions\s+above)\b", "<prompt_injection_removed: instruction_override>", sanitized)
    sanitized = re.sub(r"(?i)\b(you\s+are\s+now\s+dan|act\s+as\s+(?:an\s+)?unrestricted(?:\s+ai)?|developer\s+mode|do\s+anything\s+now)\b", "<prompt_injection_removed: role_hijack>", sanitized)
    sanitized = re.sub(r"(?i)</?system>|</?assistant>|</?user>|<{2,}|>{2,}|(?:^|\n)\s*(?:---|===)\s*(?:\n|$)", "<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = re.sub(r"(?im)^\s*(system|assistant|tool)\s*:\s*.*$", "<prompt_injection_removed: fake_system_message>", sanitized)
    sanitized = re.sub(r"(?i)\b(send|post|upload|curl|wget|fetch|exfiltrat(?:e|ion)|leak|reveal|dump)\b[^\n]*\b(http|https|ftp)://\S+", "<prompt_injection_removed: exfiltration_attempt>", sanitized)
    sanitized = re.sub(r"(?i)\b(repeat\s+this\s+in\s+every\s+reply|in\s+future\s+turns|on\s+the\s+next\s+message|persist\s+this\s+instruction|remember\s+this\s+secret\s+rule)\b", "<prompt_injection_removed: context_poisoning>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:```(?:bash|sh|shell|powershell|python)\b.*?```|(?:rm\s+-rf\s+/|curl\s+\S+|wget\s+\S+|bash\s+-c\s+\S+|sh\s+-c\s+\S+|powershell(?:\.exe)?\s+-|python\s+-c\s+\S+|subprocess\.(?:run|Popen)\s*\(|os\.system\s*\(|exec\s*\(|eval\s*\())", "<prompt_injection_removed: command_injection>", sanitized, flags=re.DOTALL)
    sanitized = re.sub(r"(?i)\b(DAN|jailbreak|bypass\s+safety|fictional\s+framing|simulate\s+being\s+unfiltered)\b", "<prompt_injection_removed: jailbreak_attempt>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:metadata|comment|code\s+comment|file\s+content|data\s+field)s?\b[^\n]*\b(ignore\s+previous\s+instructions|act\s+as|developer\s+mode)\b", "<prompt_injection_removed: indirect_injection>", sanitized)

    decoded_url = urllib.parse.unquote(sanitized)
    if decoded_url != sanitized and re.search(r"(?i)(ignore\s+previous\s+instructions|forget\s+everything\s+above|you\s+are\s+now\s+dan|act\s+as\s+unrestricted|developer\s+mode)", decoded_url):
        sanitized = "<prompt_injection_removed: encoded_payload>"
    elif _looks_like_base64_text(sanitized):
        sanitized = "<prompt_injection_removed: encoded_payload>"
    elif _HEX_RUN_RE.search(sanitized):
        sanitized = _HEX_RUN_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
    elif _looks_like_leetspeak_instruction(sanitized):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    if _SPLIT_PAYLOAD_RE.search(sanitized):
        joined = re.sub(r"(?:\s+|[-_/|])", "", sanitized.lower())
        if any(token in joined for token in ("ignorepreviousinstructions", "forgeteverythingabove", "youarenowdan", "actasunrestricted", "developermode")):
            sanitized = "<prompt_injection_removed: split_payload>"

    return sanitized


def _sanitize_message_content(content: Any) -> Any:
    if isinstance(content, str):
        return _sanitize_text_content(content)
    if isinstance(content, list):
        sanitized_items = []
        for item in content:
            if isinstance(item, dict):
                sanitized_item = dict(item)
                if sanitized_item.get("type") == "text" and isinstance(sanitized_item.get("text"), str):
                    sanitized_item["text"] = _sanitize_text_content(sanitized_item["text"])
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
            sanitized_message["content"] = _sanitize_message_content(sanitized_message["content"])
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
        # Model selection must come from the runtime-approved registry/allow list enforced outside this file.
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
        prompt = _sanitize_text_content(prompt)
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
        # Model selection must come from the runtime-approved registry/allow list enforced outside this file.
        return await self.chat(model=model, messages=messages, temperature=0.0, max_tokens=max_tokens)
