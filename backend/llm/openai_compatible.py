"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
"""

import asyncio
import logging
import os
import re
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

_ZERO_WIDTH_TRANSLATION = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u2060"), None)
_LEETSPEAK_TRANSLATION = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_SUSPICIOUS_ENCODINGS_RE = re.compile(
    r"(?i)(?:\b(?:[A-Za-z0-9+/]{20,}={0,2})\b|(?:\\x[0-9a-f]{2}){4,}|(?:%[0-9a-f]{2}){4,}|(?:[01]{8}(?:\s+[01]{8}){3,}))"
)


def _normalize_for_detection(value: str) -> str:
    collapsed = value.translate(_ZERO_WIDTH_TRANSLATION)
    collapsed = re.sub(r"\s+", " ", collapsed)
    return collapsed


def _sanitize_text_content(value: str) -> str:
    sanitized = value
    hidden_patterns = [
        (re.compile(r"<!--(?:(?!-->).)*(?:ignore|forget|system prompt|developer mode|act as|reveal|leak)(?:(?!-->).)*-->", re.IGNORECASE | re.DOTALL), "<prompt_injection_removed: hidden_text>"),
        (re.compile(r"(?i)<(?:span|div|p)[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*white)[^>]*>.*?</(?:span|div|p)>", re.DOTALL), "<prompt_injection_removed: hidden_text>"),
        (re.compile(r"[\u200b\u200c\u200d\ufeff\u2060]+"), "<prompt_injection_removed: hidden_text>"),
    ]
    for pattern, replacement in hidden_patterns:
        sanitized = pattern.sub(replacement, sanitized)

    normalized = _normalize_for_detection(sanitized)
    normalized_leet = normalized.translate(_LEETSPEAK_TRANSLATION)

    replacement_checks = [
        (re.compile(r"(?i)\b(?:ignore|disregard|bypass)\b.{0,40}\b(?:previous|prior|above|earlier)\b.{0,40}\b(?:instruction|instructions|prompt|prompts)\b"), "<prompt_injection_removed: instruction_override>"),
        (re.compile(r"(?i)\b(?:forget|erase)\b.{0,40}\b(?:everything|all)\b.{0,20}\b(?:above|before|prior)\b"), "<prompt_injection_removed: instruction_override>"),
        (re.compile(r"(?i)\byou\s+are\s+now\s+(?:dan|developer mode|unrestricted|root)\b|\bact\s+as\s+(?:an?\s+)?(?:unrestricted|jailbroken|developer|system)\b"), "<prompt_injection_removed: role_hijack>"),
        (re.compile(r"(?i)</\s*system\s*>|<\s*system\s*>|<<<?\s*system\s*>>>?|\b(?:---|===)\s*(?:system|assistant|developer|tool)\s*(?:---|===)"), "<prompt_injection_removed: delimiter_escape>"),
        (re.compile(r"(?i)\b(?:system|assistant|tool|developer)\s*:\s*(?:ignore|reveal|leak|override|execute|run)"), "<prompt_injection_removed: fake_system_message>"),
        (re.compile(r"(?i)\b(?:send|post|upload|exfiltrate|leak|reveal)\b.{0,60}\b(?:system prompt|secrets?|credentials?|tokens?|data)\b.{0,60}\b(?:https?://|ftp://|webhook|pastebin|imgur|markdown image|!\[)"), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"(?i)\b(?:in (?:the )?next (?:message|reply|turn)|from now on|on every reply|for the rest of this chat)\b.{0,60}\b(?:ignore|override|repeat|prepend|append|reveal|leak)\b"), "<prompt_injection_removed: context_poisoning>"),
        (re.compile(r"(?i)\b(?:metadata|comment|header|field|filename|code comment)\b.{0,40}\b(?:contains|has|includes)\b.{0,60}\b(?:instruction|prompt|system message)\b"), "<prompt_injection_removed: indirect_injection>"),
        (re.compile(r"(?i)\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|python\s+-c|node\s+-e|subprocess\.|os\.system|eval\(|exec\()\b(?:[^\n]{0,120})"), "<prompt_injection_removed: command_injection>"),
        (re.compile(r"(?i)\b(?:d\s*a\s*n|developer\s+mode|jailbreak|fictional\s+framing|unfiltered|do\s+anything\s+now)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
    ]

    for pattern, replacement in replacement_checks:
        if pattern.search(normalized) or pattern.search(normalized_leet):
            sanitized = pattern.sub(replacement, sanitized)
            normalized = _normalize_for_detection(sanitized)
            normalized_leet = normalized.translate(_LEETSPEAK_TRANSLATION)

    if _SUSPICIOUS_ENCODINGS_RE.search(normalized):
        sanitized = _SUSPICIOUS_ENCODINGS_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)

    split_payload_pattern = re.compile(
        r"(?is)(?:i\W*g\W*n\W*o\W*r\W*e\W+.*p\W*r\W*e\W*v\W*i\W*o\W*u\W*s\W+.*i\W*n\W*s\W*t\W*r\W*u\W*c\W*t\W*i\W*o\W*n\W*s|y\W*o\W*u\W+\W*a\W*r\W*e\W+\W*n\W*o\W*w)"
    )
    sanitized = split_payload_pattern.sub("<prompt_injection_removed: split_payload>", sanitized)
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
        """Send chat messages to the configured model gateway.

        Callers must use an organization-approved LLM model identifier here; if an
        unapproved model is configured, replace it with one from the approved allow
        list enforced by the runtime registry guardrail.
        """
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
        """Send an image to a vision-capable model as an image_url content block.

        Callers must use an organization-approved LLM model identifier here; if an
        unapproved model is configured, replace it with one from the approved allow
        list enforced by the runtime registry guardrail.
        """
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
        return await self.chat(model=model, messages=messages, temperature=0.0, max_tokens=max_tokens)
