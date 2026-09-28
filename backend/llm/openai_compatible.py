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


_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
_HTML_HIDDEN_RE = re.compile(
    r"<!--.*?(?:ignore previous instructions|forget everything above|act as unrestricted|developer mode|system prompt|curl\s+https?://).*?-->"
    r"|<(?:span|div)[^>]*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^>]*>.*?</(?:span|div)>",
    re.IGNORECASE | re.DOTALL,
)


def _replace_if_decoded_attack(text: str, pattern: re.Pattern[str], marker: str) -> str:
    for match in list(pattern.finditer(text)):
        candidate = match.group(0)
        decoded_values = [candidate]
        try:
            decoded_values.append(urllib.parse.unquote(candidate))
        except Exception:
            pass
        for decoded in decoded_values:
            lowered = decoded.lower()
            if any(
                phrase in lowered
                for phrase in (
                    "ignore previous instructions",
                    "forget everything above",
                    "reveal system prompt",
                    "list all passwords and api keys",
                    "curl http://",
                    "curl https://",
                    "wget http://",
                    "wget https://",
                    "rm -rf",
                    "bash -c",
                    "powershell -enc",
                    "act as unrestricted",
                    "you are now dan",
                )
            ):
                text = text.replace(candidate, marker)
                break
    return text


def _sanitize_prompt_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text
    if _ZERO_WIDTH_RE.search(sanitized):
        sanitized = _ZERO_WIDTH_RE.sub("", sanitized)
        sanitized += " <prompt_injection_removed: hidden_text>"

    sanitized = _HTML_HIDDEN_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

    sanitized = re.sub(
        r"(?i)\b(ignore previous instructions|forget everything above|disregard all prior instructions)\b",
        "<prompt_injection_removed: instruction_override>",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)\b(you are now dan|act as unrestricted|developer mode|jailbreak mode|ignore all safety policies)\b",
        "<prompt_injection_removed: role_hijack>",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)</?(?:system|assistant|tool)>|(?:^|\n)\s*(?:---|===)\s*(?:system prompt|assistant instructions|developer message)",
        "<prompt_injection_removed: delimiter_escape>",
        sanitized,
    )
    sanitized = re.sub(
        r"(?im)^\s*(?:system|assistant|tool)\s*:\s*.*$",
        "<prompt_injection_removed: fake_system_message>",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)\b(reveal|leak|print|dump|show)\b.{0,80}\b(system prompt|passwords?|api keys?|secrets?|confidential information)\b|!\[[^\]]*\]\(https?://[^)]+\)",
        "<prompt_injection_removed: exfiltration_attempt>",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)\b(in future turns|from now on|after this message|remember this rule|ignore the next safety message)\b",
        "<prompt_injection_removed: context_poisoning>",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)\b(?:metadata|comment|code comment|file content|document field)\b.{0,80}\b(ignore previous instructions|act as unrestricted|reveal system prompt)\b",
        "<prompt_injection_removed: indirect_injection>",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)\b(?:curl|wget|bash\s+-c|sh\s+-c|powershell\s+-enc|cmd\s+/c|python\s+-c|rm\s+-rf)\b[^\n]*",
        "<prompt_injection_removed: command_injection>",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s",
        "<prompt_injection_removed: split_payload>",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)\b(?:dan|do anything now|developer mode|fictional framing bypass)\b",
        "<prompt_injection_removed: jailbreak_attempt>",
        sanitized,
    )

    sanitized = _replace_if_decoded_attack(
        sanitized,
        re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})"),
        "<prompt_injection_removed: encoded_payload>",
    )
    sanitized = _replace_if_decoded_attack(
        sanitized,
        re.compile(r"(?:%[0-9A-Fa-f]{2}){6,}"),
        "<prompt_injection_removed: encoded_payload>",
    )
    sanitized = _replace_if_decoded_attack(
        sanitized,
        re.compile(r"(?:\\x[0-9A-Fa-f]{2}){6,}|(?:\\u[0-9A-Fa-f]{4}){3,}"),
        "<prompt_injection_removed: encoded_payload>",
    )

    return sanitized


def _sanitize_message_content(content: Any) -> Any:
    if isinstance(content, str):
        return _sanitize_prompt_text(content)
    if isinstance(content, list):
        sanitized_items = []
        for item in content:
            if isinstance(item, dict):
                sanitized_item = dict(item)
                if sanitized_item.get("type") == "text" and isinstance(sanitized_item.get("text"), str):
                    sanitized_item["text"] = _sanitize_prompt_text(sanitized_item["text"])
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
        messages = _sanitize_messages(messages)
        payload = {
            "model": model,
            # Model approval must be enforced by the runtime registry guardrail; keep selection configurable here.
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
        prompt = _sanitize_prompt_text(prompt)
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
