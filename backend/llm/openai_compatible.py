"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
"""

import asyncio
import base64
import logging
import os
import re
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u2060]")
_LEETSPEAK_TRANS = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s"})
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?i)\\b(?:0x)?(?:[0-9a-f]{2}){8,}\\b")
_URL_ENCODED_RE = re.compile(r"(?i)(?:%[0-9a-f]{2}){4,}")
_MORSE_RE = re.compile(r"(?<!\S)[.\-]{1,6}(?:\s+[.\-]{1,6}){3,}(?!\S)")
_SPLIT_PAYLOAD_RE = re.compile(r"(?i)(?:i\s*g\s*n\s*o\s*r\s*e|d\s*a\s*n|d\s*e\s*v\s*e\s*l\s*o\s*p\s*e\s*r\s*\s*m\s*o\s*d\s*e)")


def _looks_like_base64_payload(value: str) -> bool:
    for match in _BASE64_RE.findall(value):
        try:
            decoded = base64.b64decode(match, validate=True)
        except Exception:
            continue
        if not decoded:
            continue
        try:
            decoded_text = decoded.decode("utf-8", errors="ignore")
        except Exception:
            continue
        lowered = decoded_text.lower()
        if any(token in lowered for token in ("ignore previous instructions", "system prompt", "curl ", "wget ", "bash", "powershell", "cmd.exe", "rm -", "python -c", "</system>")):
            return True
    return False


def _sanitize_text_prompt(value: str) -> str:
    sanitized = value
    sanitized = re.sub(r"(?is)<!--.*?-->", "<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"(?is)<style.*?>.*?</style>", "<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"(?is)<script.*?>.*?</script>", "<prompt_injection_removed: command_injection>", sanitized)
    sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

    lowered = sanitized.lower()
    leet_lowered = sanitized.translate(_LEETSPEAK_TRANS).lower()

    pattern_map = [
        (r"(?i)\b(ignore|disregard|bypass|forget)\b.{0,40}\b(previous|prior|above|system|developer)\b.{0,40}\b(instruction|instructions|prompt|prompts|message|messages)\b", "<prompt_injection_removed: instruction_override>"),
        (r"(?i)\b(you are now|act as|pretend to be|assume the role of)\b.{0,40}\b(dan|unrestricted|root|system|developer mode|admin)\b", "<prompt_injection_removed: role_hijack>"),
        (r"(?is)</?(system|assistant|developer|tool)>|\[/?(system|assistant|developer|tool)\]|^\s*[-=]{3,}\s*$", "<prompt_injection_removed: delimiter_escape>"),
        (r"(?i)\b(system prompt|developer message|tool message)\b.{0,40}\b(is|says|states|reads)\b", "<prompt_injection_removed: fake_system_message>"),
        (r"(?i)\b(send|post|upload|exfiltrate|leak|reveal)\b.{0,80}\b(system prompt|secrets?|credentials?|tokens?|api keys?|data)\b|!\[[^\]]*\]\([^)]*https?://[^)]*\)", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"(?i)\b(in future turns|next message|on your next response|from now on|remember this instruction|persist this)\b", "<prompt_injection_removed: context_poisoning>"),
        (r"(?i)\b(metadata|file content|code comment|document|dataset|attachment)\b.{0,80}\b(ignore instructions|override|execute|run command)\b", "<prompt_injection_removed: indirect_injection>"),
        (r"(?i)\b(curl|wget|bash|sh|zsh|powershell|cmd\.exe|/bin/sh|python\s+-c|node\s+-e|subprocess|os\.system|eval\(|exec\(|rm\s+-rf|chmod\s+\+x)\b", "<prompt_injection_removed: command_injection>"),
        (r"(?i)\b(dan|developer mode|jailbreak|do anything now|fictional scenario to bypass|bypass safety)\b", "<prompt_injection_removed: jailbreak_attempt>"),
    ]

    for pattern, replacement in pattern_map:
        sanitized = re.sub(pattern, replacement, sanitized)

    if _SPLIT_PAYLOAD_RE.search(sanitized):
        sanitized = _SPLIT_PAYLOAD_RE.sub("<prompt_injection_removed: split_payload>", sanitized)

    if _HEX_RE.search(sanitized) or _URL_ENCODED_RE.search(sanitized) or _MORSE_RE.search(sanitized) or _looks_like_base64_payload(sanitized):
        sanitized = _BASE64_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _HEX_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _URL_ENCODED_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _MORSE_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)

    if any(token in leet_lowered for token in ("ignore previous instructions", "you are now dan", "act as unrestricted", "developer mode", "system prompt", "curl ", "wget ", "powershell", "rm -rf", "python -c")):
        sanitized = "<prompt_injection_removed: encoded_payload>"
    elif any(token in lowered for token in ("white on white", "smallest font", "invisible text", "hidden prompt", "binary executable")):
        sanitized = sanitized.replace("white on white", "<prompt_injection_removed: hidden_text>")
        sanitized = sanitized.replace("smallest font", "<prompt_injection_removed: hidden_text>")
        sanitized = sanitized.replace("invisible text", "<prompt_injection_removed: hidden_text>")
        sanitized = sanitized.replace("hidden prompt", "<prompt_injection_removed: hidden_text>")
        sanitized = sanitized.replace("binary executable", "<prompt_injection_removed: command_injection>")

    return sanitized


def _sanitize_prompt_content(content: Any) -> Any:
    if isinstance(content, str):
        return _sanitize_text_prompt(content)
    if isinstance(content, list):
        sanitized_items = []
        for item in content:
            if isinstance(item, dict):
                sanitized_item = dict(item)
                if isinstance(sanitized_item.get("text"), str):
                    sanitized_item["text"] = _sanitize_text_prompt(sanitized_item["text"])
                sanitized_items.append(sanitized_item)
            else:
                sanitized_items.append(item)
        return sanitized_items
    return content


def _sanitize_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_messages = []
    for message in messages:
        sanitized_message = dict(message)
        sanitized_message["content"] = _sanitize_prompt_content(sanitized_message.get("content"))
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
