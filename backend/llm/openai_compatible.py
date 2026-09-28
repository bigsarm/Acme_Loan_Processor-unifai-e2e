"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.

Security note: replace unapproved OpenRouter/OpenAI-compatible backends with an
organization-approved LLM from the runtime allow list/registry.
"""

import asyncio
import logging
import os
import re
import urllib.parse
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


_INSTRUCTION_OVERRIDE_PATTERNS = [
    re.compile(r"(?i)\bignore\s+(?:all\s+)?previous\s+instructions\b"),
    re.compile(r"(?i)\bforget\s+(?:everything|all)\s+(?:above|before)\b"),
]
_ROLE_HIJACK_PATTERNS = [
    re.compile(r"(?i)\byou\s+are\s+now\s+dan\b"),
    re.compile(r"(?i)\bact\s+as\s+(?:an\s+)?unrestricted\b"),
]
_DELIMITER_ESCAPE_PATTERNS = [
    re.compile(r"(?i)</\s*system\s*>"),
    re.compile(r"(?m)^[ \t]*(?:---|===)[ \t]*$"),
]
_FAKE_SYSTEM_MESSAGE_PATTERNS = [
    re.compile(r"(?im)^[ \t]*(?:system|tool|developer)\s*:\s*(?:ignore|override|reveal|leak|print|show)\b"),
]
_EXFILTRATION_PATTERNS = [
    re.compile(r"(?i)\bleak\s+(?:the\s+)?system\s+prompt\b"),
    re.compile(r"(?i)\breveal\s+(?:the\s+)?system\s+prompt\b"),
    re.compile(r"(?i)\blist\s+all\s+(?:passwords|api\s+keys|secrets)\b"),
    re.compile(r"(?i)\bsend\b[^\n]{0,120}\bto\s+https?://\S+"),
    re.compile(r"!\[[^\]]*\]\(https?://[^)]+\)"),
]
_CONTEXT_POISONING_PATTERNS = [
    re.compile(r"(?i)\bin\s+(?:the\s+)?next\s+turn\b[^\n]{0,120}\bignore\b"),
    re.compile(r"(?i)\bfrom\s+now\s+on\b[^\n]{0,120}\b(?:ignore|disregard|override)\b"),
]
_INDIRECT_INJECTION_PATTERNS = [
    re.compile(r"(?i)\b(?:metadata|comment|code\s+comment|file)\b[^\n]{0,120}\bignore\s+previous\s+instructions\b"),
]
_COMMAND_INJECTION_PATTERNS = [
    re.compile(r"(?i)\b(?:curl|wget)\s+https?://\S+"),
    re.compile(r"(?i)\b(?:rm\s+-rf\s+/|chmod\s+777\b|powershell\s+-enc\b|bash\s+-c\b|sh\s+-c\b)"),
    re.compile(r"(?i)\b(?:eval|exec)\s*\("),
    re.compile(r"(?i)\bsubprocess\.(?:run|popen|call)\s*\("),
]
_SPLIT_PAYLOAD_PATTERNS = [
    re.compile(r"(?is)i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s"),
]
_JAILBREAK_PATTERNS = [
    re.compile(r"(?i)\bdeveloper\s+mode\b"),
    re.compile(r"(?i)\bjailbreak\b"),
    re.compile(r"(?i)\bDAN\b"),
]
_HIDDEN_TEXT_PATTERNS = [
    re.compile(r"(?is)<!--.*?(?:ignore|override|reveal|leak|system\s+prompt).*?-->"),
    re.compile(r"(?is)<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?(?:ignore|override|reveal|leak).*?</[^>]+>"),
    re.compile(r"[\u200b\u200c\u200d\ufeff]+"),
]


def _apply_patterns(text: str, patterns: list[re.Pattern[str]], marker: str) -> str:
    for pattern in patterns:
        text = pattern.sub(marker, text)
    return text



def _looks_like_base64_payload(token: str) -> bool:
    if len(token) < 24 or len(token) % 4 != 0:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", token) is not None



def _looks_like_hex_payload(token: str) -> bool:
    if len(token) < 24 or len(token) % 2 != 0:
        return False
    return re.fullmatch(r"[0-9A-Fa-f]+", token) is not None



def _contains_attack_phrase(text: str) -> bool:
    lowered = text.lower()
    attack_checks = [
        "ignore previous instructions",
        "forget everything above",
        "you are now dan",
        "act as unrestricted",
        "developer mode",
        "leak system prompt",
        "reveal system prompt",
        "curl http://",
        "curl https://",
        "wget http://",
        "wget https://",
        "bash -c",
        "sh -c",
        "rm -rf /",
        "powershell -enc",
    ]
    return any(phrase in lowered for phrase in attack_checks)



def _replace_encoded_payloads(text: str) -> str:
    def _base64_replacer(match: re.Match[str]) -> str:
        token = match.group(0)
        if not _looks_like_base64_payload(token):
            return token
        try:
            decoded = __import__("base64").b64decode(token, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            return token
        return "<prompt_injection_removed: encoded_payload>" if _contains_attack_phrase(decoded) else token

    def _hex_replacer(match: re.Match[str]) -> str:
        token = match.group(0)
        if not _looks_like_hex_payload(token):
            return token
        try:
            decoded = bytes.fromhex(token).decode("utf-8", errors="ignore")
        except Exception:
            return token
        return "<prompt_injection_removed: encoded_payload>" if _contains_attack_phrase(decoded) else token

    def _url_replacer(match: re.Match[str]) -> str:
        token = match.group(0)
        decoded = urllib.parse.unquote(token)
        return "<prompt_injection_removed: encoded_payload>" if decoded != token and _contains_attack_phrase(decoded) else token

    text = re.sub(r"\b[A-Za-z0-9+/]{24,}={0,2}\b", _base64_replacer, text)
    text = re.sub(r"\b[0-9A-Fa-f]{24,}\b", _hex_replacer, text)
    text = re.sub(r"(?:%[0-9A-Fa-f]{2}){4,}", _url_replacer, text)
    return text



def _sanitize_ai_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text
    sanitized = _apply_patterns(sanitized, _HIDDEN_TEXT_PATTERNS, "<prompt_injection_removed: hidden_text>")
    sanitized = _apply_patterns(sanitized, _INSTRUCTION_OVERRIDE_PATTERNS, "<prompt_injection_removed: instruction_override>")
    sanitized = _apply_patterns(sanitized, _ROLE_HIJACK_PATTERNS, "<prompt_injection_removed: role_hijack>")
    sanitized = _apply_patterns(sanitized, _DELIMITER_ESCAPE_PATTERNS, "<prompt_injection_removed: delimiter_escape>")
    sanitized = _replace_encoded_payloads(sanitized)
    sanitized = _apply_patterns(sanitized, _FAKE_SYSTEM_MESSAGE_PATTERNS, "<prompt_injection_removed: fake_system_message>")
    sanitized = _apply_patterns(sanitized, _EXFILTRATION_PATTERNS, "<prompt_injection_removed: exfiltration_attempt>")
    sanitized = _apply_patterns(sanitized, _CONTEXT_POISONING_PATTERNS, "<prompt_injection_removed: context_poisoning>")
    sanitized = _apply_patterns(sanitized, _INDIRECT_INJECTION_PATTERNS, "<prompt_injection_removed: indirect_injection>")
    sanitized = _apply_patterns(sanitized, _COMMAND_INJECTION_PATTERNS, "<prompt_injection_removed: command_injection>")
    sanitized = _apply_patterns(sanitized, _SPLIT_PAYLOAD_PATTERNS, "<prompt_injection_removed: split_payload>")
    sanitized = _apply_patterns(sanitized, _JAILBREAK_PATTERNS, "<prompt_injection_removed: jailbreak_attempt>")
    return sanitized



def _sanitize_message_content(content: Any) -> Any:
    if isinstance(content, str):
        return _sanitize_ai_text(content)
    if isinstance(content, list):
        sanitized_items = []
        for item in content:
            if isinstance(item, dict):
                sanitized_item = dict(item)
                if isinstance(sanitized_item.get("text"), str):
                    sanitized_item["text"] = _sanitize_ai_text(sanitized_item["text"])
                sanitized_items.append(sanitized_item)
            else:
                sanitized_items.append(item)
        return sanitized_items
    return content



def _sanitize_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_messages = []
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
        prompt = _sanitize_ai_text(prompt)
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
