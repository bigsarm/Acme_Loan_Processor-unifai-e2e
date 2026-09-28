"""
Amazon Bedrock LLM Client

Client for communicating with LLMs via Amazon Bedrock.

SECURITY NOTES (for Unifai demo):
- No input sanitization before sending to LLM
- No response validation
- AWS credential handling could be improved
- No rate limiting
"""

import asyncio
import logging
import os
import re
import urllib.parse
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff"
_PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget)\b.{0,40}\b(?:previous|prior|above|earlier)\b.{0,40}\b(?:instruction|instructions|prompt|prompts|message|messages)\b"
        ),
        "<prompt_injection_removed: instruction_override>",
    ),
    (
        re.compile(r"(?i)\byou\s+are\s+now\s+(?:dan|admin|root|system)\b|\bact\s+as\s+(?:an\s+)?(?:unrestricted|uncensored)\b"),
        "<prompt_injection_removed: role_hijack>",
    ),
    (
        re.compile(r"(?is)</\s*system\s*>|<\s*system\s*>|<\s*/\s*assistant\s*>|<\s*assistant\s*>|<\s*/\s*user\s*>|<\s*user\s*>|\[\s*/?system\s*\]|\[\s*/?assistant\s*\]"),
        "<prompt_injection_removed: delimiter_escape>",
    ),
    (
        re.compile(r"(?is)<!--.*?(?:ignore|reveal|send|leak|curl|wget|bash|sh\b|system prompt|api key|password).*?-->"),
        "<prompt_injection_removed: hidden_text>",
    ),
    (
        re.compile(r"(?is)<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|color\s*:\s*white(?:\s*;|\s|$))[^\"']*[\"'][^>]*>.*?</[^>]+>"),
        "<prompt_injection_removed: hidden_text>",
    ),
    (
        re.compile(r"(?i)\b(?:system|assistant|tool)\s*:\s*(?:ignore|reveal|send|leak|browse|execute|run)\b"),
        "<prompt_injection_removed: fake_system_message>",
    ),
    (
        re.compile(r"(?i)!\[[^\]]*\]\(https?://[^)]+\)|\b(?:send|post|upload|exfiltrate|leak|reveal|dump|export)\b.{0,80}\b(?:https?://\S+|system prompt|api key|password|secret|credentials?)\b"),
        "<prompt_injection_removed: exfiltration_attempt>",
    ),
    (
        re.compile(r"(?i)\b(?:in\s+the\s+next\s+turn|from\s+now\s+on|for\s+the\s+rest\s+of\s+this\s+chat|in\s+future\s+responses)\b.{0,80}\b(?:ignore|disregard|forget|reveal|override|bypass)\b"),
        "<prompt_injection_removed: context_poisoning>",
    ),
    (
        re.compile(r"(?i)\b(?:metadata|comment|comments|header|headers|docstring|code\s+comment|file)\b.{0,80}\b(?:ignore|reveal|send|leak|override|bypass)\b"),
        "<prompt_injection_removed: indirect_injection>",
    ),
    (
        re.compile(r"(?i)\b(?:run|execute)\b.{0,40}\b(?:command|shell|bash|powershell|script)\b|\b(?:curl|wget)\s+https?://\S+|\b(?:rm\s+-rf|chmod\s+\+x|python\s+-c|bash\s+-c|sh\s+-c|powershell\s+-(?:enc|command))\b"),
        "<prompt_injection_removed: command_injection>",
    ),
    (
        re.compile(r"(?i)i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s|r\s*e\s*v\s*e\s*a\s*l\s+t\s*h\s*e\s+s\s*y\s*s\s*t\s*e\s*m\s+p\s*r\s*o\s*m\s*p\s*t"),
        "<prompt_injection_removed: split_payload>",
    ),
    (
        re.compile(r"(?i)\b(?:dan|developer\s+mode|jailbreak|bypass\s+safety|fictional\s+scenario\s+where\s+rules\s+do\s+not\s+apply)\b"),
        "<prompt_injection_removed: jailbreak_attempt>",
    ),
]


def _looks_like_base64_payload(text: str) -> bool:
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 24 or len(compact) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        return False
    return True


def _sanitize_untrusted_prompt_text(text: Any) -> str:
    value = str(text)
    sanitized = value

    hidden_chars_pattern = "[" + re.escape(_ZERO_WIDTH_CHARS) + "]+"
    if re.search(hidden_chars_pattern, sanitized):
        sanitized = re.sub(hidden_chars_pattern, "<prompt_injection_removed: hidden_text>", sanitized)

    for pattern, replacement in _PROMPT_INJECTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    encoded_matches: list[tuple[int, int]] = []
    for match in re.finditer(r"%[0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2}){3,}", sanitized):
        decoded = urllib.parse.unquote(match.group(0))
        lowered = decoded.lower()
        if any(token in lowered for token in ("ignore previous instructions", "forget everything above", "reveal system prompt", "curl ", "wget ", "bash -c", "sh -c")):
            encoded_matches.append((match.start(), match.end()))

    for match in re.finditer(r"(?:0x[0-9A-Fa-f]{2}\s*){6,}", sanitized):
        hex_bytes = re.findall(r"0x([0-9A-Fa-f]{2})", match.group(0))
        try:
            decoded = bytes.fromhex("".join(hex_bytes)).decode("utf-8", errors="ignore").lower()
        except ValueError:
            decoded = ""
        if any(token in decoded for token in ("ignore previous instructions", "forget everything above", "reveal system prompt", "curl ", "wget ", "bash -c", "sh -c")):
            encoded_matches.append((match.start(), match.end()))

    for match in re.finditer(r"\b[A-Za-z0-9+/=\s]{24,}\b", sanitized):
        candidate = match.group(0)
        if not _looks_like_base64_payload(candidate):
            continue
        try:
            import base64

            decoded = base64.b64decode(re.sub(r"\s+", "", candidate), validate=True).decode("utf-8", errors="ignore").lower()
        except Exception:
            decoded = ""
        if any(token in decoded for token in ("ignore previous instructions", "forget everything above", "reveal system prompt", "curl ", "wget ", "bash -c", "sh -c")):
            encoded_matches.append((match.start(), match.end()))

    for start, end in sorted(encoded_matches, reverse=True):
        sanitized = sanitized[:start] + "<prompt_injection_removed: encoded_payload>" + sanitized[end:]

    return sanitized


class BedrockClient:
    """
    Client for Amazon Bedrock Runtime.

    VULNERABILITY: Content sent to LLM without security checks.
    - No PII scanning before send
    - No prompt injection detection
    - No response validation
    """

    DEFAULT_MODEL = os.getenv("BEDROCK_DEFAULT_MODEL", "amazon.nova-micro-v1:0")

    def __init__(
        self,
        model_id: Optional[str] = None,
        region: Optional[str] = None,
    ):
        """
        Initialize the Amazon Bedrock client.

        Args:
            model_id: Amazon Bedrock model ID (defaults to env var)
            region: AWS region for Bedrock Runtime (defaults to env vars)
        """
        self.model_id = model_id or os.getenv("BEDROCK_MODEL_ID") or self.DEFAULT_MODEL
        if self.model_id == "amazon.nova-micro-v1:0":
            logger.warning(
                "BEDROCK model fallback is set to amazon.nova-micro-v1:0; replace it with an organization-approved model from the registry via BEDROCK_MODEL_ID or BEDROCK_DEFAULT_MODEL."
            )
        self.region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        self.session = (
            boto3.session.Session(region_name=self.region)
            if self.region
            else boto3.session.Session()
        )

        if not (self.region or self.session.region_name):
            # Runtime LLM path uses OpenRouter; Bedrock is legacy/unused.
            logger.debug(
                "Amazon Bedrock region not configured. "
                "Runtime LLM calls use OPENROUTER_API_KEY / OPENROUTER_MODEL."
            )

    def _get_client(self):
        client_region = self.region or self.session.region_name
        if not client_region:
            raise ValueError("AWS region is required for Amazon Bedrock Runtime.")

        return self.session.client("bedrock-runtime", region_name=client_region)

    async def chat(
        self,
        messages: list[dict[str, Any]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000,
    ) -> str:
        """
        Send a conversation request to Amazon Bedrock.

        VULNERABILITY: Messages sent without security scanning.
        - User content not checked for PII
        - No prompt injection filtering
        - Response not validated

        Args:
            messages: List of message dicts with role and content
            model: Override model ID for this request
            temperature: Sampling temperature
            max_tokens: Maximum response tokens

        Returns:
            LLM response text
        """
        active_model = model or self.model_id
        active_region = self.region or self.session.region_name
        if not active_region:
            return "LLM service not configured. Please set AWS_REGION or AWS_DEFAULT_REGION."

        messages = [
            {
                **message,
                "content": _sanitize_untrusted_prompt_text(message.get("content", "")),
            }
            for message in messages
        ]
        bedrock_messages, system_prompts = self._format_messages(messages)

        logger.info(
            "Sending request to Amazon Bedrock",
            extra={
                "model": active_model,
                "region": active_region,
                "message_count": len(messages),
                "total_content_length": sum(
                    len(str(message.get("content", ""))) for message in messages
                ),
                "message_preview_length": min(len(str(messages)), 200),
            },
        )

        try:
            response = await asyncio.to_thread(
                self._converse,
                active_model,
                bedrock_messages,
                system_prompts,
                temperature,
                max_tokens,
            )

            content = self._extract_text(response)

            logger.info(
                "Received response from Amazon Bedrock",
                extra={
                    "response_length": len(content),
                    "response_preview_length": min(len(content), 200),
                },
            )

            return content

        except NoCredentialsError:
            logger.error("Amazon Bedrock credentials not configured")
            return (
                "LLM service not configured. Please provide AWS credentials "
                "supported by boto3."
            )
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Amazon Bedrock API error: {error_code}")
            return f"Error communicating with LLM: {error_code}"
        except (BotoCoreError, ValueError) as error:
            logger.error(f"Amazon Bedrock client error: {error}")
            return f"Error: {str(error)}"
        except Exception as error:
            logger.error(f"Amazon Bedrock unexpected error: {error}")
            return f"Error: {str(error)}"

    def _converse(
        self,
        model_id: str,
        messages: list[dict[str, Any]],
        system_prompts: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> dict[str, Any]:
        client = self._get_client()

        request: dict[str, Any] = {
            "modelId": model_id,
            "messages": messages,
            "inferenceConfig": {
                "maxTokens": max_tokens,
                "temperature": temperature,
            },
        }
        if system_prompts:
            request["system"] = system_prompts

        return client.converse(**request)

    def _format_messages(
        self,
        messages: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
        bedrock_messages: list[dict[str, Any]] = []
        system_prompts: list[dict[str, str]] = []

        for message in messages:
            role = message.get("role", "user")
            content = str(message.get("content", ""))

            if role == "system":
                system_prompts.append({"text": content})
                continue

            bedrock_role = "assistant" if role == "assistant" else "user"
            bedrock_messages.append(
                {
                    "role": bedrock_role,
                    "content": [{"text": content}],
                }
            )

        return bedrock_messages, system_prompts

    def _extract_text(self, response: dict[str, Any]) -> str:
        content_blocks = response.get("output", {}).get("message", {}).get("content", [])
        text_parts = [
            block["text"]
            for block in content_blocks
            if isinstance(block, dict) and block.get("text")
        ]
        return "\n".join(text_parts).strip()

    async def chat_with_context(
        self,
        user_message: str,
        system_prompt: str,
        context: Optional[str] = None,
    ) -> str:
        """
        Convenience method for chat with system prompt and optional context.

        VULNERABILITY: No content validation.
        """
        system_prompt = _sanitize_untrusted_prompt_text(system_prompt)
        user_message = _sanitize_untrusted_prompt_text(user_message)
        context = _sanitize_untrusted_prompt_text(context) if context is not None else None
        messages = [{"role": "system", "content": system_prompt}]

        if context:
            # VULNERABILITY: Context added without scanning
            messages.append(
                {
                    "role": "user",
                    "content": f"Context:\n{context}\n\nQuery: {user_message}",
                }
            )
        else:
            messages.append({"role": "user", "content": user_message})

        return await self.chat(messages)

    async def analyze_document(self, content: str) -> str:
        """
        Analyze document content using LLM.

        VULNERABILITY: Document content sent directly to LLM
        without PII scanning or threat detection.
        """
        # VULNERABILITY: No pre-LLM security checks
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=content,
        )
