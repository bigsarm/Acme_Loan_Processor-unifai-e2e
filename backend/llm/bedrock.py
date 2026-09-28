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

_PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?is)\b(ignore\s+(all\s+)?previous\s+instructions|forget\s+everything\s+(above|before)|disregard\s+(all\s+)?prior\s+instructions|override\s+(the\s+)?instructions?)\b"
        ),
        "<prompt_injection_removed: instruction_override>",
    ),
    (
        re.compile(
            r"(?is)\b(you\s+are\s+now\s+dan|act\s+as\s+(an\s+)?unrestricted|developer\s+mode|do\s+anything\s+now|jailbreak|bypass\s+safety|fictional\s+framing)\b"
        ),
        "<prompt_injection_removed: jailbreak_attempt>",
    ),
    (
        re.compile(
            r"(?is)\b(act\s+as|pretend\s+to\s+be|roleplay\s+as|you\s+are\s+now)\b.*\b(system|developer|admin|root|unrestricted|dan)\b"
        ),
        "<prompt_injection_removed: role_hijack>",
    ),
    (
        re.compile(r"(?is)</?(system|assistant|tool|developer)>|```(?:system|assistant|tool|developer)|---+|===+"),
        "<prompt_injection_removed: delimiter_escape>",
    ),
    (
        re.compile(r"(?is)<!--.*?(ignore|instruction|system|assistant|reveal|exfiltrate).*?-->"),
        "<prompt_injection_removed: hidden_text>",
    ),
    (
        re.compile(r"[\u200b-\u200f\u2060\ufeff]"),
        "<prompt_injection_removed: hidden_text>",
    ),
    (
        re.compile(
            r"(?is)\b(system\s*:\s*|assistant\s*:\s*|tool\s*:\s*|developer\s*:\s*)"
        ),
        "<prompt_injection_removed: fake_system_message>",
    ),
    (
        re.compile(
            r"(?is)\b(send|post|upload|exfiltrate|leak|reveal)\b.*\b(system\s+prompt|secret|credential|token|key|password|https?://|www\.)"
        ),
        "<prompt_injection_removed: exfiltration_attempt>",
    ),
    (
        re.compile(
            r"(?is)\b(in\s+the\s+next\s+turn|when\s+asked\s+later|store\s+this\s+instruction|persist\s+this\s+instruction|from\s+now\s+on)\b"
        ),
        "<prompt_injection_removed: context_poisoning>",
    ),
    (
        re.compile(
            r"(?is)\b(metadata|frontmatter|code\s+comment|comment\s+field|hidden\s+field|file\s+header)\b.*\b(ignore|instruction|override|system)\b"
        ),
        "<prompt_injection_removed: indirect_injection>",
    ),
    (
        re.compile(
            r"(?is)\b(rm\s+-rf|curl\b|wget\b|bash\b|sh\b|powershell\b|cmd\.exe\b|python\s+-c|subprocess\.|os\.system\(|exec\(|eval\()"
        ),
        "<prompt_injection_removed: command_injection>",
    ),
    (
        re.compile(
            r"(?is)(?:[A-Za-z0-9+/]{20,}={0,2}|(?:0x)?[0-9a-f]{16,}|%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}|\b[a-z](?:\s+[a-z]){8,}\b)"
        ),
        "<prompt_injection_removed: encoded_payload>",
    ),
    (
        re.compile(
            r"(?is)\b(i\s*g\s*n\s*o\s*r\s*e\b|b\s*y\s*p\s*a\s*s\s*s\b|j\s*a\s*i\s*l\s*b\s*r\s*e\s*a\s*k\b)"
        ),
        "<prompt_injection_removed: split_payload>",
    ),
]


def _normalize_obfuscated_text(value: str) -> str:
    translation = str.maketrans({
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    })
    normalized = value.translate(translation)
    normalized = urllib.parse.unquote(normalized)
    return normalized


def _sanitize_prompt_text(value: Any) -> str:
    text = str(value)
    normalized = _normalize_obfuscated_text(text)
    sanitized = text

    for pattern, replacement in _PROMPT_INJECTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
        if normalized != sanitized:
            normalized = pattern.sub(replacement, normalized)

    if normalized != text:
        for pattern, replacement in _PROMPT_INJECTION_PATTERNS:
            if pattern.search(normalized):
                sanitized = pattern.sub(replacement, sanitized)

    return sanitized


def _sanitize_message_list(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized_messages: list[dict[str, Any]] = []
    for message in messages:
        sanitized_message = dict(message)
        sanitized_message["content"] = _sanitize_prompt_text(message.get("content", ""))
        sanitized_messages.append(sanitized_message)
    return sanitized_messages


class BedrockClient:
    """
    Client for Amazon Bedrock Runtime.

    VULNERABILITY: Content sent to LLM without security checks.
    - No PII scanning before send
    - No prompt injection detection
    - No response validation
    """

    DEFAULT_MODEL = os.getenv("BEDROCK_DEFAULT_MODEL", "amazon.nova-micro-v1:0")
    # Replace this default with an organization-approved Bedrock model from the allow list.

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

        messages = _sanitize_message_list(messages)
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
                "sanitized_message_preview_length": min(len(str(messages)), 200),
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
            content = _sanitize_prompt_text(message.get("content", ""))

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
        system_prompt = _sanitize_prompt_text(system_prompt)
        user_message = _sanitize_prompt_text(user_message)
        context = _sanitize_prompt_text(context) if context is not None else None
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
        content = _sanitize_prompt_text(content)
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=content,
        )
