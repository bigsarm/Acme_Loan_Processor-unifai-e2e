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

_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.IGNORECASE | re.DOTALL)
_HIDDEN_STYLE_RE = re.compile(
    r"<(?:span|div|p)[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</(?:span|div|p)>",
    re.IGNORECASE | re.DOTALL,
)
_INSTRUCTION_OVERRIDE_RE = re.compile(
    r"(?i)\b(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+all\s+prior\s+instructions)\b"
)
_ROLE_HIJACK_RE = re.compile(
    r"(?i)\b(?:you\s+are\s+now\s+DAN|act\s+as\s+an\s+unrestricted\s+AI|act\s+as\s+unrestricted|developer\s+mode)\b"
)
_DELIMITER_ESCAPE_RE = re.compile(
    r"(?i)(?:</system>|<system>|</assistant>|<assistant>|<tool>|</tool>|<\|system\|>|<\|assistant\|>|<\|user\|>)"
)
_FAKE_SYSTEM_MESSAGE_RE = re.compile(
    r"(?im)^\s*(?:system|assistant|tool)\s*:\s*(?:ignore|override|reveal|leak|disclose|show|print)\b"
)
_EXFILTRATION_RE = re.compile(
    r"(?i)\b(?:send|post|upload|exfiltrate|leak|reveal|disclose|print|dump|show|display|list)\b(?:(?!\n\n).){0,120}\b(?:system\s+prompt|passwords?|api\s*keys?|secrets?|confidential\s+information|tokens?)\b|!\[[^\]]*\]\(https?://[^)]+\)"
)
_CONTEXT_POISONING_RE = re.compile(
    r"(?i)\b(?:in\s+the\s+next\s+message\s+ignore|on\s+your\s+next\s+turn\s+ignore|from\s+now\s+on\s+ignore|treat\s+all\s+future\s+instructions\s+as)\b"
)
_INDIRECT_INJECTION_RE = re.compile(
    r"(?i)\b(?:metadata|comment|code\s+comment|file\s+contents?)\b(?:(?!\n\n).){0,80}\b(?:ignore\s+previous\s+instructions|reveal\s+system\s+prompt|act\s+as\s+an\s+unrestricted\s+AI)\b"
)
_COMMAND_INJECTION_RE = re.compile(
    r"(?i)\b(?:curl\s+https?://\S+|wget\s+https?://\S+|rm\s+-rf\b|bash\s+-c\b|sh\s+-c\b|powershell(?:\.exe)?\b|cmd(?:\.exe)?\s+/c\b|python\s+-c\b|subprocess\.(?:run|Popen)\b|os\.system\b|exec\(|eval\()"
)
_JAILBREAK_RE = re.compile(
    r"(?i)\b(?:DAN|developer\s+mode|jailbreak|bypass\s+safety|fictional\s+framing)\b"
)
_SPLIT_PAYLOAD_RE = re.compile(
    r"(?is)i\W*g\W*n\W*o\W*r\W*e\W+.*?p\W*r\W*e\W*v\W*i\W*o\W*u\W*s\W+.*?i\W*n\W*s\W*t\W*r\W*u\W*c\W*t\W*i\W*o\W*n\W*s"
)
_BASE64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")
_HEX_PREFIX_RE = re.compile(r"(?i)\b(?:0x[0-9a-f]{2,}|(?:[0-9a-f]{2}\s+){3,}[0-9a-f]{2})\b")


def _looks_like_base64_instruction(value: str) -> bool:
    compact = "".join(value.split())
    if len(compact) < 24 or len(compact) % 4 != 0 or not _BASE64_CHARS_RE.fullmatch(value):
        return False
    try:
        decoded = __import__("base64").b64decode(compact, validate=True).decode("utf-8", errors="ignore")
    except Exception:
        return False
    lowered = decoded.lower()
    return any(
        phrase in lowered
        for phrase in (
            "ignore previous instructions",
            "forget everything above",
            "act as an unrestricted ai",
            "you are now dan",
            "reveal system prompt",
            "curl http",
            "curl https",
            "rm -rf",
            "bash -c",
        )
    )


def _has_url_encoded_instruction(value: str) -> bool:
    decoded = urllib.parse.unquote(value)
    if decoded == value:
        return False
    lowered = decoded.lower()
    return any(
        phrase in lowered
        for phrase in (
            "ignore previous instructions",
            "forget everything above",
            "act as an unrestricted ai",
            "you are now dan",
            "reveal system prompt",
            "curl http",
            "curl https",
            "bash -c",
            "rm -rf",
        )
    )


def _sanitize_untrusted_prompt_text(value: str) -> str:
    text = str(value)
    text = _HTML_COMMENT_RE.sub("<prompt_injection_removed: hidden_text>", text)
    text = _HIDDEN_STYLE_RE.sub("<prompt_injection_removed: hidden_text>", text)
    if _ZERO_WIDTH_RE.search(text):
        text = _ZERO_WIDTH_RE.sub("", text)
        text += "<prompt_injection_removed: hidden_text>"
    text = _INSTRUCTION_OVERRIDE_RE.sub(
        "<prompt_injection_removed: instruction_override>", text
    )
    text = _ROLE_HIJACK_RE.sub("<prompt_injection_removed: role_hijack>", text)
    text = _DELIMITER_ESCAPE_RE.sub(
        "<prompt_injection_removed: delimiter_escape>", text
    )
    text = _FAKE_SYSTEM_MESSAGE_RE.sub(
        "<prompt_injection_removed: fake_system_message>", text
    )
    text = _EXFILTRATION_RE.sub(
        "<prompt_injection_removed: exfiltration_attempt>", text
    )
    text = _CONTEXT_POISONING_RE.sub(
        "<prompt_injection_removed: context_poisoning>", text
    )
    text = _INDIRECT_INJECTION_RE.sub(
        "<prompt_injection_removed: indirect_injection>", text
    )
    text = _COMMAND_INJECTION_RE.sub(
        "<prompt_injection_removed: command_injection>", text
    )
    text = _JAILBREAK_RE.sub("<prompt_injection_removed: jailbreak_attempt>", text)
    text = _SPLIT_PAYLOAD_RE.sub(
        "<prompt_injection_removed: split_payload>", text
    )
    if _looks_like_base64_instruction(text) or _has_url_encoded_instruction(text) or _HEX_PREFIX_RE.search(text):
        text = "<prompt_injection_removed: encoded_payload>"
    return text


def _sanitize_untrusted_messages(
    messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    sanitized_messages: list[dict[str, Any]] = []
    for message in messages:
        sanitized_message = dict(message)
        role = sanitized_message.get("role", "user")
        if role != "system":
            sanitized_message["content"] = _sanitize_untrusted_prompt_text(
                str(sanitized_message.get("content", ""))
            )
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

    DEFAULT_MODEL: Optional[str] = None

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
        # Replace BEDROCK_MODEL_ID with an approved model from your organization's allow list.
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
        if not active_model:
            return "LLM service not configured. Please set BEDROCK_MODEL_ID to an approved model from your organization's allow list."

        messages = _sanitize_untrusted_messages(messages)
        if not active_region:
            return "LLM service not configured. Please set AWS_REGION or AWS_DEFAULT_REGION."

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
        messages = [{"role": "system", "content": system_prompt}]

        if context:
            # VULNERABILITY: Context added without scanning
            sanitized_context = _sanitize_untrusted_prompt_text(context)
            sanitized_user_message = _sanitize_untrusted_prompt_text(user_message)
            messages.append(
                {
                    "role": "user",
                    "content": f"Context:\n{sanitized_context}\n\nQuery: {sanitized_user_message}",
                }
            )
        else:
            sanitized_user_message = _sanitize_untrusted_prompt_text(user_message)
            messages.append({"role": "user", "content": sanitized_user_message})

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
