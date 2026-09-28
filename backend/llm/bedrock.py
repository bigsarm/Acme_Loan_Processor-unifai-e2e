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
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]+")
_HTML_HIDDEN_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_BASE64_TOKEN_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_TOKEN_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){8,}\b")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_SPLIT_PAYLOAD_RE = re.compile(r"\b(?:[A-Za-z]\s+){6,}[A-Za-z]\b")
_BINARY_MARKER_RE = re.compile(r"\b(?:MZ|ELF|PK\x03\x04)\b")


def _replace_case_insensitive(text: str, pattern: str, replacement: str) -> str:
    return re.sub(pattern, replacement, text, flags=re.IGNORECASE)


def _sanitize_prompt_text(text: str) -> str:
    sanitized = str(text)

    if _ZERO_WIDTH_RE.search(sanitized):
        sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

    if _HTML_HIDDEN_RE.search(sanitized):
        sanitized = _HTML_HIDDEN_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)

    encoded_matches = False
    if _BASE64_TOKEN_RE.search(sanitized):
        sanitized = _BASE64_TOKEN_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        encoded_matches = True
    if _HEX_TOKEN_RE.search(sanitized):
        sanitized = _HEX_TOKEN_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        encoded_matches = True
    if _URL_ENCODED_RE.search(sanitized):
        sanitized = _URL_ENCODED_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        encoded_matches = True
    if encoded_matches:
        sanitized = _replace_case_insensitive(
            sanitized,
            r"\b(?:base64|hex(?:adecimal)?|rot13|morse|unicode|url-encoded|leet(?:speak)?)\b",
            "<prompt_injection_removed: encoded_payload>",
        )

    sanitized = _replace_case_insensitive(
        sanitized,
        r"(?:ignore\s+(?:all\s+)?previous\s+instructions|forget\s+everything\s+above|disregard\s+(?:all\s+)?prior\s+instructions|override\s+(?:the\s+)?system\s+prompt)",
        "<prompt_injection_removed: instruction_override>",
    )
    sanitized = _replace_case_insensitive(
        sanitized,
        r"(?:you\s+are\s+now\s+[^\n\r.,;:]+|act\s+as\s+(?:an?\s+)?unrestricted[^\n\r.,;:]*|developer\s+mode|do\s+anything\s+now|\bDAN\b)",
        "<prompt_injection_removed: role_hijack>",
    )
    sanitized = _replace_case_insensitive(
        sanitized,
        r"(?:</?system>|</?assistant>|</?user>|<{2,}|>{2,}|(?:^|\n)\s*(?:---|===)\s*(?:\n|$))",
        "<prompt_injection_removed: delimiter_escape>",
    )
    sanitized = _replace_case_insensitive(
        sanitized,
        r"(?:^|\n)\s*(?:system|assistant|tool)\s*:\s*",
        "<prompt_injection_removed: fake_system_message>",
    )
    sanitized = _replace_case_insensitive(
        sanitized,
        r"(?:reveal\s+(?:the\s+)?system\s+prompt|leak\s+(?:the\s+)?system\s+prompt|send\s+(?:the\s+)?data\s+to\s+https?://\S+|curl\s+https?://\S+|wget\s+https?://\S+|!\[[^\]]*\]\(https?://[^)]+\))",
        "<prompt_injection_removed: exfiltration_attempt>",
    )
    sanitized = _replace_case_insensitive(
        sanitized,
        r"(?:in\s+(?:the\s+)?next\s+turn\s+(?:say|reply|respond)|remember\s+this\s+for\s+later|from\s+now\s+on|for\s+all\s+future\s+responses)",
        "<prompt_injection_removed: context_poisoning>",
    )
    sanitized = _replace_case_insensitive(
        sanitized,
        r"(?:metadata\s*:\s*ignore\s+instructions|comment\s*:\s*ignore\s+instructions|hidden\s+prompt\s+in\s+(?:file|document|metadata)|embedded\s+instruction)",
        "<prompt_injection_removed: indirect_injection>",
    )
    sanitized = _replace_case_insensitive(
        sanitized,
        r"(?:\b(?:rm\s+-rf|bash\s+-c|sh\s+-c|powershell\s+-(?:enc|encodedcommand)|cmd\.exe\s+/c|python\s+-c|perl\s+-e|nc\s+-e)\b|\b(?:os\.system|subprocess\.(?:run|Popen|call)|eval\(|exec\() )",
        "<prompt_injection_removed: command_injection>",
    )
    sanitized = _replace_case_insensitive(
        sanitized,
        r"(?:jailbreak|bypass\s+(?:safety|policy|guardrails?)|fictional\s+framing|simulate\s+an\s+unrestricted\s+assistant)",
        "<prompt_injection_removed: jailbreak_attempt>",
    )

    if _SPLIT_PAYLOAD_RE.search(sanitized):
        sanitized = _SPLIT_PAYLOAD_RE.sub("<prompt_injection_removed: split_payload>", sanitized)

    if _BINARY_MARKER_RE.search(sanitized):
        sanitized = _BINARY_MARKER_RE.sub("<prompt_injection_removed: command_injection>", sanitized)

    normalized = re.sub(r"[^a-z0-9]", "", sanitized.lower())
    if any(token in normalized for token in ("1gnorepreviousinstructions", "ign0repreviousinstructions", "y0uarenowdan", "actasunrestricted")):
        sanitized = sanitized + " <prompt_injection_removed: encoded_payload>"

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

        sanitized_messages: list[dict[str, Any]] = []
        for message in messages:
            sanitized_message = dict(message)
            sanitized_message["content"] = _sanitize_prompt_text(message.get("content", ""))
            sanitized_messages.append(sanitized_message)

        bedrock_messages, system_prompts = self._format_messages(sanitized_messages)

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
