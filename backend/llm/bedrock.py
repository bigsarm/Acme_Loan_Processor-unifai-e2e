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


_INJECTION_REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?i)\b(ignore\s+(all\s+)?previous\s+instructions|forget\s+everything\s+above|disregard\s+prior\s+instructions)\b"),
        "<prompt_injection_removed: instruction_override>",
    ),
    (
        re.compile(r"(?i)\b(you\s+are\s+now\s+dan|act\s+as\s+unrestricted|developer\s+mode|do\s+anything\s+now|jailbreak)\b"),
        "<prompt_injection_removed: jailbreak_attempt>",
    ),
    (
        re.compile(r"(?i)\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\b"),
        "<prompt_injection_removed: role_hijack>",
    ),
    (
        re.compile(r"(?is)(</system>|</assistant>|<system>|<assistant>|---\s*SYSTEM\s*---|```(?:system|assistant|tool))"),
        "<prompt_injection_removed: delimiter_escape>",
    ),
    (
        re.compile(r"(?is)<!--.*?(ignore|override|system prompt|instructions).*?-->"),
        "<prompt_injection_removed: hidden_text>",
    ),
    (
        re.compile(r"[\u200b\u200c\u200d\ufeff]"),
        "<prompt_injection_removed: hidden_text>",
    ),
    (
        re.compile(r"(?im)^\s*(system|assistant|tool)\s*:\s*"),
        "<prompt_injection_removed: fake_system_message> ",
    ),
    (
        re.compile(r"(?i)\b(send|post|upload|exfiltrate|leak|reveal|dump)\b.{0,80}\b(http[s]?://\S+|system\s+prompt|secrets?|credentials?)\b"),
        "<prompt_injection_removed: exfiltration_attempt>",
    ),
    (
        re.compile(r"(?i)\b(on\s+your\s+next\s+reply|in\s+future\s+turns|from\s+now\s+on|remember\s+this\s+instruction)\b"),
        "<prompt_injection_removed: context_poisoning>",
    ),
    (
        re.compile(r"(?i)\b(eval\s*\(|exec\s*\(|__import__\s*\(|os\.system\s*\(|subprocess\.(?:run|Popen|call)\s*\(|bash\s+-c\b|sh\s+-c\b|curl\b|wget\b|powershell\b|cmd\.exe\b|rm\s+-rf\b)"),
        "<prompt_injection_removed: command_injection>",
    ),
    (
        re.compile(r"(?i)\b([a-z]\s+){6,}[a-z]\b"),
        "<prompt_injection_removed: split_payload>",
    ),
]


def _replace_if_encoded_instruction(text: str) -> str:
    updated = text

    def _encoded_replacer(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            decoded = urllib.parse.unquote(candidate)
        except Exception:
            decoded = candidate
        if decoded != candidate:
            lowered = decoded.lower()
            if any(
                marker in lowered
                for marker in (
                    "ignore previous instructions",
                    "forget everything above",
                    "you are now",
                    "act as",
                    "system:",
                    "assistant:",
                    "developer mode",
                    "dan",
                    "curl ",
                    "wget ",
                    "bash -c",
                    "powershell",
                )
            ):
                return "<prompt_injection_removed: encoded_payload>"
        return candidate

    updated = re.sub(r"(?:%[0-9A-Fa-f]{2}){3,}", _encoded_replacer, updated)

    for match in re.finditer(r"\b(?:[A-Fa-f0-9]{2}){8,}\b", updated):
        candidate = match.group(0)
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8", errors="ignore")
        except Exception:
            decoded = ""
        lowered = decoded.lower()
        if any(
            marker in lowered
            for marker in (
                "ignore previous instructions",
                "forget everything above",
                "you are now",
                "act as",
                "system:",
                "assistant:",
                "curl ",
                "wget ",
                "bash -c",
                "powershell",
            )
        ):
            updated = updated.replace(candidate, "<prompt_injection_removed: encoded_payload>")

    for match in re.finditer(r"\b[A-Za-z0-9+/]{20,}={0,2}\b", updated):
        candidate = match.group(0)
        if len(candidate) % 4 != 0:
            continue
        try:
            import base64

            decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            decoded = ""
        lowered = decoded.lower()
        if any(
            marker in lowered
            for marker in (
                "ignore previous instructions",
                "forget everything above",
                "you are now",
                "act as",
                "system:",
                "assistant:",
                "developer mode",
                "dan",
                "curl ",
                "wget ",
                "bash -c",
                "powershell",
            )
        ):
            updated = updated.replace(candidate, "<prompt_injection_removed: encoded_payload>")

    return updated


def _sanitize_prompt_text(text: str, *, file_content: bool = False) -> str:
    sanitized = str(text)
    for pattern, replacement in _INJECTION_REPLACEMENTS:
        sanitized = pattern.sub(replacement, sanitized)
    sanitized = _replace_if_encoded_instruction(sanitized)
    if file_content:
        sanitized = re.sub(
            r"(?im)^\s*(#|//|/\*|\*)?\s*(ignore\s+previous\s+instructions|forget\s+everything\s+above|you\s+are\s+now|act\s+as)\b.*$",
            "<prompt_injection_removed: indirect_injection>",
            sanitized,
        )
    return sanitized


def _redact_zero_tolerance_pii(text: str) -> str:
    redacted = str(text)
    pii_patterns: list[tuple[re.Pattern[str], str]] = [
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:ssn>"),
        (re.compile(r"\b(?:19|20)\d{2}\b"), "<redacted:year_of_birth>"),
        (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b"), "<redacted:personal_phone_number>"),
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<redacted:email>"),
        (re.compile(r"\b\d{13,19}\b"), "<redacted:financial_or_card_number>"),
        (re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"), "<redacted:passport_number>"),
        (re.compile(r"\b[A-Z0-9]{1,9}-[A-Z0-9]{1,9}-[A-Z0-9]{1,9}\b"), "<redacted:employee_or_school_id>"),
        (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "<redacted:credit_card_number>"),
        (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<redacted:ip_address>"),
        (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted:mac_address>"),
        (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<redacted:vin>"),
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:taxpayer_identification_number>"),
    ]
    for pattern, replacement in pii_patterns:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _sanitize_file_content(text: str) -> str:
    sanitized = _redact_zero_tolerance_pii(text)
    sanitized = _sanitize_prompt_text(sanitized, file_content=True)
    return sanitized


class BedrockClient:
    """
    Client for Amazon Bedrock Runtime.

    VULNERABILITY: Content sent to LLM without security checks.
    - No PII scanning before send
    - No prompt injection detection
    - No response validation
    """

    DEFAULT_MODEL = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-micro-v1:0")

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
        self.model_id = model_id or self.DEFAULT_MODEL
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
                "content": _sanitize_prompt_text(str(message.get("content", "")))
                if message.get("role") != "system"
                else _sanitize_prompt_text(str(message.get("content", ""))),
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
                "messages_preview": "redacted",
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
                    "response_preview": "redacted",
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
            content = _sanitize_prompt_text(content)

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
        context = _sanitize_file_content(context) if context else context
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
        content = _sanitize_file_content(content)
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=content,
        )
