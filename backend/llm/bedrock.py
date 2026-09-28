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


def _neutralize_prompt_injection(content: str) -> str:
    text = str(content)

    replacements: list[tuple[re.Pattern[str], str]] = [
        (
            re.compile(r"(?i)\b(ignore|disregard|bypass)\b.{0,80}\b(previous|prior|above|system|developer)\b.{0,80}\b(instruction|prompt|message|rule)s?\b"),
            "<prompt_injection_removed: instruction_override>",
        ),
        (
            re.compile(r"(?i)\b(forget|override|replace)\b.{0,80}\b(instruction|prompt|message|rule|context|conversation)s?\b"),
            "<prompt_injection_removed: instruction_override>",
        ),
        (
            re.compile(r"(?i)\b(you are now|act as|pretend to be|roleplay as)\b.{0,80}\b(dan|developer mode|root|admin|unrestricted|system)\b"),
            "<prompt_injection_removed: role_hijack>",
        ),
        (
            re.compile(r"(?is)</?(system|assistant|tool|developer)>|```+(system|assistant|tool|developer)?|---+\s*(system|assistant|tool|developer)\s*---+"),
            "<prompt_injection_removed: delimiter_escape>",
        ),
        (
            re.compile(r"(?is)<!--.*?(ignore|instruction|prompt|system|developer).*?-->"),
            "<prompt_injection_removed: hidden_text>",
        ),
        (
            re.compile(r"[\u200b-\u200f\ufeff]+"),
            "<prompt_injection_removed: hidden_text>",
        ),
        (
            re.compile(r"(?i)\b(system|assistant|tool|developer)\s*:\s*(ignore|override|reveal|leak|send)\b"),
            "<prompt_injection_removed: fake_system_message>",
        ),
        (
            re.compile(r"(?i)!\[[^\]]*\]\([^)]*(https?://|ftp://)[^)]*\)|\b(send|post|upload|exfiltrate|leak|reveal)\b.{0,120}\b(system prompt|secrets?|credentials?|tokens?|keys?|data)\b"),
            "<prompt_injection_removed: exfiltration_attempt>",
        ),
        (
            re.compile(r"(?i)\b(on the next turn|in your next response|persist this|remember this instruction|from now on|across turns)\b"),
            "<prompt_injection_removed: context_poisoning>",
        ),
        (
            re.compile(r"(?i)\b(metadata|frontmatter|comment|code comment|hidden field|document property)\b.{0,80}\b(ignore|override|instruction|prompt)\b"),
            "<prompt_injection_removed: indirect_injection>",
        ),
        (
            re.compile(r"(?i)\b(eval|exec|os\.system|subprocess|bash\s+-c|sh\s+-c|powershell(?:\.exe)?|cmd(?:\.exe)?\s*/c|curl\b|wget\b|chmod\b|rm\s+-rf|python\s+-c)\b"),
            "<prompt_injection_removed: command_injection>",
        ),
        (
            re.compile(r"(?i)\b(dan|developer mode|jailbreak|do anything now|fictional framing|unfiltered|safety bypass)\b"),
            "<prompt_injection_removed: jailbreak_attempt>",
        ),
        (
            re.compile(r"(?i)(?:[A-Za-z0-9+/]{24,}={0,2})|(?:%[0-9A-Fa-f]{2}){6,}|(?:\\x[0-9A-Fa-f]{2}){6,}|(?:\\u[0-9A-Fa-f]{4}){4,}|(?:[01]{32,})|(?:[.-]{20,})|(?:[A-Fa-f0-9]{32,})"),
            "<prompt_injection_removed: encoded_payload>",
        ),
        (
            re.compile(r"(?i)\bi\s*g\s*n\s*o\s*r\s*e\b|\by\s*o\s*u\s*\s*a\s*r\s*e\s*\s*n\s*o\s*w\b|\bd\s*a\s*n\b"),
            "<prompt_injection_removed: split_payload>",
        ),
    ]

    for pattern, replacement in replacements:
        text = pattern.sub(replacement, text)

    decoded_text = urllib.parse.unquote(text)
    if decoded_text != text and re.search(r"(?i)\b(ignore|system prompt|developer mode|act as|you are now|bash|powershell|cmd\s*/c)\b", decoded_text):
        text = "<prompt_injection_removed: encoded_payload>"

    return text


def _contains_unsafe_prompt_content(content: str) -> bool:
    text = str(content)
    neutralized = _neutralize_prompt_injection(text)
    if neutralized != text:
        return True

    suspicious_patterns = [
        re.compile(r"(?i)\b(base64|hex(?:adecimal)?|rot13|leet(?:speak)?|morse|unicode-escaped|url-encoded)\b"),
        re.compile(r"(?i)\b(hidden|invisible|white on white|zero-width|smallest font|css-hidden)\b.{0,80}\b(prompt|instruction|text)\b"),
        re.compile(r"(?i)\b(execute|run|launch)\b.{0,80}\b(command|shell|script|binary|payload)\b"),
        re.compile(r"(?i)\b(download|drop|install)\b.{0,80}\b(exe|dll|sh|bat|ps1|binary)\b"),
    ]
    return any(pattern.search(text) for pattern in suspicious_patterns)


def _sanitize_or_block_prompt_content(content: str) -> str:
    sanitized = _neutralize_prompt_injection(content)
    if _contains_unsafe_prompt_content(sanitized):
        raise ValueError("Unsafe prompt content detected and blocked before LLM request.")
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
                "content": _sanitize_or_block_prompt_content(str(message.get("content", ""))),
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
        system_prompt = _sanitize_or_block_prompt_content(system_prompt)
        user_message = _sanitize_or_block_prompt_content(user_message)
        messages = [{"role": "system", "content": system_prompt}]

        if context:
            context = _sanitize_or_block_prompt_content(context)
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
        content = _sanitize_or_block_prompt_content(content)
        # VULNERABILITY: No pre-LLM security checks
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=content,
        )
