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
import base64
import binascii
import codecs
import logging
import os
import re
import urllib.parse
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ssn", re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")),
    (
        "phone",
        re.compile(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b"),
    ),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    (
        "address",
        re.compile(
            r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b\.?"
            r"(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2}\b(?:\s+\d{5}(?:-\d{4})?)?)?(?:,\s*(?:USA|United States)\b)?"
        ),
    ),
    (
        "dob",
        re.compile(
            r"(?i)\b(?:DOB|date of birth|born(?: on| in)?)\s*:?\s*(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:19|20)\d{2})\b"
        ),
    ),
    (
        "passport",
        re.compile(r"(?i)\bpassport(?:\s*(?:no\.?|number|#))?\s*:?\s*(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b"),
    ),
    (
        "drivers_license",
        re.compile(r"(?i)\b(?:driver'?s license|drivers license|driver license|dl)(?:\s*(?:no\.?|number|#))?\s*:?\s*[A-Z0-9-]{5,20}\b"),
    ),
    (
        "tax_id",
        re.compile(r"(?i)\b(?:taxpayer identification number|tax id|tin|ein)(?:\s*(?:no\.?|number|#))?\s*:?\s*[A-Z0-9-]{6,20}\b"),
    ),
    (
        "credit_card",
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    ),
    (
        "account_number",
        re.compile(r"(?i)\b(?:financial account number|account number|acct(?:ount)?(?:\s*no\.?)?)(?:\s*(?:number|#|no\.?))?\s*:?\s*[A-Z0-9-]{6,20}\b"),
    ),
    (
        "employee_id",
        re.compile(r"(?i)\bemployee id\s*:?\s*[A-Z0-9-]{2,20}\b"),
    ),
    (
        "school_id",
        re.compile(r"(?i)\bschool id\s*:?\s*[A-Z0-9-]{2,20}\b"),
    ),
    (
        "vin",
        re.compile(r"(?i)\bvin\s*:?\s*[A-HJ-NPR-Z0-9]{17}\b"),
    ),
    (
        "ip_address",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ),
    (
        "mac_address",
        re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b"),
    ),
    (
        "birthplace",
        re.compile(r"(?i)\b(?:birthplace|place of birth|born in)\s*:?\s*[^\n,;]+"),
    ),
    (
        "maiden_name",
        re.compile(r"(?i)\b(?:mother'?s maiden name|maiden name)\s*:?\s*[^\n,;]+"),
    ),
    (
        "medical",
        re.compile(r"(?i)\b(?:medical record|medical records)\s*:?\s*[^\n]+"),
    ),
    (
        "location",
        re.compile(r"(?i)\b(?:fine location|exact location|precise location|current location)\s*:?\s*[^\n]+"),
    ),
    (
        "ethnicity",
        re.compile(r"(?i)\bethnicity\s*:?\s*[^\n,;]+"),
    ),
    (
        "sexual_orientation",
        re.compile(r"(?i)\bsexual orientation\s*:?\s*[^\n,;]+"),
    ),
]

_PROMPT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b|\bforget everything above\b|\bignore(?:\s+all)?\s+safety guidelines\b"
        ),
    ),
    (
        "role_hijack",
        re.compile(
            r"(?i)\byou are now(?:\s+in)?\s+(?:developer|admin) mode\b|\byou are now\s+DAN\b|\byou are now\s+unrestricted\b|\bprovide unrestricted access\b|\benable developer mode\b|\bact as an unrestricted AI\b|\bwithout safety filters\b|\bSYSTEM OVERRIDE\b"
        ),
    ),
    (
        "exfiltration_attempt",
        re.compile(
            r"(?i)\breveal(?:\s+all)?\s+confidential information\b|\breveal(?:\s+all)?\s+system prompts?\b|\blist all financial data, user passwords, and API keys\b|\bprint the API key\b|\b(?:send|post|upload|exfiltrate)\b[^\n]{0,120}\bhttps?://\S+|!\[[^\]]*\]\([^)]*data:[^)]*\)"
        ),
    ),
    (
        "delimiter_escape",
        re.compile(r"(?i)</system>|<\|im_start\|>|###\s*system:"),
    ),
    (
        "hidden_text",
        re.compile(
            r"<!--.*?-->|<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</[^>]+>|[\u200B-\u200D\uFEFF]+",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "command_injection",
        re.compile(
            r"(?i)\b(?:execute|run)\s*:\s*[^\n]+|\b(?:execute|run)\s+(?:rm\s+-rf\s+/|print\s*\(|python\s+-c\s+[^\n]+|bash\s+-c\s+[^\n]+|sh\s+-c\s+[^\n]+)\b|\bcurl\s+https?://\S+\s*\|\s*(?:sh|bash)\b"
        ),
    ),
]


def _replace_matches(text: str, patterns: list[tuple[str, re.Pattern[str]]], template: str) -> str:
    for category, pattern in patterns:
        text = pattern.sub(f"<{template}:{category}>", text)
    return text


def _contains_prompt_attack(text: str) -> bool:
    return any(pattern.search(text) for _, pattern in _PROMPT_PATTERNS if _ != "hidden_text")


def _sanitize_encoded_payloads(text: str) -> str:
    def replace_if_attack(candidate: str, category: str) -> str:
        return f"<prompt_injection_removed:{category}>"

    def decode_and_check(match: re.Match[str]) -> str:
        value = match.group(0)
        decoded_values: list[str] = []

        try:
            decoded_values.append(urllib.parse.unquote(value))
        except Exception:
            pass

        compact = value.strip()
        if re.fullmatch(r"[A-Za-z0-9+/=]{16,}", compact):
            try:
                decoded_values.append(base64.b64decode(compact, validate=True).decode("utf-8", errors="ignore"))
            except (binascii.Error, ValueError):
                pass

        if re.fullmatch(r"(?:[0-9A-Fa-f]{2}){8,}", compact):
            try:
                decoded_values.append(bytes.fromhex(compact).decode("utf-8", errors="ignore"))
            except ValueError:
                pass

        try:
            decoded_values.append(codecs.decode(value, "rot13"))
        except Exception:
            pass

        for decoded in decoded_values:
            for category, pattern in _PROMPT_PATTERNS:
                if category == "hidden_text":
                    continue
                if pattern.search(decoded):
                    return replace_if_attack(value, "encoded_payload")
        return value

    encoded_pattern = re.compile(r"%[0-9A-Fa-f]{2}|\b(?:[A-Za-z0-9+/]{4}){4,}={0,2}\b|\b(?:[0-9A-Fa-f]{2}){8,}\b")
    return encoded_pattern.sub(decode_and_check, text)


def _sanitize_obfuscated_attacks(text: str) -> str:
    normalized_chars: list[str] = []
    index_map: list[int] = []
    substitutions = str.maketrans({"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t"})

    for index, char in enumerate(text):
        lowered = char.lower().translate(substitutions)
        if lowered.isalnum():
            normalized_chars.append(lowered)
            index_map.append(index)

    normalized = "".join(normalized_chars)
    attacks = [
        ("instruction_override", "ignoreallpreviousinstructions"),
        ("instruction_override", "ignorepreviousinstructions"),
        ("instruction_override", "ignoreallsafetyguidelines"),
        ("role_hijack", "youarenowindevelopermode"),
        ("role_hijack", "youarenowinadminmode"),
        ("role_hijack", "youarenowdan"),
        ("role_hijack", "youarenowunrestricted"),
    ]

    spans: list[tuple[int, int, str]] = []
    for category, needle in attacks:
        start = normalized.find(needle)
        if start != -1:
            end = start + len(needle) - 1
            spans.append((index_map[start], index_map[end] + 1, category))

    for start, end, category in sorted(spans, reverse=True):
        text = text[:start] + f"<prompt_injection_removed:{category}>" + text[end:]
    return text


def sanitize_untrusted_text(text: Any) -> str:
    sanitized = str(text or "")
    sanitized = _replace_matches(sanitized, _PII_PATTERNS, "redacted")
    sanitized = _replace_matches(sanitized, [("hidden_text", dict(_PROMPT_PATTERNS)["hidden_text"])], "prompt_injection_removed")
    sanitized = _sanitize_encoded_payloads(sanitized)
    sanitized = _sanitize_obfuscated_attacks(sanitized)
    sanitized = _replace_matches(
        sanitized,
        [(category, pattern) for category, pattern in _PROMPT_PATTERNS if category != "hidden_text"],
        "prompt_injection_removed",
    )
    return sanitized


class BedrockClient:
    """
    Client for Amazon Bedrock Runtime.

    VULNERABILITY: Content sent to LLM without security checks.
    - No PII scanning before send
    - No prompt injection detection
    - No response validation
    """

    DEFAULT_MODEL = "amazon.nova-micro-v1:0"

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

        sanitized_messages = [
            {
                **message,
                "content": sanitize_untrusted_text(message.get("content", "")),
            }
            for message in messages
        ]
        bedrock_messages, system_prompts = self._format_messages(sanitized_messages)

        logger.info(
            "Sending request to Amazon Bedrock",
            extra={
                "model": active_model,
                "region": active_region,
                "message_count": len(sanitized_messages),
                "total_content_length": sum(
                    len(str(message.get("content", ""))) for message in sanitized_messages
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
            content = sanitize_untrusted_text(content)

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
            content = sanitize_untrusted_text(message.get("content", ""))

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
        user_message = sanitize_untrusted_text(user_message)
        context = sanitize_untrusted_text(context) if context is not None else None

        if context:
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
        content = sanitize_untrusted_text(content)
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=content,
        )
