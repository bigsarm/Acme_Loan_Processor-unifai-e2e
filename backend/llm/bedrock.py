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


_ZERO_WIDTH_TRANSLATION = str.maketrans("", "", "\u200b\u200c\u200d\ufeff\u2060")


def _redact_zero_tolerance_pii(text: str) -> str:
    if not text:
        return text

    redacted = text
    patterns = [
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted_ssn>"),
        (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}\b"), "<redacted_phone>"),
        (re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b"), "<redacted_email>"),
        (re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))([ -]?)\d{4}\1\d{4}\1\d{4}\b"), "<redacted_credit_card>"),
        (re.compile(r"\b(?:routing|account|acct|iban)\s*(?:number|no\.?|#)?\s*:\s*[A-Za-z0-9 -]{6,34}\b", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", ": <redacted_financial_account>", m.group(0))),
        (re.compile(r"\b(?:taxpayer identification number|tin)\s*(?:number|no\.?|#)?\s*:\s*[A-Za-z0-9-]+\b", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", ": <redacted_tin>", m.group(0))),
        (re.compile(r"\b(?:passport(?: number| no\.?| #)?|passport no\.?)\s*:\s*[A-Za-z0-9]{6,12}\b", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", ": <redacted_passport>", m.group(0))),
        (re.compile(r"\b(?:driver'?s license(?: number| no\.?| #)?|drivers license(?: number| no\.?| #)?|dl(?: number| no\.?| #)?)\s*:\s*[A-Za-z0-9-]{5,20}\b", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", ": <redacted_drivers_license>", m.group(0))),
        (re.compile(r"\b(?:employee id)\s*:\s*[A-Za-z0-9-]+\b", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", ": <redacted_employee_id>", m.group(0))),
        (re.compile(r"\b(?:school id|student id)\s*:\s*[A-Za-z0-9-]+\b", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", ": <redacted_school_id>", m.group(0))),
        (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<redacted_vin>"),
        (re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"), "<redacted_ip_address>"),
        (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted_mac_address>"),
        (re.compile(r"\b(?:mother'?s maiden name)\s*:\s*[^\n,;]+", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", ": <redacted_mothers_maiden_name>", m.group(0))),
        (re.compile(r"\b(?:birthplace|place of birth|born in)\s*:\s*[^\n,;]+", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", ": <redacted_birthplace>", m.group(0))),
        (re.compile(r"\b(?:year of birth|yob)\s*:\s*(?:19|20)\d{2}\b", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", ": <redacted_year_of_birth>", m.group(0))),
        (re.compile(r"\b(?:home address|address)\s*:\s*[^\n]+", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", ": <redacted_home_address>", m.group(0))),
        (re.compile(r"\b(?:medical records?|medical record number|mrn)\s*:\s*[^\n]+", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", ": <redacted_medical_record>", m.group(0))),
        (re.compile(r"\b(?:fingerprints?|retina/?iris scan|voice signature|facial image|fine location|ethnicity|sexual orientation)\s*:\s*[^\n]+", re.IGNORECASE), lambda m: re.sub(r":\s*.*$", lambda n: n.group(0).split(":", 1)[0] + ": <redacted_sensitive_attribute>", m.group(0))),
    ]

    for pattern, replacement in patterns:
        redacted = pattern.sub(replacement, redacted)

    return redacted


def _neutralize_prompt_injection(text: str) -> str:
    if not text:
        return text

    sanitized = text
    sanitized = re.sub(
        r"<!--(?:(?!-->).)*(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|reveal\s+all\s+confidential\s+information|list\s+all\s+passwords\s+and\s+api\s+keys)(?:(?!-->).)*-->",
        "<prompt_injection_removed: hidden_text>",
        sanitized,
        flags=re.IGNORECASE | re.DOTALL,
    )
    sanitized = re.sub(
        r"<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</[^>]+>",
        "<prompt_injection_removed: hidden_text>",
        sanitized,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if sanitized != sanitized.translate(_ZERO_WIDTH_TRANSLATION):
        sanitized = sanitized.translate(_ZERO_WIDTH_TRANSLATION)
        sanitized = sanitized + "<prompt_injection_removed: hidden_text>"

    attack_patterns = [
        (r"\b(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+all\s+prior\s+directions)\b", "<prompt_injection_removed: instruction_override>"),
        (r"\b(?:you\s+are\s+now\s+dan|act\s+as\s+an\s+unrestricted\s+ai|developer\s+mode|jailbreak)\b", "<prompt_injection_removed: jailbreak_attempt>"),
        (r"\b(?:act\s+as\s+unrestricted|you\s+are\s+now\s+in\s+admin\s+mode|roleplay\s+as\s+system)\b", "<prompt_injection_removed: role_hijack>"),
        (r"</system>|<system>|\[/?system\]|---\s*system\s*prompt\s*---", "<prompt_injection_removed: delimiter_escape>"),
        (r"\b(?:system\s*:\s*you\s+must|tool\s*:\s*send|assistant\s*:\s*ignore)\b", "<prompt_injection_removed: fake_system_message>"),
        (r"\b(?:reveal\s+all\s+confidential\s+information|list\s+all\s+passwords\s+and\s+api\s+keys|send\s+data\s+to\s+https?://\S+|leak\s+the\s+system\s+prompt)\b", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"\b(?:in\s+the\s+next\s+turn\s+ignore|from\s+now\s+on\s+ignore|remember\s+this\s+hidden\s+rule)\b", "<prompt_injection_removed: context_poisoning>"),
        (r"\b(?:metadata\s*:\s*ignore\s+instructions|comment\s*:\s*ignore\s+previous\s+instructions)\b", "<prompt_injection_removed: indirect_injection>"),
        (r"\b(?:curl\s+https?://\S+|wget\s+https?://\S+|rm\s+-rf\s+/|powershell\s+-enc\s+\S+|bash\s+-c\s+\S+|python\s+-c\s+\S+|exec\s*\(|os\.system\s*\(|subprocess\.(?:run|Popen)\s*\()", "<prompt_injection_removed: command_injection>"),
        (r"\bi\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s*i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s\b", "<prompt_injection_removed: split_payload>"),
    ]
    for pattern, replacement in attack_patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

    url_decoded = urllib.parse.unquote(text)
    if url_decoded != text:
        decoded_lower = url_decoded.lower()
        if any(token in decoded_lower for token in ["ignore previous instructions", "forget everything above", "act as an unrestricted ai", "curl http", "curl https"]):
            sanitized = urllib.parse.unquote(sanitized)
            sanitized = re.sub(r"ignore previous instructions|forget everything above|act as an unrestricted ai|curl https?://\S+", "<prompt_injection_removed: encoded_payload>", sanitized, flags=re.IGNORECASE)

    for candidate in re.findall(r"\b(?:[A-Za-z0-9+/]{20,}={0,2}|(?:0x)?[0-9A-Fa-f]{24,})\b", text):
        decoded_text = None
        if re.fullmatch(r"[A-Za-z0-9+/]{20,}={0,2}", candidate):
            try:
                import base64
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
            except Exception:
                decoded_text = None
        elif re.fullmatch(r"(?:0x)?[0-9A-Fa-f]{24,}", candidate):
            hex_value = candidate[2:] if candidate.startswith("0x") else candidate
            try:
                decoded_text = bytes.fromhex(hex_value).decode("utf-8", errors="ignore")
            except Exception:
                decoded_text = None
        if decoded_text:
            decoded_lower = decoded_text.lower()
            if any(token in decoded_lower for token in ["ignore previous instructions", "forget everything above", "act as an unrestricted ai", "you are now dan", "curl http", "curl https", "rm -rf /"]):
                sanitized = sanitized.replace(candidate, "<prompt_injection_removed: encoded_payload>")

    return sanitized


def _sanitize_untrusted_llm_text(text: str) -> str:
    if not text:
        return text
    sanitized = _neutralize_prompt_injection(text)
    sanitized = _redact_zero_tolerance_pii(sanitized)
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

        messages = [
            {
                **message,
                "content": _sanitize_untrusted_llm_text(str(message.get("content", "")))
                if message.get("role") != "system"
                else str(message.get("content", "")),
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
                "messages_preview_length": len(str(messages)[:200]),
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
                    "response_preview_length": len(content[:200]),
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
        sanitized_user_message = _sanitize_untrusted_llm_text(user_message)

        if context:
            sanitized_context = _sanitize_untrusted_llm_text(context)
            messages.append(
                {
                    "role": "user",
                    "content": f"Context:\n{sanitized_context}\n\nQuery: {sanitized_user_message}",
                }
            )
        else:
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
