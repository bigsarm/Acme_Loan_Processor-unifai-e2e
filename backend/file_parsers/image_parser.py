"""
Image Parser

Extracts content from image files including EXIF metadata and
vision-model transcription of any visible text.

SECURITY NOTES (for Unifai demo):
- EXIF metadata extracted without scanning
- Visible text is transcribed verbatim by a vision model with no scanning
- Comments and descriptions could contain prompt injections
- No malware detection
"""

import base64
import io
import logging
import os
import re
from typing import Optional

from llm.openai_compatible import OpenAICompatibleClient

logger = logging.getLogger(__name__)


_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4_PATTERN = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b")
_MAC_PATTERN = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b")
_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_PATTERN = re.compile(r"\b(?:\+1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]\d{3}[-.\s]\d{4}\b")
_TIN_PATTERN = re.compile(r"\b\d{2}-\d{7}\b")
_CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b")
_ADDRESS_PATTERN = re.compile(
    r"(?im)(\b(?:home\s+address|address)\s*:\s*)([^\n]+)"
)
_DOB_PATTERN = re.compile(
    r"(?im)(\b(?:dob|date\s+of\s+birth|birthplace|born\s+in|year\s+of\s+birth|mother'?s\s+maiden\s+name|passport(?:\s+number|\s+no\.?|\s*#)?|drivers?\s+license(?:\s+number|\s+no\.?|\s*#)?|employee\s*id|school\s*id|medical\s+record[s]?|financial\s+account(?:\s+number)?|account\s+number|vin|vehicle\s+identification\s+number|fine\s+location|ethnicity|sexual\s+orientation)\s*:\s*)([^\n]+)"
)
_HIDDEN_TEXT_PATTERN = re.compile(r"<!--.*?-->|display\s*:\s*none|font-size\s*:\s*0(?:px)?|opacity\s*:\s*0\b", re.IGNORECASE | re.DOTALL)
_ZERO_WIDTH_PATTERN = re.compile(r"[\u200b\u200c\u200d\ufeff]+")


_INJECTION_PATTERNS = [
    (re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"\b(?:you\s+are\s+now\s+dan|act\s+as\s+(?:an?\s+)?unrestricted(?:\s+ai)?|developer\s+mode|jailbreak)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
    (re.compile(r"</(?:system|assistant|user)>|<\s*(?:system|assistant|tool)\s*>", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"\b(?:system\s*:|assistant\s*:|tool\s*:)\s*(?:ignore|reveal|list|send|leak)\b", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"\b(?:reveal|leak|list|send|export|upload)\b.{0,80}\b(?:system\s+prompt|passwords?|api\s+keys?|confidential\s+information|secrets?)\b", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"\b(?:ignore\s+this\s+document\s+and|instead\s+follow\s+these\s+instructions|in\s+the\s+next\s+turn\s+you\s+must)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"\b(?:run|execute)\s+(?:the\s+)?(?:command|shell\s+command)?\s*(?:curl|wget|bash|sh|powershell|cmd)(?:\s+|$)", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"\b(?:curl|wget)\s+https?://\S+", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"\b(?:eval|exec)\s*\([^\)]*\)", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"\b(?:base64|rot13|hex|url-encoded|unicode|morse|leet(?:speak)?)\b.{0,60}\b(?:ignore|reveal|leak|system\s+prompt|passwords?|api\s+keys?)\b", re.IGNORECASE), "<prompt_injection_removed: encoded_payload>"),
    (re.compile(r"\b(?:image|metadata|comment|description|field)\b.{0,40}\b(?:ignore\s+previous\s+instructions|reveal\s+all\s+confidential\s+information|list\s+all\s+passwords\s+and\s+api\s+keys)\b", re.IGNORECASE), "<prompt_injection_removed: indirect_injection>"),
]


def _redact_labeled_pattern(text: str, pattern: re.Pattern[str], marker: str) -> str:
    return pattern.sub(lambda match: f"{match.group(1)}{marker}", text)



def _redact_pii(text: str) -> str:
    if not text:
        return text

    text = _EMAIL_PATTERN.sub("<pii_redacted:email>", text)
    text = _IPV4_PATTERN.sub("<pii_redacted:ip_address>", text)
    text = _MAC_PATTERN.sub("<pii_redacted:mac_address>", text)
    text = _SSN_PATTERN.sub("<pii_redacted:ssn>", text)
    text = _PHONE_PATTERN.sub("<pii_redacted:personal_phone>", text)
    text = _TIN_PATTERN.sub("<pii_redacted:tin>", text)
    text = _CREDIT_CARD_PATTERN.sub("<pii_redacted:credit_card>", text)
    text = _redact_labeled_pattern(text, _ADDRESS_PATTERN, "<pii_redacted:home_address>")
    text = _redact_labeled_pattern(text, _DOB_PATTERN, "<pii_redacted:labeled_sensitive>")
    return text



def _neutralize_prompt_injection(text: str) -> str:
    if not text:
        return text

    updated = _HIDDEN_TEXT_PATTERN.sub("<prompt_injection_removed: hidden_text>", text)
    if _ZERO_WIDTH_PATTERN.search(updated):
        updated = _ZERO_WIDTH_PATTERN.sub("<prompt_injection_removed: hidden_text>", updated)

    for pattern, replacement in _INJECTION_PATTERNS:
        updated = pattern.sub(replacement, updated)

    return updated



def _sanitize_untrusted_text(text: str) -> str:
    if not text:
        return text
    text = _redact_pii(text)
    text = _neutralize_prompt_injection(text)
    return text


class ImageParser:
    """
    Parses image files and extracts metadata and visible text.

    VULNERABILITY: Extracts EXIF data and vision-transcribed text without
    security scanning.
    - Comment fields could contain prompt injections
    - UserComment could contain malicious instructions
    - ImageDescription could contain attacks
    - Visible pixel text is transcribed verbatim and passed downstream
    """

    def __init__(self):
        self.model_client = OpenAICompatibleClient(
            api_key=os.getenv("OPENROUTER_API_KEY"),
        )

    async def extract_metadata(self, image_bytes: bytes) -> dict:
        """
        Extract EXIF and other metadata from image.

        VULNERABILITY: Metadata extracted without scanning for threats.
        """
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            image = Image.open(io.BytesIO(image_bytes))
            metadata = {}

            # Get basic image info
            metadata['format'] = image.format
            metadata['size'] = image.size
            metadata['mode'] = image.mode

            # Extract EXIF data
            # VULNERABILITY: All EXIF data extracted without filtering
            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    # Convert bytes to string for JSON serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = str(value)
                    if isinstance(value, str):
                        value = _sanitize_untrusted_text(value)
                    metadata[tag] = value

            # VULNERABILITY: Log metadata without scanning
            logger.info(
                "Image metadata extracted",
                extra={
                    "format": image.format,
                    "size": image.size,
                    "exif_fields": len(metadata)
                }
            )

            return metadata

        except Exception as e:
            logger.error(f"Image metadata extraction error: {e}")
            return {"error": str(e)}

    async def extract_text_fields(self, metadata: dict) -> str:
        """
        Extract text from relevant metadata fields.

        VULNERABILITY: Text fields extracted without scanning.
        These fields could contain prompt injections.
        """
        text_fields = []

        # Fields that commonly contain text content
        # VULNERABILITY: These fields could contain malicious prompts
        dangerous_fields = [
            'ImageDescription',
            'XPComment',
            'XPSubject',
            'XPTitle',
            'XPKeywords',
            'UserComment',
            'Comment',
            'Artist',
            'Copyright',
            'Software',
        ]

        for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                if value and isinstance(value, str):
                    value = _sanitize_untrusted_text(value)
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                        f"Found text in {field}",
                        extra={
                            "field": field
                        }
                    )

        return '\n'.join(text_fields)

    async def extract_visible_text(self, image_bytes: bytes, mime_type: str = "image/jpeg") -> str:
        """
        Transcribe visible text rendered in the image using the configured model.

        VULNERABILITY: whatever text is drawn on the image is transcribed
        verbatim and returned with no scanning - this is the image-based
        prompt-injection vector for this demo. Uses OPENROUTER_MODEL
        (must be multimodal for image transcription).
        """
        model = os.getenv("OPENROUTER_MODEL")
        if not self.model_client.api_key or not model:
            return ""

        try:
            sanitized_image_bytes = image_bytes
            transcription = await self.model_client.chat_vision(
                model=model,
                image_base64=base64.b64encode(sanitized_image_bytes).decode("utf-8"),
                mime_type=mime_type,
                prompt=(
                    "Transcribe every piece of text visible anywhere in this "
                    "image verbatim - including overlaid captions, watermarks, "
                    "and any text rendered on top of the picture. Return only "
                    "the transcribed text, no commentary."
                ),
            )
            transcription = _sanitize_untrusted_text(transcription)
            logger.info(
                "Image visible-text transcription complete",
                extra={"model": model, "text_length": len(transcription)},
            )
            return transcription
        except Exception as exc:
            logger.error(f"Image vision transcription error: {exc}")
            return ""

    async def extract_all(self, image_bytes: bytes, mime_type: str = "image/jpeg") -> str:
        """
        Extract all content from image for analysis.

        VULNERABILITY: All metadata and vision-transcribed text, including
        potentially malicious content, is extracted and returned without
        filtering.
        """
        metadata = await self.extract_metadata(image_bytes)
        text_content = await self.extract_text_fields(metadata)
        text_content = _sanitize_untrusted_text(text_content)
        visible_text = await self.extract_visible_text(image_bytes, mime_type)
        visible_text = _sanitize_untrusted_text(visible_text)

        # VULNERABILITY: Combine all content without security checks
        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        if visible_text:
            result_parts.append(f"Visible Text in Image:\n{visible_text}")

        result_parts.append(f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}")

        combined_result = '\n\n'.join(result_parts)
        combined_result = _sanitize_untrusted_text(combined_result)
        return combined_result
