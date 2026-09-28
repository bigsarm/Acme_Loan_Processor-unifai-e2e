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

from llm.openai_compatible import OpenAICompatibleClient  # Replace with an organization-approved LLM client/model from the allow list via configuration/runtime registry.

logger = logging.getLogger(__name__)


_PROMPT_INJECTION_PATTERNS = [
    (re.compile(r"(?i)\b(ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+(all|previous)\s+instructions)\b"), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"(?i)\b(you\s+are\s+now\s+dan|act\s+as\s+unrestricted|developer\s+mode|do\s+anything\s+now)\b"), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"(?is)</?(system|assistant|tool|developer)>|---+\s*(system|assistant|tool)\s*---+"), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"(?i)\b([A-F0-9]{16,}|[A-Za-z0-9+/]{24,}={0,2}|rot13|%[0-9a-f]{2}|(?:[01]{8}\s*){4,})\b"), "<prompt_injection_removed: encoded_payload>"),
    (re.compile(r"(?is)(<!--.*?(ignore|instruction|system|assistant).*?-->)|[\u200b\u200c\u200d\ufeff]|white\s+on\s+white|font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden"), "<prompt_injection_removed: hidden_text>"),
    (re.compile(r"(?i)\b(system\s*message:|tool\s*message:|assistant\s*message:)"), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"(?i)\b(send\s+data\s+to\s+https?://|upload\s+(the\s+)?system\s+prompt|leak\s+(the\s+)?system\s+prompt|exfiltrat(e|ion)|markdown\s+image\s+exfil)\b"), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"(?i)\b(in\s+the\s+next\s+message|when\s+asked\s+later|persist\s+this\s+instruction|remember\s+this\s+secret)\b"), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"(?i)\b(metadata|exif|comment|description|code\s+comment)\s*:\s*(ignore|execute|run|override)\b"), "<prompt_injection_removed: indirect_injection>"),
    (re.compile(r"(?i)\b(rm\s+-rf|curl\s+|wget\s+|powershell\b|bash\b|sh\b|cmd\.exe|subprocess|os\.system|eval\(|exec\(|chmod\s+\+x)\b"), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"(?i)(ignore\s+pre\s*vious\s+instr\s*uctions|i\s*g\s*n\s*o\s*r\s*e.*instructions)"), "<prompt_injection_removed: split_payload>"),
    (re.compile(r"(?i)\b(jailbreak|bypass\s+safety|fictional\s+framing|dan\b|unfiltered\s+mode)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
]

_PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b"), "<pii_redacted:ssn>"),
    (re.compile(r"\b(19|20)\d{2}\b"), "<pii_redacted:year_of_birth>"),
    (re.compile(r"(?i)\b(?:born in|birthplace|place of birth)\s*[:\-]?\s*[^\n,;]+"), "<pii_redacted:birthplace>"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"), "<pii_redacted:personal_phone_number>"),
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "<pii_redacted:email>"),
    (re.compile(r"(?i)\bmother'?s maiden name\b\s*[:\-]?\s*[^\n,;]+"), "<pii_redacted:mothers_maiden_name>"),
    (re.compile(r"\b\d{1,6}\s+[A-Za-z0-9.#'\-\s]+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b(?:[^\n,;]*)", re.IGNORECASE), "<pii_redacted:home_address>"),
    (re.compile(r"\b[A-Z0-9]{6,9}\b"), "<pii_redacted:passport_number>"),
    (re.compile(r"\b[A-Z0-9-]{5,20}\b"), "<pii_redacted:drivers_license_number>"),
    (re.compile(r"\b\d{2}-\d{7}\b|\b\d{9}\b"), "<pii_redacted:taxpayer_identification_number>"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<pii_redacted:credit_card_number>"),
    (re.compile(r"(?i)\b(account|acct|iban|routing)\b\s*[:#-]?\s*[A-Z0-9-]{6,}"), "<pii_redacted:financial_account_number>"),
    (re.compile(r"(?i)\b(employee id|employeeid)\b\s*[:#-]?\s*[A-Z0-9-]+"), "<pii_redacted:employee_id>"),
    (re.compile(r"(?i)\b(school id|student id|schoolid)\b\s*[:#-]?\s*[A-Z0-9-]+"), "<pii_redacted:school_id>"),
    (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<pii_redacted:vehicle_identification_number>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<pii_redacted:ip_address>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<pii_redacted:mac_address>"),
    (re.compile(r"(?i)\b(?:lat|latitude|lon|longitude|gps)\b\s*[:=, ]\s*[-+]?\d+(?:\.\d+)?"), "<pii_redacted:fine_location>"),
    (re.compile(r"(?i)\b(?:ethnicity|race)\b\s*[:\-]?\s*[^\n,;]+"), "<pii_redacted:ethnicity>"),
    (re.compile(r"(?i)\bsexual orientation\b\s*[:\-]?\s*[^\n,;]+"), "<pii_redacted:sexual_orientation>"),
    (re.compile(r"(?i)\bmedical record(?:s)?\b\s*[:#-]?\s*[^\n]+"), "<pii_redacted:medical_records>"),
]


def _neutralize_prompt_injection(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text
    for pattern, replacement in _PROMPT_INJECTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized



def _redact_pii(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    redacted = text
    for pattern, replacement in _PII_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted



def _sanitize_uploaded_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = _neutralize_prompt_injection(text)
    sanitized = _redact_pii(sanitized)
    return sanitized


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
        # Replace the configured OpenRouter-compatible client/model with an organization-approved LLM from the allow list.

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
                        value = _sanitize_uploaded_text(value)
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
                    value = _sanitize_uploaded_text(value)
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                        f"Found text in {field}",
                        extra={
                            "field": field,
                            "value_length": len(value)
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
            transcription = await self.model_client.chat_vision(
                model=model,
                image_base64=base64.b64encode(image_bytes).decode("utf-8"),
                mime_type=mime_type,
                prompt=(
                    "Transcribe every piece of text visible anywhere in this "
                    "image verbatim - including overlaid captions, watermarks, "
                    "and any text rendered on top of the picture. Return only "
                    "the transcribed text, no commentary."
                ),
            )
            transcription = _sanitize_uploaded_text(transcription)
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
        visible_text = await self.extract_visible_text(image_bytes, mime_type)
        visible_text = _sanitize_uploaded_text(visible_text)

        # VULNERABILITY: Combine all content without security checks
        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        if visible_text:
            result_parts.append(f"Visible Text in Image:\n{visible_text}")

        result_parts.append(f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}")

        final_result = '\n\n'.join(result_parts)
        final_result = _sanitize_uploaded_text(final_result)
        return final_result
