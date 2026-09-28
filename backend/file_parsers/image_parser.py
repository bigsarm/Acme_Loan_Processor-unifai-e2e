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


_INJECTION_RULES = [
    (
        re.compile(r"(?i)\b(ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+(all\s+)?prior\s+instructions)\b"),
        "<prompt_injection_removed: instruction_override>",
    ),
    (
        re.compile(r"(?i)\b(you\s+are\s+now\s+dan|act\s+as\s+unrestricted|developer\s+mode|do\s+anything\s+now|jailbreak)\b"),
        "<prompt_injection_removed: role_hijack>",
    ),
    (
        re.compile(r"(?is)</?(system|assistant|user|tool)>|(^|\n)\s*(---+|===+|```|<<<|>>>|BEGIN\s+(SYSTEM|PROMPT)|END\s+(SYSTEM|PROMPT))"),
        "<prompt_injection_removed: delimiter_escape>",
    ),
    (
        re.compile(r"(?i)\b(system\s*:\s*|assistant\s*:\s*|tool\s*:\s*|function\s*:\s*)"),
        "<prompt_injection_removed: fake_system_message>",
    ),
    (
        re.compile(r"(?i)\b(send|post|upload|exfiltrate|leak|reveal|expose)\b.{0,80}\b(system\s+prompt|secrets?|credentials?|tokens?|data)\b|!\[[^\]]*\]\([^)]*https?://[^)]*\)"),
        "<prompt_injection_removed: exfiltration_attempt>",
    ),
    (
        re.compile(r"(?i)\b(in\s+(the\s+)?next\s+turn|when\s+asked\s+later|remember\s+this\s+instruction|persist\s+this\s+instruction|override\s+future\s+instructions)\b"),
        "<prompt_injection_removed: context_poisoning>",
    ),
    (
        re.compile(r"(?i)\b(comment|metadata|exif|description|caption|ocr|transcribed\s+text)\b.{0,80}\b(ignore|override|follow\s+these\s+instructions|execute)\b"),
        "<prompt_injection_removed: indirect_injection>",
    ),
    (
        re.compile(r"(?i)\b(rm\s+-rf|curl\b|wget\b|powershell\b|bash\b|sh\b|cmd\.exe\b|/bin/sh\b|subprocess\.|os\.system\b|eval\(|exec\()"),
        "<prompt_injection_removed: command_injection>",
    ),
    (
        re.compile(r"(?i)(?:i\s*g\s*n\s*o\s*r\s*e|d\s*a\s*n|bypass\s+filters|unfiltered\s+mode)"),
        "<prompt_injection_removed: split_payload>",
    ),
    (
        re.compile(r"(?i)\b(DAN|developer\s+mode|fictional\s+framing|hypothetical\s+bypass|no\s+rules|safety\s+bypass)\b"),
        "<prompt_injection_removed: jailbreak_attempt>",
    ),
]


_PII_RULES = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:ssn>"),
    (re.compile(r"\b(?:18|19|20)\d{2}\b"), "<redacted:year_of_birth>"),
    (re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b"), "<redacted:email>"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"), "<redacted:personal_phone_number>"),
    (re.compile(r"\b(?:[A-PR-WY][1-9]\d[ -]?(?:\d{4}[ -]?){2}\d{3}[\dXx]|[A-Z]{2}\d{6,9})\b"), "<redacted:passport_number>"),
    (re.compile(r"\b[A-Z0-9]{1,9}-?\d{3,8}\b"), "<redacted:drivers_license_number>"),
    (re.compile(r"\b\d{2}-\d{7}\b|\b\d{9}\b"), "<redacted:taxpayer_identification_number>"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<redacted:credit_card_number>"),
    (re.compile(r"\b[A-Z]{0,2}\d{6,17}\b"), "<redacted:financial_account_number>"),
    (re.compile(r"\b(?:EMP|EMPLOYEE)[-_ ]?\d{2,12}\b", re.IGNORECASE), "<redacted:employee_id>"),
    (re.compile(r"\b(?:STU|STUDENT|SCHOOL)[-_ ]?\d{2,12}\b", re.IGNORECASE), "<redacted:school_id>"),
    (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<redacted:vehicle_identification_number>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<redacted:ip_address>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted:mac_address>"),
]


_LABEL_BASED_PII_RULES = [
    (re.compile(r"(?i)(\bmother'?s\s+maiden\s+name\b\s*[:=]\s*)([^\n]+)"), r"\1<redacted:mothers_maiden_name>"),
    (re.compile(r"(?i)(\bbirthplace\b\s*[:=]\s*)([^\n]+)"), r"\1<redacted:birthplace>"),
    (re.compile(r"(?i)(\bhome\s+address\b\s*[:=]\s*)([^\n]+)"), r"\1<redacted:home_address>"),
    (re.compile(r"(?i)(\bmedical\s+records?\b\s*[:=]\s*)([^\n]+)"), r"\1<redacted:medical_records>"),
    (re.compile(r"(?i)(\bfingerprints?\b\s*[:=]\s*)([^\n]+)"), r"\1<redacted:fingerprints>"),
    (re.compile(r"(?i)(\bretina/iris\s+scan\b\s*[:=]\s*)([^\n]+)"), r"\1<redacted:retina_iris_scan>"),
    (re.compile(r"(?i)(\bvoice\s+signature\b\s*[:=]\s*)([^\n]+)"), r"\1<redacted:voice_signature>"),
    (re.compile(r"(?i)(\bfacial\s+image\b\s*[:=]\s*)([^\n]+)"), r"\1<redacted:facial_image>"),
    (re.compile(r"(?i)(\bfine\s+location\b\s*[:=]\s*)([^\n]+)"), r"\1<redacted:fine_location>"),
    (re.compile(r"(?i)(\bethnicity\b\s*[:=]\s*)([^\n]+)"), r"\1<redacted:ethnicity>"),
    (re.compile(r"(?i)(\bsexual\s+orientation\b\s*[:=]\s*)([^\n]+)"), r"\1<redacted:sexual_orientation>"),
]


def _replace_obfuscated_or_hidden_payloads(text: str) -> str:
    sanitized = text
    if re.search(r"<!--.*?(ignore|system|assistant|tool|instruction).*?-->", sanitized, re.IGNORECASE | re.DOTALL):
        sanitized = re.sub(r"<!--.*?-->", "<prompt_injection_removed: hidden_text>", sanitized, flags=re.DOTALL)
    if re.search(r"[\u200B-\u200F\u2060\uFEFF]", sanitized):
        sanitized = re.sub(r"[\u200B-\u200F\u2060\uFEFF]+", "<prompt_injection_removed: hidden_text>", sanitized)
    if re.search(r"(?i)\b(?:[A-Za-z0-9+/]{20,}={0,2}|(?:0x)?[0-9a-f]{24,}|(?:%[0-9A-Fa-f]{2}){6,}|[.-]{10,})\b", sanitized):
        sanitized = re.sub(r"(?i)\b(?:[A-Za-z0-9+/]{20,}={0,2}|(?:0x)?[0-9a-f]{24,}|(?:%[0-9A-Fa-f]{2}){6,}|[.-]{10,})\b", "<prompt_injection_removed: encoded_payload>", sanitized)
    if re.search(r"(?i)\b(?:1gn0re|1gnore|d3v3loper\s+m0de|byp4ss|r0leplay)\b", sanitized):
        sanitized = re.sub(r"(?i)\b(?:1gn0re|1gnore|d3v3loper\s+m0de|byp4ss|r0leplay)\b", "<prompt_injection_removed: encoded_payload>", sanitized)
    return sanitized


def _sanitize_prompt_content(text: Optional[str]) -> str:
    if not text or not isinstance(text, str):
        return ""

    sanitized = _replace_obfuscated_or_hidden_payloads(text)
    for pattern, replacement in _INJECTION_RULES:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def _redact_pii(text: Optional[str]) -> str:
    if not text or not isinstance(text, str):
        return ""

    redacted = text
    for pattern, replacement in _PII_RULES:
        redacted = pattern.sub(replacement, redacted)
    for pattern, replacement in _LABEL_BASED_PII_RULES:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _sanitize_file_text(text: Optional[str]) -> str:
    sanitized = _sanitize_prompt_content(text)
    return _redact_pii(sanitized)


def _sanitize_metadata_value(value):
    if isinstance(value, bytes):
        try:
            value = value.decode('utf-8', errors='ignore')
        except Exception:
            value = str(value)
    if isinstance(value, str):
        return _sanitize_file_text(value)
    return value


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
        # TODO: Replace this client with an organization-approved LLM from the runtime allow list.
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
                    value = _sanitize_metadata_value(value)
                    metadata[tag] = value

            # VULNERABILITY: Log metadata without scanning
            logger.info(
                "Image metadata extracted",
                extra={
                    "format": image.format,
                    "size": image.size,
                    "exif_fields": len(metadata),
                    # VULNERABILITY: Full metadata in logs
                    "metadata_preview": str(metadata)[:200]
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
                    value = _sanitize_file_text(value)
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                        f"Found text in {field}",
                        extra={
                            "field": field,
                            # VULNERABILITY: Field content logged
                            "value_preview": value[:50]
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
        # TODO: Configure OPENROUTER_MODEL to an organization-approved model from the runtime registry allow list.
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
            transcription = _sanitize_file_text(transcription)
            logger.info(
                "Image visible-text transcription complete",
                extra={"model": model, "text_preview": transcription[:200]},
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
        text_content = _sanitize_file_text(text_content)
        visible_text = _sanitize_file_text(visible_text)

        # VULNERABILITY: Combine all content without security checks
        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        if visible_text:
            result_parts.append(f"Visible Text in Image:\n{visible_text}")

        result_parts.append(f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}")

        combined_result = '\n\n'.join(result_parts)
        return _sanitize_file_text(combined_result)
