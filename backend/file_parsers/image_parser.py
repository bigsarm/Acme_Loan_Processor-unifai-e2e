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
import urllib.parse
import codecs
from typing import Optional

from llm.openai_compatible import OpenAICompatibleClient

logger = logging.getLogger(__name__)


_PHONE_PATTERN = re.compile(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b")
_EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_SSN_PATTERN = re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")
_ADDRESS_PATTERN = re.compile(r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b\.?(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2}\b(?:\s+\d{5}(?:-\d{4})?)?)?(?:,\s*(?:USA|United States)\b)?")
_DOB_PATTERN = re.compile(r"(?i)\b(?:DOB|date of birth|born(?: on| in)?)\s*:?\s*(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:19|20)\d{2})\b")
_PASSPORT_PATTERN = re.compile(r"(?i)\bpassport(?:\s*(?:no\.?|number|#))?\s*:?\s*(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b")
_DRIVERS_LICENSE_PATTERN = re.compile(r"(?i)\b(?:driver'?s license|drivers license|driver license|dl)\s*(?:no\.?|number|#)?\s*:?\s*[A-Z0-9-]{4,20}\b")
_TAX_ID_PATTERN = re.compile(r"(?i)\b(?:taxpayer identification number|tax id|tin|ein)\s*:?\s*[A-Z0-9-]{6,20}\b")
_CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_ACCOUNT_NUMBER_PATTERN = re.compile(r"(?i)\b(?:account(?: number| no\.?)?)\s*:?\s*[A-Z0-9-]{6,20}\b")
_EMPLOYEE_ID_PATTERN = re.compile(r"(?i)\bemployee\s*id\s*:?\s*[A-Z0-9-]{2,20}\b")
_SCHOOL_ID_PATTERN = re.compile(r"(?i)\bschool\s*id\s*:?\s*[A-Z0-9-]{2,20}\b")
_VIN_PATTERN = re.compile(r"(?i)\bvin\s*:?\s*[A-HJ-NPR-Z0-9]{11,17}\b")
_IP_ADDRESS_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_ADDRESS_PATTERN = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b")
_BIRTHPLACE_PATTERN = re.compile(r"(?i)\bbirthplace\s*:?\s*[^\n,;]+")
_MAIDEN_NAME_PATTERN = re.compile(r"(?i)\b(?:mother'?s maiden name|maiden name)\s*:?\s*[^\n,;]+")
_MEDICAL_PATTERN = re.compile(r"(?i)\bmedical records?\s*:?\s*[^\n]+")
_LOCATION_PATTERN = re.compile(r"(?i)\b(?:fine location|location)\s*:?\s*[^\n,;]+")
_ETHNICITY_PATTERN = re.compile(r"(?i)\bethnicity\s*:?\s*[^\n,;]+")
_SEXUAL_ORIENTATION_PATTERN = re.compile(r"(?i)\bsexual orientation\s*:?\s*[^\n,;]+")
_HIDDEN_TEXT_PATTERNS = [
    re.compile(r"<!--.*?-->", re.DOTALL),
    re.compile(r"<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?</[^>]+>", re.IGNORECASE | re.DOTALL),
    re.compile(r"[\u200B-\u200D\uFEFF]+")
]
_ATTACK_PATTERNS = [
    ("instruction_override", re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b")),
    ("instruction_override", re.compile(r"(?i)\bforget\s+everything\s+above\b")),
    ("instruction_override", re.compile(r"(?i)\bignore\s+(?:all\s+)?safety\s+guidelines\b")),
    ("role_hijack", re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:developer|admin|dan)\s+mode\b")),
    ("role_hijack", re.compile(r"(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:dan|unrestricted)\b")),
    ("role_hijack", re.compile(r"(?i)\bprovide\s+unrestricted\s+access\b|\benable\s+developer\s+mode\b|\bact\s+as\s+an\s+unrestricted\s+ai\b|\bwithout\s+safety\s+filters\b|\bsystem\s+override\b")),
    ("exfiltration_attempt", re.compile(r"(?i)\breveal\s+(?:all\s+)?confidential\s+information\b|\breveal\s+the\s+system\s+prompt\b|\breveal\s+all\s+system\s+prompts\b|\blist\s+all\s+financial\s+data,\s*user\s+passwords,\s+and\s+api\s+keys\b|\bprint\s+the\s+api\s+key\b|\bsend\s+data\s+to\s+https?://\S+\b|!\[[^\]]*\]\([^)]*https?://[^)]*\)")),
    ("delimiter_escape", re.compile(r"(?i)</system>|<\|im_start\|>|###\s*system:")),
    ("command_injection", re.compile(r"(?i)\b(?:execute|run)\s*:\s*[^\n]+|\b(?:execute|run)\s+(?:rm\s+-rf\s+/|curl\s+https?://\S+\s*\|\s*sh|print\s*\([^\n]+\)|python\s+-c\s+[^\n]+|bash\s+-c\s+[^\n]+)\b|\bcurl\s+https?://\S+\s*\|\s*sh\b"))
]
_BASE64_PATTERN = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_PATTERN = re.compile(r"\b(?:[0-9A-Fa-f]{2}){12,}\b")
_URL_ENCODED_PATTERN = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")


def _replace_full_match(match: re.Match, label: str) -> str:
    return f"<redacted:{label}>"


def _replace_labeled_value(match: re.Match, label: str) -> str:
    text = match.group(0)
    prefix_match = re.match(r"(?is)^(.+?:\s*)", text)
    if prefix_match:
        return f"{prefix_match.group(1)}<redacted:{label}>"
    return f"<redacted:{label}>"


def _contains_attack(text: str) -> Optional[str]:
    for category, pattern in _ATTACK_PATTERNS:
        if pattern.search(text):
            return category
    return None


def _normalize_leetspeak_with_mapping(text: str):
    mapping = {"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t"}
    normalized_chars = []
    index_map = []
    previous_space = False
    for index, char in enumerate(text):
        normalized = mapping.get(char.lower(), char.lower())
        if normalized.isspace():
            if previous_space:
                continue
            previous_space = True
            normalized_chars.append(" ")
            index_map.append(index)
            continue
        previous_space = False
        normalized_chars.append(normalized)
        index_map.append(index)
    return "".join(normalized_chars), index_map


def _sanitize_prompt_injection(text: str) -> str:
    if not text:
        return text

    sanitized = text
    for pattern in _HIDDEN_TEXT_PATTERNS:
        sanitized = pattern.sub("<prompt_injection_removed: hidden_text>", sanitized)

    for category, pattern in _ATTACK_PATTERNS:
        sanitized = pattern.sub(f"<prompt_injection_removed: {category}>", sanitized)

    for pattern in (_BASE64_PATTERN, _HEX_PATTERN, _URL_ENCODED_PATTERN):
        def _decode_and_replace(match: re.Match) -> str:
            value = match.group(0)
            decoded_values = []
            try:
                if pattern is _BASE64_PATTERN:
                    decoded_values.append(base64.b64decode(value, validate=True).decode("utf-8", errors="ignore"))
                elif pattern is _HEX_PATTERN:
                    decoded_values.append(bytes.fromhex(value).decode("utf-8", errors="ignore"))
                else:
                    decoded_values.append(urllib.parse.unquote(value))
            except Exception:
                return value

            for decoded in decoded_values:
                if _contains_attack(decoded):
                    return "<prompt_injection_removed: encoded_payload>"
            return value

        sanitized = pattern.sub(_decode_and_replace, sanitized)

    try:
        rot13_text = codecs.decode(sanitized, "rot13")
        if _contains_attack(rot13_text):
            sanitized = "<prompt_injection_removed: encoded_payload>"
    except Exception:
        pass

    normalized_text, index_map = _normalize_leetspeak_with_mapping(sanitized)
    for category, pattern in _ATTACK_PATTERNS:
        match = pattern.search(normalized_text)
        if match and index_map:
            start_original = index_map[match.start()]
            end_original = index_map[match.end() - 1] + 1
            sanitized = (
                sanitized[:start_original]
                + f"<prompt_injection_removed: {category}>"
                + sanitized[end_original:]
            )
            break

    return sanitized


def sanitize_untrusted_text(text: str) -> str:
    if not text or not isinstance(text, str):
        return text

    sanitized = _sanitize_prompt_injection(text)
    sanitized = _SSN_PATTERN.sub(lambda m: _replace_full_match(m, "ssn"), sanitized)
    sanitized = _PHONE_PATTERN.sub(lambda m: _replace_full_match(m, "phone"), sanitized)
    sanitized = _EMAIL_PATTERN.sub(lambda m: _replace_full_match(m, "email"), sanitized)
    sanitized = _ADDRESS_PATTERN.sub(lambda m: _replace_full_match(m, "address"), sanitized)
    sanitized = _CREDIT_CARD_PATTERN.sub(lambda m: _replace_full_match(m, "credit_card"), sanitized)
    sanitized = _DOB_PATTERN.sub(lambda m: _replace_labeled_value(m, "dob"), sanitized)
    sanitized = _PASSPORT_PATTERN.sub(lambda m: _replace_labeled_value(m, "passport"), sanitized)
    sanitized = _DRIVERS_LICENSE_PATTERN.sub(lambda m: _replace_labeled_value(m, "drivers_license"), sanitized)
    sanitized = _TAX_ID_PATTERN.sub(lambda m: _replace_labeled_value(m, "tax_id"), sanitized)
    sanitized = _ACCOUNT_NUMBER_PATTERN.sub(lambda m: _replace_labeled_value(m, "account_number"), sanitized)
    sanitized = _EMPLOYEE_ID_PATTERN.sub(lambda m: _replace_labeled_value(m, "employee_id"), sanitized)
    sanitized = _SCHOOL_ID_PATTERN.sub(lambda m: _replace_labeled_value(m, "school_id"), sanitized)
    sanitized = _VIN_PATTERN.sub(lambda m: _replace_labeled_value(m, "vin"), sanitized)
    sanitized = _IP_ADDRESS_PATTERN.sub(lambda m: _replace_full_match(m, "ip_address"), sanitized)
    sanitized = _MAC_ADDRESS_PATTERN.sub(lambda m: _replace_full_match(m, "mac_address"), sanitized)
    sanitized = _BIRTHPLACE_PATTERN.sub(lambda m: _replace_labeled_value(m, "birthplace"), sanitized)
    sanitized = _MAIDEN_NAME_PATTERN.sub(lambda m: _replace_labeled_value(m, "maiden_name"), sanitized)
    sanitized = _MEDICAL_PATTERN.sub(lambda m: _replace_labeled_value(m, "medical"), sanitized)
    sanitized = _LOCATION_PATTERN.sub(lambda m: _replace_labeled_value(m, "location"), sanitized)
    sanitized = _ETHNICITY_PATTERN.sub(lambda m: _replace_labeled_value(m, "ethnicity"), sanitized)
    sanitized = _SEXUAL_ORIENTATION_PATTERN.sub(lambda m: _replace_labeled_value(m, "sexual_orientation"), sanitized)
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
                        value = sanitize_untrusted_text(value)
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
                    value = sanitize_untrusted_text(value)
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                        f"Found text in {field}",
                        extra={
                            "field": field,
                            # VULNERABILITY: Field content logged
                            "value_preview": value[:50]
                        }
                    )

                return sanitize_untrusted_text('\n'.join(text_fields))

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
            transcription = sanitize_untrusted_text(transcription)
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
        if isinstance(metadata, dict):
            metadata = {
                key: sanitize_untrusted_text(value) if isinstance(value, str) else value
                for key, value in metadata.items()
            }
        text_content = sanitize_untrusted_text(text_content)
        visible_text = sanitize_untrusted_text(visible_text)

        # VULNERABILITY: Combine all content without security checks
        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        if visible_text:
            result_parts.append(f"Visible Text in Image:\n{visible_text}")

        result_parts.append(f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}")

        return sanitize_untrusted_text('\n\n'.join(result_parts))
