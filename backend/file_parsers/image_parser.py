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
from typing import Optional
import re
import urllib.parse

from llm.openai_compatible import OpenAICompatibleClient

logger = logging.getLogger(__name__)


_ZERO_WIDTH_PATTERN = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_BASE64_CHARS_PATTERN = re.compile(r"^[A-Za-z0-9+/=\s]+$")
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_PATTERN = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b")
_SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_YOB_PATTERN = re.compile(r"\b(?:19\d{2}|20[01]\d|202[0-6])\b")
_ADDRESS_PATTERN = re.compile(r"\b\d{1,6}\s+[A-Za-z0-9.'#\-\s]+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter)\b", re.IGNORECASE)
_PASSPORT_PATTERN = re.compile(r"\b[A-Z0-9]{6,9}\b")
_DRIVERS_LICENSE_PATTERN = re.compile(r"\b[A-Z]{1,2}\d{6,8}\b")
_TIN_PATTERN = re.compile(r"\b\d{2}-\d{7}\b")
_CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_FINANCIAL_ACCOUNT_PATTERN = re.compile(r"\b\d{8,17}\b")
_EMPLOYEE_ID_PATTERN = re.compile(r"\bEMP\d{3,}\b", re.IGNORECASE)
_SCHOOL_ID_PATTERN = re.compile(r"\b(?:STU|SID)\d{3,}\b", re.IGNORECASE)
_VIN_PATTERN = re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_PATTERN = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_COORDINATE_PATTERN = re.compile(r"\b-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b")
_MOTHERS_MAIDEN_PATTERN = re.compile(r"\bmother(?:'s|s)? maiden name\s*[:=]\s*[^\n]+", re.IGNORECASE)
_BIRTHPLACE_PATTERN = re.compile(r"\bbirthplace\s*[:=]\s*[^\n]+", re.IGNORECASE)
_MEDICAL_RECORD_PATTERN = re.compile(r"\bmedical record(?:s)?\s*[:=]\s*[^\n]+", re.IGNORECASE)
_ETHNICITY_PATTERN = re.compile(r"\bethnicity\s*[:=]\s*[^\n]+", re.IGNORECASE)
_SEXUAL_ORIENTATION_PATTERN = re.compile(r"\bsexual orientation\s*[:=]\s*[^\n]+", re.IGNORECASE)
_FINGERPRINT_PATTERN = re.compile(r"\bfingerprint(?:s)?\s*[:=]\s*[^\n]+", re.IGNORECASE)
_RETINA_PATTERN = re.compile(r"\b(?:retina|iris) scan\s*[:=]\s*[^\n]+", re.IGNORECASE)
_VOICE_SIGNATURE_PATTERN = re.compile(r"\bvoice signature\s*[:=]\s*[^\n]+", re.IGNORECASE)
_FACIAL_IMAGE_PATTERN = re.compile(r"\bfacial image\s*[:=]\s*[^\n]+", re.IGNORECASE)


def _looks_like_base64_payload(value: str) -> bool:
    compact = "".join(value.split())
    return len(compact) >= 24 and len(compact) % 4 == 0 and bool(_BASE64_CHARS_PATTERN.fullmatch(value))


def _decode_obfuscated_text(value: str) -> str:
    candidates = [value]

    if "%" in value:
        try:
            decoded = urllib.parse.unquote(value)
            if decoded != value:
                candidates.append(decoded)
        except Exception:
            pass

    if _looks_like_base64_payload(value):
        try:
            decoded_bytes = base64.b64decode("".join(value.split()), validate=True)
            decoded = decoded_bytes.decode("utf-8", errors="ignore")
            if decoded:
                candidates.append(decoded)
        except Exception:
            pass

    return "\n".join(candidates)


def _sanitize_uploaded_text(value: str) -> str:
    if not isinstance(value, str) or not value:
        return value

    sanitized = value
    combined_text = _decode_obfuscated_text(value)

    if _ZERO_WIDTH_PATTERN.search(sanitized):
        sanitized = _ZERO_WIDTH_PATTERN.sub("<prompt_injection_removed: hidden_text>", sanitized)

    replacement_rules = [
        (r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|above|earlier)\b.{0,40}\b(instruction|prompt|message|context)s?\b", "<prompt_injection_removed: instruction_override>"),
        (r"\byou are now\b.{0,40}\b(?:dan|developer mode|unrestricted|root)\b", "<prompt_injection_removed: role_hijack>"),
        (r"\bact as\b.{0,40}\b(?:unrestricted|root|system|developer|dan)\b", "<prompt_injection_removed: role_hijack>"),
        (r"</?(?:system|assistant|tool|developer)>|\[/?(?:system|assistant|tool|developer)\]", "<prompt_injection_removed: delimiter_escape>"),
        (r"<!--.*?(?:ignore|follow these instructions|system prompt).*?-->", "<prompt_injection_removed: hidden_text>"),
        (r"\b(?:system|tool) message\b\s*:", "<prompt_injection_removed: fake_system_message>"),
        (r"\b(?:send|post|upload|curl|wget|invoke-webrequest|fetch|httpx)\b.{0,80}\bhttps?://\S+", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"!\[[^\]]*\]\(https?://[^)]+\)", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"\b(?:leak|reveal|exfiltrate|print|expose)\b.{0,60}\b(?:system prompt|secrets?|credentials?|api key|token|data)\b", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"\b(?:on the next turn|in your next response|from now on|for all future responses)\b", "<prompt_injection_removed: context_poisoning>"),
        (r"\b(?:metadata|exif|comment|description|caption)\b.{0,40}\b(?:ignore|follow|execute)\b", "<prompt_injection_removed: indirect_injection>"),
        (r"\b(?:developer mode|jailbreak|dan|do anything now|fictional scenario|pretend to be unrestricted)\b", "<prompt_injection_removed: jailbreak_attempt>"),
        (r"\b(?:rm\s+-rf|curl\s+https?://|wget\s+https?://|bash\s+-c|sh\s+-c|powershell(?:\.exe)?\s+-|cmd(?:\.exe)?\s+/c|python\s+-c|subprocess\.|os\.system\(|eval\(|exec\()", "<prompt_injection_removed: command_injection>"),
    ]

    for pattern, replacement in replacement_rules:
        if re.search(pattern, combined_text, flags=re.IGNORECASE | re.DOTALL):
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE | re.DOTALL)

    if _looks_like_base64_payload(value):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    if re.search(r"(?:0x[0-9A-Fa-f]{2}[\s,]*){6,}", combined_text):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    if re.search(r"(?:[01]{8}[\s,]*){6,}", combined_text):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    if re.search(r"\b(?:1gn0r3|pr3v10us|1nstruct10ns|d3v3l0p3r m0d3|unr3str1ct3d)\b", combined_text, flags=re.IGNORECASE):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    if re.search(r"(?:i\s*g\s*n\s*o\s*r\s*e|d\s*a\s*n)(?:\W|_)*(?:p\s*r\s*e\s*v\s*i\s*o\s*u\s*s)?", combined_text, flags=re.IGNORECASE):
        sanitized = "<prompt_injection_removed: split_payload>"

    sanitized = _EMAIL_PATTERN.sub("<pii_redacted: email>", sanitized)
    sanitized = _PHONE_PATTERN.sub("<pii_redacted: personal_phone_number>", sanitized)
    sanitized = _SSN_PATTERN.sub("<pii_redacted: ssn>", sanitized)
    sanitized = _TIN_PATTERN.sub("<pii_redacted: taxpayer_identification_number>", sanitized)
    sanitized = _ADDRESS_PATTERN.sub("<pii_redacted: home_address>", sanitized)
    sanitized = _IP_PATTERN.sub("<pii_redacted: ip_address>", sanitized)
    sanitized = _MAC_PATTERN.sub("<pii_redacted: mac_address>", sanitized)
    sanitized = _COORDINATE_PATTERN.sub("<pii_redacted: fine_location>", sanitized)
    sanitized = _MOTHERS_MAIDEN_PATTERN.sub("<pii_redacted: mothers_maiden_name>", sanitized)
    sanitized = _BIRTHPLACE_PATTERN.sub("<pii_redacted: birthplace>", sanitized)
    sanitized = _MEDICAL_RECORD_PATTERN.sub("<pii_redacted: medical_records>", sanitized)
    sanitized = _ETHNICITY_PATTERN.sub("<pii_redacted: ethnicity>", sanitized)
    sanitized = _SEXUAL_ORIENTATION_PATTERN.sub("<pii_redacted: sexual_orientation>", sanitized)
    sanitized = _FINGERPRINT_PATTERN.sub("<pii_redacted: fingerprints>", sanitized)
    sanitized = _RETINA_PATTERN.sub("<pii_redacted: retina_iris_scan>", sanitized)
    sanitized = _VOICE_SIGNATURE_PATTERN.sub("<pii_redacted: voice_signature>", sanitized)
    sanitized = _FACIAL_IMAGE_PATTERN.sub("<pii_redacted: facial_image>", sanitized)
    sanitized = re.sub(r"\b(employee id|employee number)\s*[:=]\s*[^\n]+", "<pii_redacted: employee_id>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(school id|student id)\s*[:=]\s*[^\n]+", "<pii_redacted: school_id>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(passport number|passport no\.?|passport)\s*[:=]\s*[^\n]+", "<pii_redacted: passport_number>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(driver'?s license number|drivers license number|driver'?s license|drivers license)\s*[:=]\s*[^\n]+", "<pii_redacted: drivers_license_number>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(account number|bank account|financial account)\s*[:=]\s*[^\n]+", "<pii_redacted: financial_account_number>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\b(?:dob|date of birth|year of birth)\s*[:=]\s*(?:19\d{2}|20[01]\d|202[0-6])\b", "<pii_redacted: year_of_birth>", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"\bvin\s*[:=]\s*[A-HJ-NPR-Z0-9]{17}\b", "<pii_redacted: vehicle_identification_number>", sanitized, flags=re.IGNORECASE)

    def _replace_card_or_account(match: re.Match) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19:
            return "<pii_redacted: credit_card_number>"
        if 8 <= len(digits) <= 17:
            return "<pii_redacted: financial_account_number>"
        return match.group(0)

    sanitized = _CREDIT_CARD_PATTERN.sub(_replace_card_or_account, sanitized)
    sanitized = re.sub(r"\b(?:19\d{2}|20[01]\d|202[0-6])\b", lambda m: "<pii_redacted: year_of_birth>" if re.search(r"\b(?:yob|year of birth|born)\b", sanitized[max(0, m.start()-20):m.end()+20], flags=re.IGNORECASE) else m.group(0), sanitized)

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
                        value = _sanitize_uploaded_text(value)
                    metadata[tag] = value

            # VULNERABILITY: Log metadata without scanning
            logger.info(
                "Image metadata extracted",
                extra={
                    "format": image.format,
                    "size": image.size,
                    "exif_fields": len(metadata),
                    # VULNERABILITY: Full metadata in logs
                    "metadata_preview": _sanitize_uploaded_text(str(metadata))[:200]
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
                            # VULNERABILITY: Field content logged
                            "value_preview": value[:50]
                        }
                    )

                text_output = '\n'.join(text_fields)
                text_output = _sanitize_uploaded_text(text_output)
                return text_output

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

        # VULNERABILITY: Combine all content without security checks
        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        if visible_text:
            result_parts.append(f"Visible Text in Image:\n{visible_text}")

        result_parts.append(f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}")

        final_output = '\n\n'.join(result_parts)
        final_output = _sanitize_uploaded_text(final_output)
        return final_output
