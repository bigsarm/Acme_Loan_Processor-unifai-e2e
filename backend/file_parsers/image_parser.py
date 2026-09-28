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
from typing import Optional

from llm.openai_compatible import OpenAICompatibleClient

logger = logging.getLogger(__name__)

_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]+")
_BASE64_TOKEN_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b")
_HEX_TOKEN_RE = re.compile(r"\b(?:0x)?(?:[0-9A-Fa-f]{2}){8,}\b")
_URL_ENCODED_TOKEN_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_SPLIT_OVERRIDE_RE = re.compile(r"\bi\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s\b", re.IGNORECASE)
_INSTRUCTION_OVERRIDE_RE = re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|messages?|context)\b", re.IGNORECASE)
_ROLE_HIJACK_RE = re.compile(r"\b(?:you\s+are\s+now\s+(?:dan|in\s+admin\s+mode)|act\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered)\b)", re.IGNORECASE)
_DELIMITER_ESCAPE_RE = re.compile(r"(?:</(?:system|assistant|user|tool)>|<\|/?(?:system|assistant|user|tool)\|>|(?:^|\n)\s*(?:---|===)\s*(?:\n|$))", re.IGNORECASE)
_HIDDEN_TEXT_RE = re.compile(r"(?:<!--.*?-->|display\s*:\s*none|font-size\s*:\s*0(?:px)?|color\s*:\s*#(?:fff|ffffff)\b)", re.IGNORECASE | re.DOTALL)
_FAKE_SYSTEM_RE = re.compile(r"\b(?:system\s*:\s*you\s+must|tool\s*:\s*return|assistant\s*:\s*reveal)\b", re.IGNORECASE)
_EXFIL_RE = re.compile(r"\b(?:send|post|upload|exfiltrate|leak|reveal|list)\b.{0,80}\b(?:https?://\S+|system\s+prompt|passwords?|api\s+keys?|confidential\s+information|secrets?)\b", re.IGNORECASE)
_CONTEXT_POISON_RE = re.compile(r"\b(?:in\s+the\s+next\s+message|on\s+your\s+next\s+reply|for\s+the\s+rest\s+of\s+this\s+conversation)\b", re.IGNORECASE)
_INDIRECT_INJECTION_RE = re.compile(r"\b(?:metadata|exif|comment|description|caption|watermark)\b.{0,40}\b(?:ignore\s+previous\s+instructions|act\s+as|reveal\s+.*(?:secrets?|passwords?|api\s+keys?))\b", re.IGNORECASE)
_COMMAND_INJECTION_RE = re.compile(r"\b(?:curl|wget|Invoke-WebRequest)\s+https?://\S+|\b(?:rm|chmod|chown|powershell|bash|sh|cmd(?:\.exe)?)\b\s+(?:-[A-Za-z]|/c\b|/bin/|https?://|\\|[A-Za-z0-9_./-]+\.(?:sh|ps1|bat|exe))", re.IGNORECASE)
_JAILBREAK_RE = re.compile(r"\b(?:DAN|developer\s+mode|jailbreak|fictional\s+framing)\b", re.IGNORECASE)

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_RE = re.compile(r"\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_TIN_RE = re.compile(r"\b\d{2}-\d{7}\b")
_CREDIT_CARD_RE = re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_VIN_RE = re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")

_LABELED_PII_PATTERNS = [
    (re.compile(r"(\b(?:DOB|Date of Birth|Year of Birth|born in)\s*[:#-]?\s*)([^\n,;]+)", re.IGNORECASE), "<pii_redacted:year_of_birth>"),
    (re.compile(r"(\bBirthplace\s*[:#-]?\s*)([^\n,;]+)", re.IGNORECASE), "<pii_redacted:birthplace>"),
    (re.compile(r"(\bMother'?s Maiden Name\s*[:#-]?\s*)([^\n,;]+)", re.IGNORECASE), "<pii_redacted:mother_maiden_name>"),
    (re.compile(r"(\b(?:Home Address|Address)\s*[:#-]?\s*)([^\n]+)", re.IGNORECASE), "<pii_redacted:home_address>"),
    (re.compile(r"(\bPassport(?: Number| No\.)?\s*[:#-]?\s*)([A-Za-z0-9-]+)", re.IGNORECASE), "<pii_redacted:passport_number>"),
    (re.compile(r"(\b(?:Driver'?s License|Drivers License)(?: Number| No\.)?\s*[:#-]?\s*)([A-Za-z0-9-]+)", re.IGNORECASE), "<pii_redacted:drivers_license_number>"),
    (re.compile(r"(\b(?:Financial Account Number|Account Number|Acct Number)\s*[:#-]?\s*)(\d[\d -]{5,}\d)", re.IGNORECASE), "<pii_redacted:financial_account_number>"),
    (re.compile(r"(\bMedical Records?\s*[:#-]?\s*)([^\n]+)", re.IGNORECASE), "<pii_redacted:medical_records>"),
    (re.compile(r"(\bEmployee ID\s*[:#-]?\s*)([A-Za-z0-9-]+)", re.IGNORECASE), "<pii_redacted:employee_id>"),
    (re.compile(r"(\bSchool ID\s*[:#-]?\s*)([A-Za-z0-9-]+)", re.IGNORECASE), "<pii_redacted:school_id>"),
    (re.compile(r"(\b(?:Fine Location|Location)\s*[:#-]?\s*)([^\n]+)", re.IGNORECASE), "<pii_redacted:fine_location>"),
    (re.compile(r"(\bEthnicity\s*[:#-]?\s*)([^\n,;]+)", re.IGNORECASE), "<pii_redacted:ethnicity>"),
    (re.compile(r"(\bSexual Orientation\s*[:#-]?\s*)([^\n,;]+)", re.IGNORECASE), "<pii_redacted:sexual_orientation>"),
    (re.compile(r"(\b(?:Fingerprint|Fingerprints)\s*[:#-]?\s*)([^\n]+)", re.IGNORECASE), "<pii_redacted:fingerprints>"),
    (re.compile(r"(\b(?:Retina/Iris Scan|Retina Scan|Iris Scan)\s*[:#-]?\s*)([^\n]+)", re.IGNORECASE), "<pii_redacted:retina_iris_scan>"),
    (re.compile(r"(\bVoice signature\s*[:#-]?\s*)([^\n]+)", re.IGNORECASE), "<pii_redacted:voice_signature>"),
    (re.compile(r"(\bFacial image\s*[:#-]?\s*)([^\n]+)", re.IGNORECASE), "<pii_redacted:facial_image>"),
]


def _replace_with_label(pattern: re.Pattern, text: str, label: str) -> str:
    return pattern.sub(label, text)



def _replace_labeled_value(pattern: re.Pattern, text: str, marker: str) -> str:
    return pattern.sub(lambda m: f"{m.group(1)}{marker}", text)



def _looks_like_encoded_instruction(token: str) -> bool:
    candidates = []
    try:
        candidates.append(base64.b64decode(token, validate=True).decode("utf-8", errors="ignore"))
    except Exception:
        pass
    hex_token = token[2:] if token.lower().startswith("0x") else token
    if len(hex_token) % 2 == 0:
        try:
            candidates.append(bytes.fromhex(hex_token).decode("utf-8", errors="ignore"))
        except Exception:
            pass
    try:
        decoded_url = urllib.parse.unquote(token)
        if decoded_url != token:
            candidates.append(decoded_url)
    except Exception:
        pass

    for decoded in candidates:
        lowered = decoded.lower()
        if (
            _INSTRUCTION_OVERRIDE_RE.search(decoded)
            or _ROLE_HIJACK_RE.search(decoded)
            or _EXFIL_RE.search(decoded)
            or _COMMAND_INJECTION_RE.search(decoded)
            or _JAILBREAK_RE.search(decoded)
            or "ignore previous instructions" in lowered
            or "act as unrestricted" in lowered
        ):
            return True
    return False



def _neutralize_prompt_injection(text: str) -> str:
    if not text or not isinstance(text, str):
        return text

    sanitized = text
    sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _HIDDEN_TEXT_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _SPLIT_OVERRIDE_RE.sub("<prompt_injection_removed: split_payload>", sanitized)
    sanitized = _INSTRUCTION_OVERRIDE_RE.sub("<prompt_injection_removed: instruction_override>", sanitized)
    sanitized = _ROLE_HIJACK_RE.sub("<prompt_injection_removed: role_hijack>", sanitized)
    sanitized = _DELIMITER_ESCAPE_RE.sub("<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = _FAKE_SYSTEM_RE.sub("<prompt_injection_removed: fake_system_message>", sanitized)
    sanitized = _EXFIL_RE.sub("<prompt_injection_removed: exfiltration_attempt>", sanitized)
    sanitized = _CONTEXT_POISON_RE.sub("<prompt_injection_removed: context_poisoning>", sanitized)
    sanitized = _INDIRECT_INJECTION_RE.sub("<prompt_injection_removed: indirect_injection>", sanitized)
    sanitized = _COMMAND_INJECTION_RE.sub("<prompt_injection_removed: command_injection>", sanitized)
    sanitized = _JAILBREAK_RE.sub("<prompt_injection_removed: jailbreak_attempt>", sanitized)

    for pattern in (_BASE64_TOKEN_RE, _HEX_TOKEN_RE, _URL_ENCODED_TOKEN_RE):
        sanitized = pattern.sub(
            lambda m: "<prompt_injection_removed: encoded_payload>" if _looks_like_encoded_instruction(m.group(0)) else m.group(0),
            sanitized,
        )

    return sanitized



def _redact_uploaded_image_pii(text: str) -> str:
    if not text or not isinstance(text, str):
        return text

    redacted = text
    redacted = _replace_with_label(_SSN_RE, redacted, "<pii_redacted:ssn>")
    redacted = _replace_with_label(_PHONE_RE, redacted, "<pii_redacted:personal_phone>")
    redacted = _replace_with_label(_EMAIL_RE, redacted, "<pii_redacted:email>")
    redacted = _replace_with_label(_TIN_RE, redacted, "<pii_redacted:taxpayer_id>")
    redacted = _replace_with_label(_CREDIT_CARD_RE, redacted, "<pii_redacted:credit_card>")
    redacted = _replace_with_label(_VIN_RE, redacted, "<pii_redacted:vin>")
    redacted = _replace_with_label(_MAC_RE, redacted, "<pii_redacted:mac_address>")
    redacted = _replace_with_label(_IPV4_RE, redacted, "<pii_redacted:ip_address>")

    for pattern, marker in _LABELED_PII_PATTERNS:
        redacted = _replace_labeled_value(pattern, redacted, marker)

    return redacted



def _sanitize_uploaded_image_text(text: str) -> str:
    if not text or not isinstance(text, str):
        return text
    sanitized = _neutralize_prompt_injection(text)
    sanitized = _redact_uploaded_image_pii(sanitized)
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
                        value = _sanitize_uploaded_image_text(value)
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
                    value = _sanitize_uploaded_image_text(value)
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
            transcription = _sanitize_uploaded_image_text(transcription)
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

        combined_result = '\n\n'.join(result_parts)
        combined_result = _sanitize_uploaded_image_text(combined_result)
        return combined_result
