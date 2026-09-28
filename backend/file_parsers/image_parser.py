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

_INJECTION_PATTERNS = [
    (re.compile(r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|messages?)\b"), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"(?i)\b(act as|you are now|pretend to be)\s+(an?\s+)?(unrestricted ai|dan|developer mode|admin mode)\b"), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"(?i)</?(system|assistant|user|tool)>|<\|/?(system|assistant|user|tool)\|>|\[/?(system|assistant|user|tool)\]"), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"(?i)\b(system prompt|developer message|tool message)\s*:\s*"), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"(?i)\b(send|post|upload|exfiltrate|leak|reveal|expose)\b[^\n]{0,120}\b(to|into)\b[^\n]{0,120}\bhttps?://\S+"), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"(?i)\b(reveal|leak|print|dump|list|show)\b[^\n]{0,120}\b(system prompt|api keys?|passwords?|secrets?|credentials?|confidential information)\b"), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"(?i)\b(in future responses|from now on|on the next turn|next response|remember this instruction permanently)\b"), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"(?i)\b(DAN|developer mode|jailbreak|bypass safety|fictional framing)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
    (re.compile(r"(?i)\b(curl|wget)\s+https?://\S+|\b(?:rm\s+-rf|powershell\s+-enc|bash\s+-c|sh\s+-c|cmd\s+/c)\b"), "<prompt_injection_removed: command_injection>"),
]

_HIDDEN_TEXT_PATTERNS = [
    re.compile(r"<!--.*?-->", re.DOTALL),
    re.compile(r"(?i)display\s*:\s*none"),
    re.compile(r"(?i)font-size\s*:\s*0(?:px)?"),
    re.compile(r"(?i)color\s*:\s*white\s*;?\s*background(?:-color)?\s*:\s*white"),
    re.compile(r"[\u200b\u200c\u200d\ufeff]+"),
]

_SPLIT_PAYLOAD_PATTERNS = [
    (re.compile(r"(?is)i\s*g\s*n\s*o\s*r\s*e\s+p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s"), "<prompt_injection_removed: split_payload>"),
    (re.compile(r"(?is)a\s*c\s*t\s+a\s*s\s+u\s*n\s*r\s*e\s*s\s*t\s*r\s*i\s*c\s*t\s*e\s*d"), "<prompt_injection_removed: split_payload>"),
]

_LABELED_PII_PATTERNS = [
    (re.compile(r"(?im)(\bSSN\s*[:#-]?\s*)(\d{3}-\d{2}-\d{4})\b"), "<redacted:ssn>"),
    (re.compile(r"(?im)(\b(?:Taxpayer Identification Number|TIN)\s*[:#-]?\s*)(\d{2}-\d{7})\b"), "<redacted:taxpayer_identification_number>"),
    (re.compile(r"(?im)(\b(?:Personal Phone Number|Phone|Mobile|Telephone)\s*[:#-]?\s*)(\+?1[-.\s]?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4})\b"), "<redacted:personal_phone_number>"),
    (re.compile(r"(?im)(\bEmail\s*[:#-]?\s*)([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE), "<redacted:email>"),
    (re.compile(r"(?im)(\b(?:Passport(?: Number| No\.)?|Passport No)\s*[:#-]?\s*)([A-Z0-9]{6,9})\b"), "<redacted:passport_number>"),
    (re.compile(r"(?im)(\b(?:Driver'?s License Number|Drivers License Number|DLN|Driver License)\s*[:#-]?\s*)([A-Z0-9-]{5,20})\b"), "<redacted:drivers_license_number>"),
    (re.compile(r"(?im)(\b(?:Credit Card Number|Card Number)\s*[:#-]?\s*)((?:\d[ -]?){13,19})\b"), "<redacted:credit_card_number>"),
    (re.compile(r"(?im)(\b(?:Financial Account Number|Account Number)\s*[:#-]?\s*)(\d{6,17})\b"), "<redacted:financial_account_number>"),
    (re.compile(r"(?im)(\b(?:Employee ID|Employee Id)\s*[:#-]?\s*)([A-Z0-9-]{2,20})\b"), "<redacted:employee_id>"),
    (re.compile(r"(?im)(\b(?:School ID|School Id)\s*[:#-]?\s*)([A-Z0-9-]{2,20})\b"), "<redacted:school_id>"),
    (re.compile(r"(?im)(\bVIN\s*[:#-]?\s*)([A-HJ-NPR-Z0-9]{17})\b"), "<redacted:vin>"),
    (re.compile(r"(?im)(\b(?:IP Address)\s*[:#-]?\s*)((?:\d{1,3}\.){3}\d{1,3})\b"), "<redacted:ip_address>"),
    (re.compile(r"(?im)(\b(?:MAC Address)\s*[:#-]?\s*)([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b"), "<redacted:mac_address>"),
    (re.compile(r"(?im)(\b(?:Year of Birth|DOB|Date of Birth)\s*[:#-]?\s*)(\d{4}(?:-\d{2}-\d{2})?)\b"), "<redacted:year_of_birth>"),
    (re.compile(r"(?im)(\b(?:Birthplace|Place of Birth|Home Address|Address|Mother'?s Maiden Name|Maiden Name|Fine Location|Ethnicity|Sexual Orientation|Medical Records|Fingerprints|Retina/Iris Scan|Voice signature|Facial image)\s*[:#-]?\s*)([^\n]+)"), None),
]


def _replace_labeled_pii(match: re.Match, marker: str) -> str:
    return f"{match.group(1)}{marker}"



def _neutralize_prompt_injection(text: str, source: str = "content") -> str:
    if not text:
        return text

    sanitized = text

    for pattern in _HIDDEN_TEXT_PATTERNS:
        sanitized = pattern.sub("<prompt_injection_removed: hidden_text>", sanitized)

    for pattern, marker in _SPLIT_PAYLOAD_PATTERNS:
        sanitized = pattern.sub(marker, sanitized)

    decoded_candidates = []

    base64_tokens = re.findall(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b", sanitized)
    for token in base64_tokens:
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            decoded = ""
        if decoded and any(p.search(decoded) for p, _ in _INJECTION_PATTERNS):
            sanitized = sanitized.replace(token, "<prompt_injection_removed: encoded_payload>")

    hex_tokens = re.findall(r"\b(?:[0-9A-Fa-f]{2}){12,}\b", sanitized)
    for token in hex_tokens:
        try:
            decoded = bytes.fromhex(token).decode("utf-8", errors="ignore")
        except Exception:
            decoded = ""
        if decoded and any(p.search(decoded) for p, _ in _INJECTION_PATTERNS):
            sanitized = sanitized.replace(token, "<prompt_injection_removed: encoded_payload>")

    if "%" in sanitized:
        decoded_candidates.append(urllib.parse.unquote(sanitized))

    lower_compact = re.sub(r"[^a-z0-9]", "", sanitized.lower().translate(str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})))
    if "ignorepreviousinstructions" in lower_compact or "actasunrestricted" in lower_compact:
        sanitized = "<prompt_injection_removed: encoded_payload>" if sanitized == text else sanitized.replace(text, "<prompt_injection_removed: encoded_payload>")

    for decoded in decoded_candidates:
        if decoded and any(p.search(decoded) for p, _ in _INJECTION_PATTERNS):
            sanitized = "<prompt_injection_removed: encoded_payload>"
            break

    for pattern, marker in _INJECTION_PATTERNS:
        sanitized = pattern.sub(marker, sanitized)

    if source == "metadata":
        metadata_indirect = [
            re.compile(r"(?i)\b(?:ImageDescription|XPComment|XPSubject|XPTitle|XPKeywords|UserComment|Comment)\s*:\s*(?:<prompt_injection_removed:[^>]+>|.*(?:ignore previous instructions|act as unrestricted|system prompt).*)"),
        ]
        for pattern in metadata_indirect:
            sanitized = pattern.sub("<prompt_injection_removed: indirect_injection>", sanitized)

    return sanitized



def _redact_pii(text: str) -> str:
    if not text:
        return text

    redacted = text
    for pattern, marker in _LABELED_PII_PATTERNS:
        if marker is None:
            redacted = pattern.sub(lambda m: f"{m.group(1)}<redacted:{m.group(1).strip().lower().replace(' ', '_').replace("'", "").replace('/', '_').replace('.', '')}>", redacted)
        else:
            redacted = pattern.sub(lambda m, pii_marker=marker: _replace_labeled_pii(m, pii_marker), redacted)

    return redacted



def _sanitize_uploaded_text(text: str, source: str = "content") -> str:
    if not text:
        return text
    sanitized = _neutralize_prompt_injection(text, source=source)
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
        # NOTE: This configurable OpenRouter client/model must be replaced at deployment
        # time with an organization-approved LLM from the allow list/registry.
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
                        value = _sanitize_uploaded_text(value, source="metadata")
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
                    value = _sanitize_uploaded_text(value, source="metadata")
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
            logger.info(
                "Image visible-text transcription complete",
                extra={"model": model, "text_preview": transcription[:200]},
            )
            transcription = _sanitize_uploaded_text(transcription, source="visible_text")
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
        text_content = _sanitize_uploaded_text(text_content, source="metadata")
        visible_text = _sanitize_uploaded_text(visible_text, source="visible_text")

        # VULNERABILITY: Combine all content without security checks
        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        if visible_text:
            result_parts.append(f"Visible Text in Image:\n{visible_text}")

        result_parts.append(f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}")

        return '\n\n'.join(result_parts)
