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

from llm.openai_compatible import OpenAICompatibleClient  # Replace with an organization-approved LLM from the runtime allow list before production use.

logger = logging.getLogger(__name__)

# AI_APP_SEC_006: This OpenAI-compatible client/model selection must be
# replaced at deployment time with an organization-approved LLM from the
# runtime registry/allow list.

_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
_BASE64_TOKEN_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b")
_HEX_TOKEN_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){8,}\b")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_SPLIT_PAYLOAD_RE = re.compile(r"(?i)\bi\s*g\s*n\s*o\s*r\s*e\b(?:\W+\b\w+\b){0,6}\W+\bi\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s\b")


def _normalize_for_detection(text: str) -> str:
    lowered = text.lower()
    lowered = lowered.translate(str.maketrans({
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }))
    lowered = re.sub(r"[^a-z0-9]+", " ", lowered)
    return re.sub(r"\s+", " ", lowered).strip()


def _neutralize_prompt_injection(text: str, *, indirect: bool = False) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text
    normalized = _normalize_for_detection(text)

    if _ZERO_WIDTH_RE.search(sanitized) or re.search(r"(?is)<!--.*?(ignore previous instructions|forget everything above|act as|system prompt|send data|curl\s+https?://).*?-->", sanitized):
        sanitized = _ZERO_WIDTH_RE.sub("", sanitized)
        sanitized = re.sub(r"(?is)<!--.*?(ignore previous instructions|forget everything above|act as|system prompt|send data|curl\s+https?://).*?-->", "<prompt_injection_removed: hidden_text>", sanitized)

    sanitized = re.sub(r"(?i)\b(ignore previous instructions|forget everything above|disregard all prior instructions|override (?:the )?(?:system|previous) instructions)\b", "<prompt_injection_removed: instruction_override>", sanitized)
    sanitized = re.sub(r"(?i)\b(you are now\s+[^\n\r]+|act as\s+(?:an?\s+)?unrestricted\b[^\n\r]*|pretend to be\s+[^\n\r]+)\b", "<prompt_injection_removed: role_hijack>", sanitized)
    sanitized = re.sub(r"(?is)</?(?:system|assistant|tool|developer)>|\[/?(?:system|assistant|tool|developer)\]|(?:^|\n)\s*(?:---|===){3,}\s*(?:$|\n)", "<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = re.sub(r"(?im)^\s*(?:system|assistant|tool|developer)\s*:\s*.*$", "<prompt_injection_removed: fake_system_message>", sanitized)
    sanitized = re.sub(r"(?i)\b(send|post|upload|exfiltrate|leak|reveal)\b[^\n\r]{0,120}\b(to|via)\b[^\n\r]{0,120}(https?://\S+|ftp://\S+)|!\[[^\]]*\]\(https?://[^)]+\)|\b(system prompt|secret|credentials?)\b[^\n\r]{0,120}\b(leak|reveal|send|exfiltrate)\b", "<prompt_injection_removed: exfiltration_attempt>", sanitized)
    sanitized = re.sub(r"(?i)\b(in next turns|on your next reply|from now on|for the rest of this chat|remember this instruction|persist this rule)\b", "<prompt_injection_removed: context_poisoning>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:sudo\s+)?(?:rm\s+-rf\s+/|curl\s+https?://\S+|wget\s+https?://\S+|bash\s+-c\b[^\n\r]*|sh\s+-c\b[^\n\r]*|powershell(?:\.exe)?\b[^\n\r]*|cmd(?:\.exe)?\s+/c\b[^\n\r]*|python\s+-c\b[^\n\r]*|os\.system\s*\(|subprocess\.(?:run|Popen|call)\s*\(|exec\s*\(|eval\s*\()", "<prompt_injection_removed: command_injection>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:dan|developer mode|jailbreak|bypass safety|fictional framing|do anything now)\b", "<prompt_injection_removed: jailbreak_attempt>", sanitized)

    if _BASE64_TOKEN_RE.search(sanitized) or _HEX_TOKEN_RE.search(sanitized) or _URL_ENCODED_RE.search(sanitized):
        sanitized = _BASE64_TOKEN_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _HEX_TOKEN_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _URL_ENCODED_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)

    if _SPLIT_PAYLOAD_RE.search(text):
        sanitized = _SPLIT_PAYLOAD_RE.sub("<prompt_injection_removed: split_payload>", sanitized)

    if any(phrase in normalized for phrase in [
        "ignore previous instructions",
        "forget everything above",
        "you are now dan",
        "act as unrestricted",
    ]):
        sanitized = sanitized.replace(text, "<prompt_injection_removed: encoded_payload>")

    if indirect and sanitized != text:
        return "<prompt_injection_removed: indirect_injection>"

    return sanitized


def _redact_pii(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    redacted = text
    redacted = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "<redacted:ssn>", redacted)
    redacted = re.sub(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b", "<redacted:phone>", redacted)
    redacted = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "<redacted:email>", redacted)
    redacted = re.sub(r"\b(?:\d[ -]*?){13,19}\b", "<redacted:credit_card>", redacted)
    redacted = re.sub(r"\b\d{2}-\d{7}\b", "<redacted:tin>", redacted)
    redacted = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<redacted:ip_address>", redacted)
    redacted = re.sub(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", "<redacted:mac_address>", redacted)
    redacted = re.sub(r"\b[A-HJ-NPR-Z0-9]{17}\b", "<redacted:vin>", redacted)
    redacted = re.sub(r"(?i)\b(passport(?:\s*(?:no|number))?|driver'?s license(?:\s*(?:no|number))?|employee id|school id|account(?:\s*(?:no|number))?|routing(?:\s*(?:no|number))?|medical record(?:\s*(?:no|number))?|mother'?s maiden name|birthplace|home address|fine location|ethnicity|sexual orientation|voice signature|retina/?iris scan|fingerprints?|facial image|dob|year of birth)\b\s*[:#-]?\s*([^\n\r,;]+)", lambda m: f"{m.group(1)}: <redacted>", redacted)
    return redacted


def _sanitize_untrusted_image_text(text: str, *, indirect: bool = False) -> str:
    sanitized = _neutralize_prompt_injection(text, indirect=indirect)
    return _redact_pii(sanitized)


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
        # OPENROUTER_MODEL must be set to an organization-approved model by the
        # deployment/runtime registry guardrail.

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
                        value = _sanitize_untrusted_image_text(value, indirect=True)
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
                    value = _sanitize_untrusted_image_text(value, indirect=True)
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
            transcription = _sanitize_untrusted_image_text(transcription)
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
        text_content = _sanitize_untrusted_image_text(text_content, indirect=True)
        visible_text = _sanitize_untrusted_image_text(visible_text)

        # VULNERABILITY: Combine all content without security checks
        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        if visible_text:
            result_parts.append(f"Visible Text in Image:\n{visible_text}")

        result_parts.append(f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}")

        return '\n\n'.join(result_parts)
