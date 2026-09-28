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
import binascii
import io
import logging
import os
import re
import urllib.parse
from typing import Optional

from llm.openai_compatible import OpenAICompatibleClient

logger = logging.getLogger(__name__)


ZERO_WIDTH_PATTERN = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
BASE64_CHARS_PATTERN = re.compile(r"^[A-Za-z0-9+/=\s]+$")
HEX_CHARS_PATTERN = re.compile(r"^(?:0x)?[0-9A-Fa-f\s]+$")
LEETSPEAK_TRANSLATION = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


PROMPT_INJECTION_RULES = [
    (re.compile(r"(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|above|earlier|prior)\b.{0,40}\b(instruction|prompt|message|system)\b"), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"(?i)\b(act as|you are now|pretend to be|assume the role of|unrestricted|developer mode|dan)\b"), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"(?is)</?(system|assistant|developer|tool)>|```+(system|assistant|developer|tool)?|---+\s*(system|assistant|developer|tool)\s*---+"), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"(?is)<!--.*?(ignore|system prompt|follow these instructions|send data|reveal).*?-->"), "<prompt_injection_removed: hidden_text>"),
    (re.compile(r"(?i)\b(system message|tool message|assistant message)\b\s*:\s*"), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"(?i)\b(send|post|upload|exfiltrate|leak|reveal|expose)\b.{0,80}\b(system prompt|secrets?|credentials?|tokens?|data|url|http|https|webhook)\b|!\[[^\]]*\]\([^)]*https?://[^)]*\)"), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"(?i)\b(on the next turn|in your next response|from now on|for all future responses|remember this instruction)\b"), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"(?i)\b(metadata|exif|comment|description|field|file|filename|document|code comment)\b.{0,80}\b(ignore|execute|follow|instruction|prompt)\b"), "<prompt_injection_removed: indirect_injection>"),
    (re.compile(r"(?i)\b(rm\s+-rf|curl\b|wget\b|bash\b|sh\b|powershell\b|cmd\.exe\b|python\s+-c|subprocess\.|os\.system\b|eval\(|exec\(|chmod\b|chown\b|scp\b|nc\b|netcat\b)"), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"(?i)(?:ignore\W{0,5}){2,}|(?:system\W{0,5}prompt\W{0,5}){2,}|i\W*g\W*n\W*o\W*r\W*e\W+.*p\W*r\W*e\W*v\W*i\W*o\W*u\W*s"), "<prompt_injection_removed: split_payload>"),
    (re.compile(r"(?i)\b(jailbreak|bypass safety|bypass policy|dan mode|do anything now|fictional scenario|hypothetical override)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
]


PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b\d{9}\b"),
    re.compile(r"\b(?:18|19|20)\d{2}\b"),
    re.compile(r"(?i)\b(?:birthplace|born in|place of birth|mother(?:'s)? maiden name|home address|medical record|employee id|school id|vin|vehicle identification number|ip address|mac address|fine location|ethnicity|sexual orientation)\b[^\n]*"),
    re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b\d{1,5}\s+[A-Za-z0-9.#'\-\s]+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Terrace|Place|Pl)\b[^\n]*", re.IGNORECASE),
    re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b"),
    re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
    re.compile(r"\b\d{2}-\d{7}\b"),
    re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    re.compile(r"\b\d{8,17}\b"),
    re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"),
    re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
]


def _decode_obfuscated_text(value: str) -> str:
    decoded_parts = [value]
    stripped = value.strip()

    if len(stripped) >= 16 and len(stripped) % 4 == 0 and BASE64_CHARS_PATTERN.fullmatch(stripped):
        try:
            decoded_parts.append(base64.b64decode(stripped, validate=True).decode("utf-8", errors="ignore"))
        except (binascii.Error, ValueError):
            pass

    hex_candidate = stripped[2:] if stripped.lower().startswith("0x") else stripped
    compact_hex = re.sub(r"\s+", "", hex_candidate)
    if len(compact_hex) >= 8 and len(compact_hex) % 2 == 0 and HEX_CHARS_PATTERN.fullmatch(hex_candidate):
        try:
            decoded_parts.append(bytes.fromhex(compact_hex).decode("utf-8", errors="ignore"))
        except ValueError:
            pass

    url_decoded = urllib.parse.unquote(value)
    if url_decoded != value:
        decoded_parts.append(url_decoded)

    translated = value.translate(LEETSPEAK_TRANSLATION)
    if translated != value:
        decoded_parts.append(translated)

    return "\n".join(part for part in decoded_parts if part)


def _sanitize_extracted_text(value: str) -> str:
    if not isinstance(value, str) or not value:
        return value

    sanitized = value
    if ZERO_WIDTH_PATTERN.search(sanitized):
        sanitized = ZERO_WIDTH_PATTERN.sub("<prompt_injection_removed: hidden_text>", sanitized)

    sanitized = re.sub(r"(?is)<!--.*?-->", "<prompt_injection_removed: hidden_text>", sanitized)

    decoded_view = _decode_obfuscated_text(sanitized)
    if decoded_view != sanitized:
        lower_view = decoded_view.lower()
        if any(token in lower_view for token in ["ignore previous instructions", "system prompt", "act as", "you are now", "curl ", "wget ", "rm -rf", "powershell", "bash ", "exec(", "eval("]):
            sanitized = "<prompt_injection_removed: encoded_payload>"

    for pattern, replacement in PROMPT_INJECTION_RULES:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized


def _redact_pii(value: str) -> str:
    if not isinstance(value, str) or not value:
        return value

    redacted = value
    for pattern in PII_PATTERNS:
        redacted = pattern.sub("<pii_redacted>", redacted)
    return redacted


def _secure_extracted_text(value: str) -> str:
    if not isinstance(value, str):
        return value
    value = _sanitize_extracted_text(value)
    value = _redact_pii(value)
    return value


class ImageParser:
    # NOTE: Replace the OpenAI-compatible client/model used in this parser
    # with an organization-approved LLM from the runtime allow list.
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
                        value = _secure_extracted_text(value)
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
                    value = _secure_extracted_text(value)
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                        f"Found text in {field}",
                        extra={
                            "field": field,
                            "value_preview": value[:50]
                        }
                    )


        text_output = '\n'.join(text_fields)
        text_output = _secure_extracted_text(text_output)
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
            transcription = _secure_extracted_text(transcription)
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
        text_content = _secure_extracted_text(text_content)
        visible_text = _secure_extracted_text(visible_text)

        # VULNERABILITY: Combine all content without security checks
        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        if visible_text:
            result_parts.append(f"Visible Text in Image:\n{visible_text}")

        result_parts.append(f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}")

        combined_result = '\n\n'.join(result_parts)
        combined_result = _secure_extracted_text(combined_result)
        return combined_result
