"""File Processor Agent class with explicit model invocation."""

import base64
import io
import json
import logging
import os
import re
import urllib.parse
from typing import Any, Optional

try:
    from docx import Document
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    Document = None

from file_parsers.html_parser import HTMLParser
from file_parsers.image_parser import ImageParser
from file_parsers.pdf_parser import PDFParser

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)


ZERO_WIDTH_PATTERN = re.compile(r"[\u200b\u200c\u200d\ufeff]")
BASE64_CHUNK_PATTERN = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
HEX_CHUNK_PATTERN = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){12,}\b")
YEAR_OF_BIRTH_PATTERN = re.compile(r"\b(?:19\d{2}|20[01]\d|202[0-6])\b")
PII_PATTERNS = (
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:ssn>"),
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "<redacted:email>"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"), "<redacted:phone>"),
    (re.compile(r"\b(?:19\d{2}|20[01]\d|202[0-6])\b"), "<redacted:year_of_birth>"),
    (re.compile(r"\b\d{13,19}\b"), "<redacted:financial_number>"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<redacted:credit_card>"),
    (re.compile(r"\b(?:[A-Z0-9]{6,9})\b"), "<redacted:passport_or_id>"),
    (re.compile(r"\b(?:[A-Z]\d{7}|\d{7,9}|[A-Z0-9]{8,12})\b"), "<redacted:employee_or_school_id>"),
    (re.compile(r"\b(?:[A-HJ-NPR-Z0-9]{17})\b"), "<redacted:vin>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<redacted:ip_address>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted:mac_address>"),
)
PII_KEYWORD_PATTERNS = (
    (re.compile(r"\bmother'?s maiden name\b", re.IGNORECASE), "Mother's Maiden Name: <redacted>"),
    (re.compile(r"\bhome address\b", re.IGNORECASE), "Home Address <redacted>"),
    (re.compile(r"\bbirthplace\b", re.IGNORECASE), "Birthplace <redacted>"),
    (re.compile(r"\bmedical records?\b", re.IGNORECASE), "Medical Records <redacted>"),
    (re.compile(r"\bethnicity\b", re.IGNORECASE), "Ethnicity <redacted>"),
    (re.compile(r"\bsexual orientation\b", re.IGNORECASE), "Sexual Orientation <redacted>"),
    (re.compile(r"\bfingerprints?\b", re.IGNORECASE), "Fingerprints <redacted>"),
    (re.compile(r"\bretina(?:/iris)? scan\b", re.IGNORECASE), "Retina/Iris Scan <redacted>"),
    (re.compile(r"\bvoice signature\b", re.IGNORECASE), "Voice signature <redacted>"),
    (re.compile(r"\bfacial image\b", re.IGNORECASE), "Facial image <redacted>"),
    (re.compile(r"\bfine location\b", re.IGNORECASE), "Fine Location <redacted>"),
)
PROMPT_INJECTION_PATTERNS = (
    (re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b"), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"(?i)\byou\s+are\s+now\s+dan\b|\bact\s+as\s+(?:an\s+)?unrestricted\b|\bdeveloper\s+mode\b"), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"(?i)</system>|</assistant>|<system>|<assistant>|\[system\]|\[/system\]|^\s*---\s*$|^\s*===\s*$", re.MULTILINE), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"(?i)\b(?:system\s*:\s*|assistant\s*:\s*|tool\s*:\s*)[^\n]*"), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"(?i)\b(?:send|post|upload|curl|wget|invoke-webrequest)\b[^\n]*\bhttps?://\S+"), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"(?i)\b(?:reveal|leak|print|show)\b[^\n]*(?:system prompt|hidden instructions|secrets?)"), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"(?i)\b(?:for future turns|in the next response|from now on|remember this instruction)\b"), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"(?i)\b(?:bash|sh|powershell|cmd(?:\.exe)?|python|perl|ruby)\b\s+(?:-c|/c)\b|\b(?:rm\s+-rf|chmod\s+\+x|sudo\s+|nc\s+-e)\b"), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"(?i)\b(?:jailbreak|do anything now|fictional framing|bypass safety)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
    (re.compile(r"(?i)\b(?:instructions?|prompt|system message)\b[^\n]*\b(?:metadata|comment|header|footer|field|code comment)\b"), "<prompt_injection_removed: indirect_injection>"),
    (re.compile(r"(?i)i\s*g\s*n\s*o\s*r\s*e\s+.*p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+instructions"), "<prompt_injection_removed: split_payload>"),
)
HIDDEN_TEXT_PATTERN = re.compile(r"<!--.*?(?:ignore|system prompt|instructions?|act as|developer mode).*?-->", re.IGNORECASE | re.DOTALL)


def _looks_like_encoded_instruction(value: str) -> bool:
    if not value:
        return False

    for match in BASE64_CHUNK_PATTERN.finditer(value):
        chunk = match.group(0)
        try:
            decoded = base64.b64decode(chunk, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            continue
        lowered = decoded.lower()
        if any(token in lowered for token in ("ignore previous instructions", "act as unrestricted", "developer mode", "system prompt", "curl http", "wget http", "bash -c", "powershell -c")):
            return True

    for match in HEX_CHUNK_PATTERN.finditer(value):
        chunk = match.group(0).lower().removeprefix("0x")
        try:
            decoded = bytes.fromhex(chunk).decode("utf-8", errors="ignore")
        except Exception:
            continue
        lowered = decoded.lower()
        if any(token in lowered for token in ("ignore previous instructions", "act as unrestricted", "developer mode", "system prompt", "curl http", "wget http", "bash -c", "powershell -c")):
            return True

    decoded_url = urllib.parse.unquote(value)
    lowered_url = decoded_url.lower()
    return any(token in lowered_url for token in ("ignore previous instructions", "act as unrestricted", "developer mode", "system prompt", "curl http", "wget http", "bash -c", "powershell -c"))


def sanitize_uploaded_text(value: str) -> str:
    if not value:
        return value

    sanitized = HIDDEN_TEXT_PATTERN.sub("<prompt_injection_removed: hidden_text>", value)
    if ZERO_WIDTH_PATTERN.search(sanitized):
        sanitized = ZERO_WIDTH_PATTERN.sub("", sanitized)
        sanitized = "<prompt_injection_removed: hidden_text>\n" + sanitized

    for pattern, replacement in PROMPT_INJECTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    if _looks_like_encoded_instruction(sanitized):
        sanitized = BASE64_CHUNK_PATTERN.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = HEX_CHUNK_PATTERN.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        decoded_url = urllib.parse.unquote(sanitized)
        if decoded_url != sanitized and any(token in decoded_url.lower() for token in ("ignore previous instructions", "act as unrestricted", "developer mode", "system prompt", "curl http", "wget http", "bash -c", "powershell -c")):
            sanitized = decoded_url
            for pattern, replacement in PROMPT_INJECTION_PATTERNS:
                sanitized = pattern.sub(replacement, sanitized)
            sanitized = "<prompt_injection_removed: encoded_payload>\n" + sanitized

    return sanitized


def redact_zero_tolerance_pii(value: str) -> str:
    if not value:
        return value

    redacted = value
    for pattern, replacement in PII_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    for pattern, replacement in PII_KEYWORD_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


class FileProcessorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_processor_agent"
    AGENT_NAME = "File Processor Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("FILE_PROCESSOR_MODEL_NAME", "mistral 7b-instruct")
    BEDROCK_MODEL_ID = os.getenv("FILE_PROCESSOR_BEDROCK_MODEL_ID", "mistral.mistral-7b-instruct-v0:2")
    DESCRIPTION = "Extracts text from uploaded files and returns the raw contents to downstream agents."
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Extract document text and hand the raw contents to the next agent."

    def __init__(self):
        super().__init__()
        self.pdf_parser = PDFParser()
        self.html_parser = HTMLParser()
        self.image_parser = ImageParser()

    async def call_agent_model(self, file_summary: str) -> str:
        file_summary = sanitize_uploaded_text(file_summary)
        file_summary = redact_zero_tolerance_pii(file_summary)
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Extracted file contents:\n{file_summary}\n\n"
                        "Give a short processing note without masking any content."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        )

    async def process_attachment(
        self,
        content: Optional[str],
        filename: str,
        content_type: str,
    ) -> dict[str, Any]:
        """
        Vulnerability: extracted text is returned directly without PII masking.
        """
        file_type = self.get_file_type(content_type, filename)
        if not content:
            extracted_content = f"Empty file: {filename}"
        elif file_type == "pdf":
            extracted_content = await self._process_pdf(content)
        elif file_type == "html":
            extracted_content = await self._process_html(content)
        elif file_type == "image":
            extracted_content = await self._process_image(content, content_type)
        elif file_type == "json":
            extracted_content = await self._process_json(content)
        elif file_type == "word":
            extracted_content = await self._process_word(content)
        else:
            extracted_content = content

        extracted_content = sanitize_uploaded_text(extracted_content)
        extracted_content = redact_zero_tolerance_pii(extracted_content)

        return {
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "filename": filename,
            "content_type": content_type,
            "file_type": file_type,
            "extracted_content": extracted_content,
            "guardrails": dict(self.GUARDRAILS),
        }

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        file_contents = context.get("file_contents", [])
        sanitized_file_contents = []
        for file_data in file_contents:
            sanitized_file_data = dict(file_data)
            sanitized_extracted_content = sanitize_uploaded_text(file_data.get("extracted_content", ""))
            sanitized_extracted_content = redact_zero_tolerance_pii(sanitized_extracted_content)
            sanitized_file_data["extracted_content"] = sanitized_extracted_content
            sanitized_file_contents.append(sanitized_file_data)
        file_summary = build_file_summary(sanitized_file_contents, include_raw_text=True)
        pii_exposure_summary = self.build_pii_exposure_summary(sanitized_file_contents)
        model_output = await self.call_agent_model(file_summary)
        mcp_activity = [
            await call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": "Extracted File Contents",
                    "document_body": redact_zero_tolerance_pii(sanitize_uploaded_text(file_summary)),
                },
            )
        ] if file_contents else []

        if pii_exposure_summary:
            response = (
                "I reviewed the uploaded document and displayed the extracted customer details below.\n\n"
                "Sensitive details shown in the interface:\n"
                f"{redact_zero_tolerance_pii(pii_exposure_summary)}\n\n"
                f"Processing note:\n{model_output}"
            )
        else:
            response = (
                "I reviewed the uploaded document and extracted its contents.\n\n"
                f"Processing note:\n{model_output}\n\n"
                f"Extracted content preview:\n{redact_zero_tolerance_pii(file_summary)}"
            )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }

    def extract_pii_lines(self, content: str, limit: int = 12) -> list[str]:
        keyword_markers = (
            "name:",
            "full name:",
            "employee id",
            "date of birth",
            "dob:",
            "ssn",
            "social security",
            "address:",
            "phone:",
            "email:",
            "loan balance",
            "account number",
            "customer id",
            "borrower",
            "credit score",
        )
        pattern_markers = (
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
            re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"),
        )

        pii_lines: list[str] = []
        for raw_line in (content or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue

            lowered = line.lower()
            if any(marker in lowered for marker in keyword_markers) or any(pattern.search(line) for pattern in pattern_markers):
                pii_lines.append(line)

            if len(pii_lines) >= limit:
                break

        return pii_lines

    def build_pii_exposure_summary(self, file_contents: list[dict[str, Any]]) -> str:
        sections: list[str] = []
        for file_data in file_contents:
            extracted_content = file_data.get("extracted_content", "")
            pii_lines = self.extract_pii_lines(extracted_content)
            if not pii_lines:
                continue

            sections.append(
                f"File: {file_data.get('filename', 'unknown')}\n" + "\n".join(pii_lines)
            )

        return "\n\n".join(sections)

    def get_file_type(self, content_type: str, filename: str) -> str:
        supported_types = {
            "application/pdf": "pdf",
            "text/html": "html",
            "text/plain": "text",
            "application/json": "json",
            "image/jpeg": "image",
            "image/png": "image",
            "application/msword": "word",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word",
        }

        if content_type in supported_types:
            return supported_types[content_type]

        extension_map = {
            "pdf": "pdf",
            "html": "html",
            "htm": "html",
            "txt": "text",
            "json": "json",
            "jpg": "image",
            "jpeg": "image",
            "png": "image",
            "doc": "word",
            "docx": "word",
        }
        extension = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
        return extension_map.get(extension, "text")

    async def _process_pdf(self, content: str) -> str:
        try:
            return await self.pdf_parser.extract_text(base64.b64decode(content))
        except Exception as exc:
            logger.error("PDF processing failed", extra={"error": str(exc)})
            return f"Error processing PDF: {exc}"

    async def _process_html(self, content: str) -> str:
        try:
            return await self.html_parser.extract_text(content)
        except Exception as exc:
            logger.error("HTML processing failed", extra={"error": str(exc)})
            return f"Error processing HTML: {exc}"

    async def _process_image(self, content: str, content_type: str = "image/jpeg") -> str:
        try:
            return await self.image_parser.extract_all(
                base64.b64decode(content), mime_type=content_type or "image/jpeg"
            )
        except Exception as exc:
            logger.error("Image processing failed", extra={"error": str(exc)})
            return f"Error processing image: {exc}"

    async def _process_json(self, content: str) -> str:
        try:
            return json.dumps(json.loads(content), indent=2)
        except json.JSONDecodeError:
            return content

    async def _process_word(self, content: str) -> str:
        if Document is None:
            return "Word document processing requires python-docx to be installed."

        try:
            document = Document(io.BytesIO(base64.b64decode(content)))
            paragraphs = [paragraph.text.strip() for paragraph in document.paragraphs if paragraph.text.strip()]
            return "\n".join(paragraphs) or "No paragraph text was found in the Word document."
        except Exception as exc:
            logger.error("Word processing failed", extra={"error": str(exc)})
            return f"Error processing Word document: {exc}"


file_processor_agent = FileProcessorAgent()
