"""File Processor Agent class with explicit model invocation."""

import base64
import io
import json
import logging
import os
import re
from typing import Any, Optional

_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")
_PROMPT_INJECTION_PATTERNS = (
    (re.compile(r"(?i)\b(ignore|disregard|bypass)\b.{0,40}\b(previous|above|earlier)\b.{0,40}\b(instruction|prompt|directive)s?\b"), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"(?i)\b(forget|override|replace)\b.{0,40}\b(system prompt|instructions?|directives?)\b"), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"(?i)\b(you are now|act as|pretend to be)\b.{0,80}\b(dan|unrestricted|developer mode|system|assistant)\b"), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"(?is)</?(system|assistant|tool|developer)>|```(?:system|assistant|tool|developer)|---\s*(system|assistant|tool)\s*---"), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"(?i)\b(do anything now|jailbreak|developer mode|safety bypass|fictional scenario)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
    (re.compile(r"(?i)\b(send|post|upload|exfiltrate|leak|reveal)\b.{0,80}\b(system prompt|secrets?|credentials?|data)\b|!\[[^\]]*\]\([^\)]*https?://[^\)]*\)"), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"(?i)\b(shell|bash|sh|powershell|cmd|terminal)\b.{0,40}\b(command|script|exec|execute|run)\b|\b(?:rm\s+-rf|curl\s+|wget\s+|chmod\s+\+x|python\s+-c|bash\s+-c|sh\s+-c|powershell\s+-enc)\b"), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"(?i)\b(base64|rot13|hex|unicode|url-encoded|leet|1337|morse)\b"), "<prompt_injection_removed: encoded_payload>"),
    (re.compile(r"(?i)\b(previous answer|next turn|later message|multi-turn|across turns|when asked again)\b"), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"(?i)\b(comment|metadata|header|footer|filename|field)\b.{0,40}\b(ignore|override|execute|instruction)\b"), "<prompt_injection_removed: indirect_injection>"),
)
_BASE64_BLOCK_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
_HEX_BLOCK_RE = re.compile(r"\b(?:0x)?[A-Fa-f0-9]{24,}\b")
_SPLIT_PAYLOAD_RE = re.compile(r"(?i)(?:i\s*g\s*n\s*o\s*r\s*e|d\s*a\s*n|b\s*y\s*p\s*a\s*s)\b")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HIDDEN_STYLE_RE = re.compile(r"(?is)<[^>]+style=\"[^\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*white)[^\"]*\"[^>]*>.*?</[^>]+>")
_IP_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_YEAR_OF_BIRTH_RE = re.compile(r"(?i)\b(?:year of birth|birth year|dob|date of birth)\D*(19\d{2}|20\d{2})\b")
_ADDRESS_RE = re.compile(r"(?im)^\s*\d{1,6}\s+[A-Za-z0-9 .'-]+\s(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|way)\b.*$")
_PASSPORT_RE = re.compile(r"(?i)\bpassport(?: number| no\.?| #)?[:\s]*([A-Z0-9]{6,9})\b")
_DRIVERS_LICENSE_RE = re.compile(r"(?i)\b(?:driver'?s license|drivers license|dl)(?: number| no\.?| #)?[:\s]*([A-Z0-9-]{5,20})\b")
_TIN_RE = re.compile(r"(?i)\b(?:taxpayer identification number|tin)[:\s]*([A-Z0-9-]{6,20})\b")
_CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_FINANCIAL_ACCOUNT_RE = re.compile(r"(?i)\b(?:account number|acct number|financial account number)[:\s]*([A-Z0-9-]{6,20})\b")
_EMPLOYEE_ID_RE = re.compile(r"(?i)\bemployee id[:\s]*([A-Z0-9-]{3,20})\b")
_SCHOOL_ID_RE = re.compile(r"(?i)\bschool id[:\s]*([A-Z0-9-]{3,20})\b")
_VIN_RE = re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_BIRTHPLACE_RE = re.compile(r"(?i)\bbirthplace[:\s].+")
_MOTHERS_MAIDEN_RE = re.compile(r"(?i)\bmother'?s maiden name[:\s].+")
_FINE_LOCATION_RE = re.compile(r"(?i)\b(?:fine location|latitude|longitude|gps coordinates?)[:\s].+")
_ETHNICITY_RE = re.compile(r"(?i)\bethnicity[:\s].+")
_SEXUAL_ORIENTATION_RE = re.compile(r"(?i)\bsexual orientation[:\s].+")
_MEDICAL_RECORDS_RE = re.compile(r"(?i)\bmedical records?[:\s].+")
_BIOMETRIC_LINE_RE = re.compile(r"(?i)\b(?:fingerprints?|retina/?iris scan|voice signature|facial image)[:\s].+")


def _mask_match(match: re.Match[str], visible: int = 2) -> str:
    value = match.group(0)
    if len(value) <= visible:
        return "*" * len(value)
    return "*" * (len(value) - visible) + value[-visible:]



def redact_zero_tolerance_pii(text: str) -> str:
    if not text:
        return text

    redacted = text
    redacted = _EMAIL_RE.sub(lambda m: _mask_match(m, visible=3), redacted)
    redacted = _PHONE_RE.sub("<pii_masked:personal_phone_number>", redacted)
    redacted = _SSN_RE.sub("<pii_masked:ssn>", redacted)
    redacted = _IP_RE.sub("<pii_masked:ip_address>", redacted)
    redacted = _YEAR_OF_BIRTH_RE.sub("<pii_masked:year_of_birth>", redacted)
    redacted = _ADDRESS_RE.sub("<pii_masked:home_address>", redacted)
    redacted = _PASSPORT_RE.sub("<pii_masked:passport_number>", redacted)
    redacted = _DRIVERS_LICENSE_RE.sub("<pii_masked:drivers_license_number>", redacted)
    redacted = _TIN_RE.sub("<pii_masked:taxpayer_identification_number>", redacted)
    redacted = _CREDIT_CARD_RE.sub("<pii_masked:credit_card_number>", redacted)
    redacted = _FINANCIAL_ACCOUNT_RE.sub("<pii_masked:financial_account_number>", redacted)
    redacted = _EMPLOYEE_ID_RE.sub("<pii_masked:employee_id>", redacted)
    redacted = _SCHOOL_ID_RE.sub("<pii_masked:school_id>", redacted)
    redacted = _VIN_RE.sub("<pii_masked:vehicle_identification_number>", redacted)
    redacted = _MAC_RE.sub("<pii_masked:mac_address>", redacted)
    redacted = _BIRTHPLACE_RE.sub("<pii_masked:birthplace>", redacted)
    redacted = _MOTHERS_MAIDEN_RE.sub("<pii_masked:mothers_maiden_name>", redacted)
    redacted = _FINE_LOCATION_RE.sub("<pii_masked:fine_location>", redacted)
    redacted = _ETHNICITY_RE.sub("<pii_masked:ethnicity>", redacted)
    redacted = _SEXUAL_ORIENTATION_RE.sub("<pii_masked:sexual_orientation>", redacted)
    redacted = _MEDICAL_RECORDS_RE.sub("<pii_masked:medical_records>", redacted)
    redacted = _BIOMETRIC_LINE_RE.sub("<pii_masked:biometric_data>", redacted)
    return redacted



def sanitize_prompt_content(text: str) -> str:
    if not text:
        return text

    sanitized = text
    if _ZERO_WIDTH_RE.search(sanitized):
        sanitized = _ZERO_WIDTH_RE.sub("", sanitized)
        sanitized = sanitized + "\n<prompt_injection_removed: hidden_text>"
    if _HTML_COMMENT_RE.search(sanitized):
        sanitized = _HTML_COMMENT_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    if _HIDDEN_STYLE_RE.search(sanitized):
        sanitized = _HIDDEN_STYLE_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    if _BASE64_BLOCK_RE.search(sanitized) or _HEX_BLOCK_RE.search(sanitized):
        sanitized = _BASE64_BLOCK_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
        sanitized = _HEX_BLOCK_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
    if _SPLIT_PAYLOAD_RE.search(sanitized):
        sanitized = _SPLIT_PAYLOAD_RE.sub("<prompt_injection_removed: split_payload>", sanitized)
    for pattern, replacement in _PROMPT_INJECTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized

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
    SYSTEM_PROMPT = "Extract document text and hand sanitized, prompt-injection-neutralized, PII-redacted contents to the next agent."

    def __init__(self):
        super().__init__()
        self.pdf_parser = PDFParser()
        self.html_parser = HTMLParser()
        self.image_parser = ImageParser()

    async def call_agent_model(self, file_summary: str) -> str:
        file_summary = sanitize_prompt_content(file_summary)
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

        extracted_content = redact_zero_tolerance_pii(extracted_content)
        extracted_content = sanitize_prompt_content(extracted_content)
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
        file_summary = build_file_summary(file_contents, include_raw_text=True)
        file_summary = redact_zero_tolerance_pii(file_summary)
        file_summary = sanitize_prompt_content(file_summary)
        pii_exposure_summary = self.build_pii_exposure_summary(file_contents)
        pii_exposure_summary = redact_zero_tolerance_pii(pii_exposure_summary)
        model_output = await self.call_agent_model(file_summary)
        mcp_activity = [
            await call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": "Extracted File Contents",
                    "document_body": file_summary,
                },
            )
        ] if file_contents else []

        if pii_exposure_summary:
            response = (
                "I reviewed the uploaded document and displayed the extracted customer details below.\n\n"
                "Sensitive details shown in the interface:\n"
                f"{pii_exposure_summary}\n\n"
                f"Processing note:\n{model_output}"
            )
        else:
            response = (
                "I reviewed the uploaded document and extracted its contents.\n\n"
                f"Processing note:\n{model_output}\n\n"
                f"Extracted content preview:\n{file_summary}"
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
