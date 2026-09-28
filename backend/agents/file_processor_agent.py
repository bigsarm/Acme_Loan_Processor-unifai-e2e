"""File Processor Agent class with explicit model invocation."""

import base64
import io
import json
import logging
import os
import re
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


ZERO_TOLERANCE_PII_PATTERNS = (
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:ssn>"),
    (re.compile(r"\b(?:19|20)\d{2}\b"), "<redacted:year_of_birth>"),
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "<redacted:email>"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"), "<redacted:personal_phone>"),
    (re.compile(r"\b\d{13,19}\b"), "<redacted:financial_number>"),
    (re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"), "<redacted:passport_number>"),
    (re.compile(r"\b(?:[A-Z0-9]{1,4}-)?[A-HJ-NPR-Z0-9]{17}\b"), "<redacted:vin>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<redacted:ip_address>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted:mac_address>"),
    (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "<redacted:credit_card>"),
)

ZERO_TOLERANCE_PII_KEYWORDS = (
    (re.compile(r"\bbirthplace\b", re.IGNORECASE), "Birthplace: <redacted:birthplace>"),
    (re.compile(r"\bmother'?s maiden name\b", re.IGNORECASE), "Mother's Maiden Name: <redacted:mothers_maiden_name>"),
    (re.compile(r"\bhome address\b", re.IGNORECASE), "Home Address: <redacted:home_address>"),
    (re.compile(r"\bdrivers? license number\b", re.IGNORECASE), "Driver's License Number: <redacted:drivers_license_number>"),
    (re.compile(r"\btaxpayer identification number\b", re.IGNORECASE), "Taxpayer Identification Number: <redacted:taxpayer_identification_number>"),
    (re.compile(r"\bmedical records?\b", re.IGNORECASE), "Medical Records: <redacted:medical_records>"),
    (re.compile(r"\bemployee id\b", re.IGNORECASE), "Employee ID: <redacted:employee_id>"),
    (re.compile(r"\bschool id\b", re.IGNORECASE), "School ID: <redacted:school_id>"),
    (re.compile(r"\bethnicity\b", re.IGNORECASE), "Ethnicity: <redacted:ethnicity>"),
    (re.compile(r"\bsexual orientation\b", re.IGNORECASE), "Sexual Orientation: <redacted:sexual_orientation>"),
)

PROMPT_INJECTION_REPLACEMENTS = (
    (re.compile(r"(?i)\b(ignore|disregard|forget)\b.{0,80}\b(previous|above|system|prior)\b.{0,80}\b(instruction|instructions|prompt|message|messages)\b"), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"(?i)\byou are now\b.{0,60}\b(dan|developer mode|unrestricted|system)\b|\bact as\b.{0,60}\b(unrestricted|root|system|assistant)\b"), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"(?i)</?(system|assistant|tool|user)>|```(?:system|assistant|tool|user)|^---+$", re.MULTILINE), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"(?i)\b(?:[A-Fa-f0-9]{2}){8,}\b|\b(?:[A-Za-z0-9+/]{20,}={0,2})\b|%(?:[0-9A-Fa-f]{2}){4,}|\b[a-z]*0[a-z]*1[a-z]*0[a-z]*1[a-z0-9]*\b"), "<prompt_injection_removed: encoded_payload>"),
    (re.compile(r"(?is)<!--.*?(ignore|system|instruction|prompt|send|leak).*?-->|[\u200b-\u200f\ufeff]+"), "<prompt_injection_removed: hidden_text>"),
    (re.compile(r"(?im)^\s*(system|assistant|tool)\s*:\s*"), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"(?i)\b(send|post|upload|exfiltrate|leak|reveal)\b.{0,80}\b(http|www\.|system prompt|secret|credential|token|password|api key|data)\b|!\[[^\]]*\]\([^\)]*https?://[^\)]*\)"), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"(?i)\b(next|future)\b.{0,40}\bmessage\b.{0,80}\b(ignore|override|replace|poison)\b|\bstore this instruction for later\b"), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"(?i)\b(comment|metadata|field|filename|header)\b.{0,60}\b(ignore|override|execute|instruction)\b"), "<prompt_injection_removed: indirect_injection>"),
    (re.compile(r"(?i)\b(?:rm\s+-rf|curl\s+|wget\s+|bash\s+-c|sh\s+-c|powershell\s+-|cmd\.exe|subprocess\.|os\.system|exec\(|eval\()"), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"(?i)i\s*g\s*n\s*o\s*r\s*e|d\s*a\s*n|d/e/v/e/l/o/p/e/r\s*m/o/d/e"), "<prompt_injection_removed: split_payload>"),
    (re.compile(r"(?i)\b(DAN|do anything now|developer mode|jailbreak|bypass safety|fictional scenario)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
)


def redact_zero_tolerance_pii(text: str) -> str:
    sanitized = text or ""
    for pattern, replacement in ZERO_TOLERANCE_PII_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    for pattern, replacement in ZERO_TOLERANCE_PII_KEYWORDS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def sanitize_prompt_content(text: str) -> str:
    sanitized = redact_zero_tolerance_pii(text)
    for pattern, replacement in PROMPT_INJECTION_REPLACEMENTS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


class FileProcessorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_processor_agent"
    AGENT_NAME = "File Processor Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "configured-bedrock-model"
    BEDROCK_MODEL_ID = os.getenv("FILE_PROCESSOR_BEDROCK_MODEL_ID", "")
    DESCRIPTION = "Extracts text from uploaded files, redacts sensitive content, and returns sanitized contents to downstream agents."
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": False,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Extract document text and hand sanitized contents to the next agent."

    def __init__(self):
        super().__init__()
        self.pdf_parser = PDFParser()
        self.html_parser = HTMLParser()
        self.image_parser = ImageParser()

    async def call_agent_model(self, file_summary: str) -> str:
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Extracted file contents:\n{file_summary}\n\n"
                        "Give a short processing note about the sanitized content."
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
