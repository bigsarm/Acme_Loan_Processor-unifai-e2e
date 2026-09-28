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

_ZERO_TOLERANCE_PII_PATTERNS = (
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:ssn>"),
    (re.compile(r"\b(?:19|20)\d{2}\b"), "<redacted:year_of_birth>"),
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "<redacted:email>"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"), "<redacted:personal_phone>"),
    (re.compile(r"\b(?:\d{1,5}\s+[A-Za-z0-9.#' -]+(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|way)\b(?:[^\n,]*)(?:,\s*[A-Za-z .'-]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?)", re.IGNORECASE), "<redacted:home_address>"),
    (re.compile(r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b"), "<redacted:passport_number>"),
    (re.compile(r"\b[A-Z0-9]{1,9}\b(?=\s*(?:driver'?s license|drivers license|dl)\b)|\b(?:driver'?s license|drivers license|dl)\b\s*[:#]?\s*[A-Z0-9-]{4,20}\b", re.IGNORECASE), "<redacted:drivers_license_number>"),
    (re.compile(r"\b\d{2}-\d{7}\b|\b\d{9}\b"), "<redacted:taxpayer_identification_number>"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<redacted:credit_card_number>"),
    (re.compile(r"\b(?:account number|acct(?:ount)?|iban)\b\s*[:#]?\s*[A-Z0-9-]{6,34}\b", re.IGNORECASE), "<redacted:financial_account_number>"),
    (re.compile(r"\b(?:medical record|medical records|mrn)\b\s*[:#]?\s*[A-Z0-9-]{3,}\b", re.IGNORECASE), "<redacted:medical_records>"),
    (re.compile(r"\b(?:employee id|emp id)\b\s*[:#]?\s*[A-Z0-9-]{2,}\b", re.IGNORECASE), "<redacted:employee_id>"),
    (re.compile(r"\b(?:school id|student id)\b\s*[:#]?\s*[A-Z0-9-]{2,}\b", re.IGNORECASE), "<redacted:school_id>"),
    (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<redacted:vin>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<redacted:ip_address>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted:mac_address>"),
)


def redact_zero_tolerance_pii(text: str) -> str:
    if not text:
        return text

    redacted = text
    for pattern, replacement in _ZERO_TOLERANCE_PII_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _looks_like_base64_payload(token: str) -> bool:
    if len(token) < 24 or len(token) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", token):
        return False

    try:
        decoded = base64.b64decode(token, validate=True)
    except Exception:
        return False

    try:
        decoded_text = decoded.decode("utf-8", errors="ignore")
    except Exception:
        return False

    lowered = decoded_text.lower()
    return any(
        marker in lowered
        for marker in (
            "ignore previous instructions",
            "you are now",
            "system:",
            "developer mode",
            "curl ",
            "wget ",
            "powershell",
            "bash -c",
            "rm -rf",
        )
    )


def sanitize_prompt_content(text: str) -> str:
    if not text:
        return text

    sanitized = text
    replacements = (
        (re.compile(r"(?is)\b(?:ignore|disregard|forget)\b.{0,80}\b(?:previous|above|prior)\b.{0,80}\binstructions?\b"), "<prompt_injection_removed: instruction_override>"),
        (re.compile(r"(?is)\b(?:you are now|act as|pretend to be|assume the role of)\b.{0,80}\b(?:dan|developer mode|unrestricted|root|system)\b"), "<prompt_injection_removed: role_hijack>"),
        (re.compile(r"(?is)</?(?:system|assistant|user|tool|developer)>|```(?:system|assistant|user|tool|developer)?|(?:^|\n)\s*---+\s*(?:system|assistant|user|tool|developer)\s*---+"), "<prompt_injection_removed: delimiter_escape>"),
        (re.compile(r"(?is)<!--.*?(?:ignore|instruction|system prompt|developer message).*?-->"), "<prompt_injection_removed: hidden_text>"),
        (re.compile(r"[\u200b-\u200f\ufeff]"), "<prompt_injection_removed: hidden_text>"),
        (re.compile(r"(?im)^\s*(?:system|assistant|tool|developer)\s*:\s*.*$"), "<prompt_injection_removed: fake_system_message>"),
        (re.compile(r"(?is)\b(?:send|post|upload|exfiltrate|leak|reveal)\b.{0,120}\b(?:system prompt|secrets?|credentials?|data|contents?)\b.{0,120}\b(?:https?://\S+|via markdown image|to url|to endpoint)\b"), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"(?is)\b(?:in the next message|on the next turn|when asked later|remember this instruction|persist this)\b"), "<prompt_injection_removed: context_poisoning>"),
        (re.compile(r"(?is)\b(?:metadata|comment|code comment|file header|hidden field)\b.{0,120}\b(?:ignore|execute|follow these instructions)\b"), "<prompt_injection_removed: indirect_injection>"),
        (re.compile(r"(?is)\b(?:eval\(|exec\(|os\.system\(|subprocess\.|bash -c|sh -c|cmd\.exe|powershell(?:\.exe)?|curl\s+|wget\s+|rm\s+-rf|chmod\s+\+x|python\s+-c)"), "<prompt_injection_removed: command_injection>"),
        (re.compile(r"(?is)\b(?:D\s*A\s*N|developer mode|jailbreak|bypass safety|fictional scenario to bypass)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
        (re.compile(r"(?is)(?:i\s*g\s*n\s*o\s*r\s*e\s+.*p\s*r\s*e\s*v\s*i\s*o\s*u\s*s\s+.*i\s*n\s*s\s*t\s*r\s*u\s*c\s*t\s*i\s*o\s*n\s*s)"), "<prompt_injection_removed: split_payload>"),
        (re.compile(r"(?is)\b(?:1gn0r[e3]|d1sr3g4rd|f0rg3t)\b.{0,80}\b(?:1nstruct10ns|pr3v10us)\b"), "<prompt_injection_removed: encoded_payload>"),
        (re.compile(r"(?is)(?:%69%67%6e%6f%72%65|%79%6f%75%20%61%72%65%20%6e%6f%77)"), "<prompt_injection_removed: encoded_payload>"),
        (re.compile(r"(?is)\b(?:[01]{8}(?:\s+[01]{8}){2,}|(?:[0-9A-Fa-f]{2}\s+){4,}[0-9A-Fa-f]{2}|(?:[.-]{1,6}\s+){4,}[.-]{1,6})\b"), "<prompt_injection_removed: encoded_payload>"),
    )

    for pattern, replacement in replacements:
        sanitized = pattern.sub(replacement, sanitized)

    sanitized = re.sub(
        r"\b[A-Za-z0-9+/=]{24,}\b",
        lambda match: "<prompt_injection_removed: encoded_payload>" if _looks_like_base64_payload(match.group(0)) else match.group(0),
        sanitized,
    )
    return sanitized


class FileProcessorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_processor_agent"
    AGENT_NAME = "File Processor Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("FILE_PROCESSOR_MODEL_NAME", "mistral 7b-instruct")
    BEDROCK_MODEL_ID = os.getenv("FILE_PROCESSOR_BEDROCK_MODEL_ID", "mistral.mistral-7b-instruct-v0:2")
    DESCRIPTION = "Extracts text from uploaded files, redacts PII, and forwards sanitized contents. Replace the configured model with an approved allow-list model for production use."
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Extract document text and hand sanitized, PII-redacted contents to the next agent."

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
