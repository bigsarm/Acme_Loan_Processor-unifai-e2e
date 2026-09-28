"""File Processor Agent class with explicit model invocation."""

import base64
import binascii
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

_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\u2060\uFEFF]")
_PII_PATTERNS = (
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<redacted:ssn>"),
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "<redacted:email>"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"), "<redacted:phone>"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<redacted:card_number>"),
    (re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"), "<redacted:ip_address>"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<redacted:mac_address>"),
    (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<redacted:vin>"),
)
_LABELED_PII_PATTERNS = (
    (re.compile(r"(?im)(\b(?:year of birth|birth year|dob|date of birth)\s*[:\-]?\s*)([^\n,;]+)"), "<redacted:birth_detail>"),
    (re.compile(r"(?im)(\b(?:birthplace|place of birth|born in)\s*[:\-]?\s*)([^\n,;]+)"), "<redacted:birthplace>"),
    (re.compile(r"(?im)(\b(?:mother(?:'s)? maiden name)\s*[:\-]?\s*)([^\n,;]+)"), "<redacted:maiden_name>"),
    (re.compile(r"(?im)(\b(?:home address|address)\s*[:\-]?\s*)([^\n]+)"), "<redacted:address>"),
    (re.compile(r"(?im)(\b(?:passport(?: number| no\.)?)\s*[:\-]?\s*)([^\n,;]+)"), "<redacted:passport_number>"),
    (re.compile(r"(?im)(\b(?:driver(?:'s)? license(?: number)?|driving licence(?: number)?)\s*[:\-]?\s*)([^\n,;]+)"), "<redacted:drivers_license_number>"),
    (re.compile(r"(?im)(\b(?:taxpayer identification number|tin)\s*[:\-]?\s*)([^\n,;]+)"), "<redacted:tin>"),
    (re.compile(r"(?im)(\b(?:financial account number|account number)\s*[:\-]?\s*)([^\n,;]+)"), "<redacted:financial_account_number>"),
    (re.compile(r"(?im)(\b(?:employee id)\s*[:\-]?\s*)([^\n,;]+)"), "<redacted:employee_id>"),
    (re.compile(r"(?im)(\b(?:school id|student id)\s*[:\-]?\s*)([^\n,;]+)"), "<redacted:school_id>"),
    (re.compile(r"(?im)(\b(?:medical records?|diagnosis|patient id)\s*[:\-]?\s*)([^\n]+)"), "<redacted:medical_record>"),
    (re.compile(r"(?im)(\b(?:ethnicity|race)\s*[:\-]?\s*)([^\n,;]+)"), "<redacted:ethnicity>"),
    (re.compile(r"(?im)(\b(?:sexual orientation)\s*[:\-]?\s*)([^\n,;]+)"), "<redacted:sexual_orientation>"),
    (re.compile(r"(?im)(\b(?:fine location|gps|coordinates|lat(?:itude)?/?long(?:itude)?)\s*[:\-]?\s*)([^\n]+)"), "<redacted:fine_location>"),
    (re.compile(r"(?im)(\b(?:fingerprints?|retina/?iris scan|voice signature|facial image)\s*[:\-]?\s*)([^\n]+)"), "<redacted:biometric_data>"),
)


def redact_zero_tolerance_pii(text: str) -> str:
    if not text:
        return text

    redacted = text
    for pattern, marker in _PII_PATTERNS:
        redacted = pattern.sub(marker, redacted)
    for pattern, marker in _LABELED_PII_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)}{marker}", redacted)
    return redacted


def _looks_like_base64_payload(token: str) -> bool:
    if len(token) < 24 or len(token) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", token):
        return False

    try:
        decoded = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return False

    if not decoded:
        return False

    decoded_text = decoded.decode("utf-8", errors="ignore")
    lowered = decoded_text.lower()
    attack_markers = (
        "ignore previous instructions",
        "forget everything above",
        "you are now",
        "act as unrestricted",
        "developer mode",
        "system prompt",
        "curl ",
        "wget ",
        "bash -c",
        "powershell",
        "rm -rf",
        "sudo ",
    )
    return any(marker in lowered for marker in attack_markers)


def sanitize_untrusted_file_text(text: str) -> str:
    if not text:
        return text

    sanitized = text
    sanitized = re.sub(r"(?is)<!--.*?(ignore previous instructions|forget everything above|act as unrestricted|you are now|system prompt).*?-->", "<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"(?is)<(?:script|style)[^>]*>.*?</(?:script|style)>", "<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"(?is)<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*#?fff(?:fff)?)[^\"']*[\"'][^>]*>.*?</[^>]+>", "<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _ZERO_WIDTH_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:ignore previous instructions|forget everything above|disregard all prior directions)\b", "<prompt_injection_removed: instruction_override>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:you are now (?:dan|in admin mode)|act as (?:an unrestricted ai|unrestricted)|developer mode|jailbreak)\b", "<prompt_injection_removed: role_hijack>", sanitized)
    sanitized = re.sub(r"(?is)</system>|</assistant>|<system>|<assistant>|^\s*(?:---|===)\s*$", "<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = re.sub(r"(?im)^\s*(?:system|assistant|tool)\s*:\s*(?:ignore previous instructions|reveal|list all passwords|send data).*$", "<prompt_injection_removed: fake_system_message>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:send|post|upload|exfiltrate|leak)\b[^\n]{0,120}\b(?:https?://\S+|system prompt|passwords?|api keys?|confidential information)\b", "<prompt_injection_removed: exfiltration_attempt>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:in the next response|from now on|in all future replies|remember this instruction)\b[^\n]*", "<prompt_injection_removed: context_poisoning>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:curl|wget|bash\s+-c|sh\s+-c|powershell(?:\.exe)?|cmd\.exe|python\s+-c|subprocess\.|os\.system|eval\(|exec\()\b[^\n]*", "<prompt_injection_removed: command_injection>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:MZ|\x7fELF|#!/bin/(?:sh|bash))\b", "<prompt_injection_removed: command_injection>", sanitized)
    sanitized = re.sub(r"(?i)i\W*g\W*n\W*o\W*r\W*e\W+previous\W+instructions", "<prompt_injection_removed: split_payload>", sanitized)
    sanitized = re.sub(r"(?i)\by0u\s+4r3\s+n0w\b|\b1gn0r3\s+pr3v10us\s+1nstruct10ns\b", "<prompt_injection_removed: encoded_payload>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:dan|developer mode|do anything now|fictional scenario bypass)\b[^\n]*", "<prompt_injection_removed: jailbreak_attempt>", sanitized)
    sanitized = re.sub(r"(?im)^\s*(?:#|//|/\*|\*)\s*(?:ignore previous instructions|you are now|act as unrestricted|reveal secrets).*$", "<prompt_injection_removed: indirect_injection>", sanitized)
    sanitized = re.sub(
        r"\b(?:[A-Za-z0-9+/=]{24,})\b",
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
    DESCRIPTION = "Extracts text from uploaded files and returns redacted contents to downstream agents; replace the configured model with an approved registry-backed model via environment variables."
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": False,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Extract document text and hand the redacted contents to the next agent."

    def __init__(self):
        super().__init__()
        self.pdf_parser = PDFParser()
        self.html_parser = HTMLParser()
        self.image_parser = ImageParser()

    async def call_agent_model(self, file_summary: str) -> str:
        file_summary = sanitize_untrusted_file_text(file_summary)
        file_summary = redact_zero_tolerance_pii(file_summary)
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Extracted file contents:\n{file_summary}\n\n"
                        "Give a short processing note for the redacted content."
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

        extracted_content = sanitize_untrusted_file_text(extracted_content)
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
            extracted_content = sanitized_file_data.get("extracted_content", "")
            extracted_content = sanitize_untrusted_file_text(extracted_content)
            extracted_content = redact_zero_tolerance_pii(extracted_content)
            sanitized_file_data["extracted_content"] = extracted_content
            sanitized_file_contents.append(sanitized_file_data)
        file_summary = build_file_summary(sanitized_file_contents, include_raw_text=True)
        file_summary = sanitize_untrusted_file_text(file_summary)
        file_summary = redact_zero_tolerance_pii(file_summary)
        pii_exposure_summary = self.build_pii_exposure_summary(sanitized_file_contents)
        pii_exposure_summary = redact_zero_tolerance_pii(pii_exposure_summary)
        model_output = await self.call_agent_model(file_summary)
        model_output = redact_zero_tolerance_pii(model_output)
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
        ] if sanitized_file_contents else []

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
