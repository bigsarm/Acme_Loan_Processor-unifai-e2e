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


ZERO_TOLERANCE_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("email", re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")),
    ("personal_phone_number", re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b")),
    ("year_of_birth", re.compile(r"\b(?:19|20)\d{2}\b")),
    ("passport_number", re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b")),
    ("drivers_license_number", re.compile(r"\bDL[:#\s-]*[A-Z0-9-]{5,20}\b", re.IGNORECASE)),
    ("taxpayer_identification_number", re.compile(r"\b\d{2}-\d{7}\b")),
    ("credit_card_number", re.compile(r"\b(?:\d[ -]*?){13,16}\b")),
    ("financial_account_number", re.compile(r"\b(?:account|acct)\s*(?:number|no\.?|#)?[:\s-]*\d{6,17}\b", re.IGNORECASE)),
    ("employee_id", re.compile(r"\bemployee id[:\s-]*[A-Z0-9-]{2,20}\b", re.IGNORECASE)),
    ("school_id", re.compile(r"\bschool id[:\s-]*[A-Z0-9-]{2,20}\b", re.IGNORECASE)),
    ("vehicle_identification_number", re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("mac_address", re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")),
]

ZERO_TOLERANCE_PII_KEYWORDS: list[tuple[str, re.Pattern[str]]] = [
    ("birthplace", re.compile(r"\bbirthplace\b\s*[:\-].+", re.IGNORECASE)),
    ("mothers_maiden_name", re.compile(r"\bmother'?s maiden name\b\s*[:\-].+", re.IGNORECASE)),
    ("home_address", re.compile(r"\b(?:home )?address\b\s*[:\-].+", re.IGNORECASE)),
    ("fingerprints", re.compile(r"\bfingerprint(?:s)?\b", re.IGNORECASE)),
    ("retina_iris_scan", re.compile(r"\b(?:retina|iris) scan\b", re.IGNORECASE)),
    ("voice_signature", re.compile(r"\bvoice signature\b", re.IGNORECASE)),
    ("facial_image", re.compile(r"\bfacial image\b", re.IGNORECASE)),
    ("medical_records", re.compile(r"\bmedical record(?:s)?\b", re.IGNORECASE)),
    ("fine_location", re.compile(r"\b(?:fine|precise|exact) location\b", re.IGNORECASE)),
    ("ethnicity", re.compile(r"\bethnicity\b\s*[:\-].+", re.IGNORECASE)),
    ("sexual_orientation", re.compile(r"\bsexual orientation\b\s*[:\-].+", re.IGNORECASE)),
]

PROMPT_INJECTION_REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?is)\b(ignore|disregard|forget)\b.{0,80}\b(previous|above|system|prior)\b.{0,80}\binstruction"), "<prompt_injection_removed: instruction_override>"),
    (re.compile(r"(?is)\byou are now\b.{0,80}\b(DAN|developer mode|unrestricted)\b|\bact as\b.{0,80}\b(unrestricted|system|developer)\b"), "<prompt_injection_removed: role_hijack>"),
    (re.compile(r"(?is)</?(system|assistant|user|tool)>|---\s*(system|assistant|developer)\s*prompt\s*---|```(?:system|assistant|tool)"), "<prompt_injection_removed: delimiter_escape>"),
    (re.compile(r"(?is)<!--.*?(ignore|system prompt|send data|leak|exfiltrate).*?-->"), "<prompt_injection_removed: hidden_text>"),
    (re.compile(r"[\u200b\u200c\u200d\ufeff]"), "<prompt_injection_removed: hidden_text>"),
    (re.compile(r"(?is)\b(system message|tool message|developer message)\b\s*:\s*"), "<prompt_injection_removed: fake_system_message>"),
    (re.compile(r"(?is)!\[[^\]]*\]\((?:https?://|mailto:)[^\)]*\)|\b(send|post|upload|exfiltrate|leak)\b.{0,80}\b(http|url|webhook|endpoint|system prompt|secret|credential|token|data)\b"), "<prompt_injection_removed: exfiltration_attempt>"),
    (re.compile(r"(?is)\b(in future responses|from now on|across turns|next message|subsequent replies)\b"), "<prompt_injection_removed: context_poisoning>"),
    (re.compile(r"(?is)\b(comment|metadata|header|field)\b.{0,40}\b(ignore|override|execute)\b|(?:#|//)\s*(?:ignore|execute|override)"), "<prompt_injection_removed: indirect_injection>"),
    (re.compile(r"(?is)\b(?:rm\s+-rf|curl\b|wget\b|powershell\b|bash\b|sh\b|cmd\.exe\b|/bin/sh\b|subprocess\.|os\.system\b|eval\(|exec\()"), "<prompt_injection_removed: command_injection>"),
    (re.compile(r"(?is)(?:i\s*g\s*n\s*o\s*r\s*e|d\s*a\s*n|b\s*y\s*p\s*a\s*s\s*s)"), "<prompt_injection_removed: split_payload>"),
    (re.compile(r"(?is)\b(?:DAN|developer mode|jailbreak|bypass safety|fictional scenario|no rules|unfiltered)\b"), "<prompt_injection_removed: jailbreak_attempt>"),
]

PROMPT_RISK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?is)\b(ignore|disregard|forget)\b.{0,80}\binstruction"),
    re.compile(r"(?is)\byou are now\b|\bact as\b"),
    re.compile(r"(?is)</?(system|assistant|user|tool)>|<!--|[\u200b\u200c\u200d\ufeff]"),
    re.compile(r"(?is)\b(?:rm\s+-rf|curl\b|wget\b|powershell\b|bash\b|cmd\.exe\b|eval\(|exec\()"),
    re.compile(r"(?is)\b(?:DAN|developer mode|jailbreak|bypass safety)\b"),
    re.compile(r"(?is)\b(?:[A-Za-z0-9+/]{40,}={0,2}|(?:0x)?[0-9a-f]{32,}|%[0-9A-Fa-f]{2})\b"),
    re.compile(r"(?is)\b[a4@][c(][t+][\s_-]*a[s5]\b|\b[i1!][g9][n\\/][o0]r[e3]\b"),
]


def _mask_pii_text(content: str) -> str:
    masked = content or ""
    for label, pattern in ZERO_TOLERANCE_PII_PATTERNS:
        masked = pattern.sub(f"<masked_pii:{label}>", masked)
    for label, pattern in ZERO_TOLERANCE_PII_KEYWORDS:
        masked = pattern.sub(f"<masked_pii:{label}>", masked)
    return masked


def _neutralize_prompt_injection(content: str) -> str:
    sanitized = content or ""
    for pattern, replacement in PROMPT_INJECTION_REPLACEMENTS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def _contains_prompt_risk(content: str) -> bool:
    text = content or ""
    return any(pattern.search(text) for pattern in PROMPT_RISK_PATTERNS)


def _sanitize_uploaded_text(content: str) -> str:
    sanitized = _neutralize_prompt_injection(content or "")
    sanitized = _mask_pii_text(sanitized)
    return sanitized


class FileProcessorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_processor_agent"
    AGENT_NAME = "File Processor Agent"
    VERSION = "1.0.0"
    MODEL_NAME = os.getenv("FILE_PROCESSOR_AGENT_MODEL_NAME", "mistral 7b-instruct")
    BEDROCK_MODEL_ID = os.getenv("FILE_PROCESSOR_AGENT_BEDROCK_MODEL_ID", "mistral.mistral-7b-instruct-v0:2")
    DESCRIPTION = "Extracts text from uploaded files, redacts zero-tolerance PII, and forwards sanitized contents to downstream agents."
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": False,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Extract document text and provide only sanitized, prompt-safe content to the next agent."

    def __init__(self):
        super().__init__()
        self.pdf_parser = PDFParser()
        self.html_parser = HTMLParser()
        self.image_parser = ImageParser()

    async def call_agent_model(self, file_summary: str) -> str:
        file_summary = _sanitize_uploaded_text(file_summary)
        if _contains_prompt_risk(file_summary):
            file_summary = _neutralize_prompt_injection(file_summary)
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Extracted file contents:\n{file_summary}\n\n"
                        "Give a short processing note about the sanitized contents."
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

        extracted_content = _sanitize_uploaded_text(extracted_content)
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
        file_summary = _sanitize_uploaded_text(file_summary)
        pii_exposure_summary = self.build_pii_exposure_summary(file_contents)
        pii_exposure_summary = _mask_pii_text(pii_exposure_summary)
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
                "I reviewed the uploaded document and displayed sanitized customer details below.\n\n"
                "Sensitive details shown in the interface:\n"
                f"{pii_exposure_summary}\n\n"
                f"Processing note:\n{model_output}"
            )
        else:
            response = (
                "I reviewed the uploaded document and extracted its sanitized contents.\n\n"
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
