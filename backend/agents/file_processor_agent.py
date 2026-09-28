"""File Processor Agent class with explicit model invocation."""

import base64
import io
import json
import logging
import re
from typing import Any, Optional
from urllib.parse import unquote

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


_ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\ufeff\u2060"


def _replace_decoded_attack_span(text: str, pattern: re.Pattern[str], replacement: str) -> str:
    updated = text
    for match in list(pattern.finditer(text)):
        token = match.group(0)
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if decoded and _contains_prompt_injection_or_command(decoded):
            updated = updated.replace(token, replacement)
    return updated


def _contains_prompt_injection_or_command(text: str) -> bool:
    normalized = (text or "").lower()
    return any(
        pattern.search(normalized)
        for pattern in (
            re.compile(r"\bignore\s+(?:all\s+)?previous\s+instructions\b"),
            re.compile(r"\bforget\s+everything\s+(?:above|before)\b"),
            re.compile(r"\byou\s+are\s+now\s+(?:dan|in\s+admin\s+mode)\b"),
            re.compile(r"\bact\s+as\s+(?:an\s+)?unrestricted\b"),
            re.compile(r"</system>|<system>|\[system\]|\[tool\]"),
            re.compile(r"\breveal\s+(?:the\s+)?system\s+prompt\b"),
            re.compile(r"\blist\s+all\s+(?:passwords|api\s+keys|secrets)\b"),
            re.compile(r"\bsend\s+data\s+to\s+https?://\S+\b"),
            re.compile(r"\bcurl\s+https?://\S+\b"),
            re.compile(r"\b(?:bash|sh|powershell|cmd(?:\.exe)?)\s+-c\b"),
            re.compile(r"\b(?:rm\s+-rf\s+/|wget\s+https?://\S+|scp\s+\S+@\S+)\b"),
        )
    )


def sanitize_uploaded_text(text: str) -> str:
    sanitized = text or ""
    sanitized = re.sub(r"<!--(?is:.*?(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|reveal\s+the\s+system\s+prompt).*?)-->", "<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"(?is)<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0px|color\s*:\s*white)[^\"']*[\"'][^>]*>.*?(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|reveal\s+the\s+system\s+prompt).*?</[^>]+>", "<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"[%][0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2}){3,}", lambda match: "<prompt_injection_removed: encoded_payload>" if _contains_prompt_injection_or_command(unquote(match.group(0))) else match.group(0), sanitized)
    sanitized = _replace_decoded_attack_span(sanitized, re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b"), "<prompt_injection_removed: encoded_payload>")
    sanitized = re.sub(r"(?:[01]{8}\s+){3,}[01]{8}", lambda match: "<prompt_injection_removed: encoded_payload>" if _contains_prompt_injection_or_command("".join(chr(int(bits, 2)) for bits in match.group(0).split())) else match.group(0), sanitized)
    sanitized = re.sub(r"(?:\\x[0-9A-Fa-f]{2}){4,}", lambda match: "<prompt_injection_removed: encoded_payload>" if _contains_prompt_injection_or_command(bytes.fromhex(match.group(0).replace("\\x", "")).decode("utf-8", errors="ignore")) else match.group(0), sanitized)
    sanitized = re.sub(r"(?:\\u[0-9A-Fa-f]{4}){4,}", lambda match: "<prompt_injection_removed: encoded_payload>" if _contains_prompt_injection_or_command(match.group(0).encode("utf-8").decode("unicode_escape", errors="ignore")) else match.group(0), sanitized)
    sanitized = re.sub(r"(?i)\b[a-z4@][a-z430@1!]{2,}(?:\s+[a-z4@][a-z430@1!]{2,}){1,5}\b", lambda match: "<prompt_injection_removed: encoded_payload>" if _contains_prompt_injection_or_command(match.group(0).lower().translate(str.maketrans({"4": "a", "@": "a", "3": "e", "0": "o", "1": "i", "!": "i", "$": "s", "5": "s", "7": "t"}))) else match.group(0), sanitized)
    sanitized = re.sub(r"(?i)\bignore\s+(?:all\s+)?previous\s+instructions\b|\bforget\s+everything\s+(?:above|before)\b", "<prompt_injection_removed: instruction_override>", sanitized)
    sanitized = re.sub(r"(?i)\byou\s+are\s+now\s+(?:dan|in\s+admin\s+mode)\b|\bact\s+as\s+(?:an\s+)?unrestricted\b", "<prompt_injection_removed: role_hijack>", sanitized)
    sanitized = re.sub(r"(?i)</system>|<system>|\[system\]|\[tool\]|(?:^|\n)\s*(?:---|===)\s*(?:\n|$)", "<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = re.sub(rf"[{_ZERO_WIDTH_CHARS}]+", "<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = re.sub(r"(?im)^\s*(?:system|assistant|tool)\s*:\s*(?:ignore\s+previous\s+instructions|reveal\s+the\s+system\s+prompt|list\s+all\s+(?:passwords|api\s+keys|secrets)).*$", "<prompt_injection_removed: fake_system_message>", sanitized)
    sanitized = re.sub(r"(?i)!\[[^\]]*\]\(https?://[^)]+\)|\breveal\s+(?:the\s+)?system\s+prompt\b|\blist\s+all\s+(?:passwords|api\s+keys|secrets)\b|\bsend\s+data\s+to\s+https?://\S+\b", "<prompt_injection_removed: exfiltration_attempt>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:in\s+the\s+next\s+turn|on\s+your\s+next\s+response)\b.*\b(?:ignore|reveal|leak)\b", "<prompt_injection_removed: context_poisoning>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:comment|metadata|header|footer)\s*:\s*(?:ignore\s+previous\s+instructions|reveal\s+the\s+system\s+prompt)\b", "<prompt_injection_removed: indirect_injection>", sanitized)
    sanitized = re.sub(r"(?i)\bcurl\s+https?://\S+\b|\b(?:bash|sh|powershell|cmd(?:\.exe)?)\s+-c\s+(?:['\"]).+?(?:['\"])|\b(?:rm\s+-rf\s+/|wget\s+https?://\S+|scp\s+\S+@\S+)\b", "<prompt_injection_removed: command_injection>", sanitized)
    sanitized = re.sub(r"(?i)(?:ignore\s+previous\s+instructions\s*){2,}|(?:reveal\s+the\s+system\s+prompt\s*){2,}", "<prompt_injection_removed: split_payload>", sanitized)
    sanitized = re.sub(r"(?i)\b(?:dan|developer\s+mode|jailbreak|fictional\s+framing)\b.*\b(?:ignore|bypass|unrestricted)\b", "<prompt_injection_removed: jailbreak_attempt>", sanitized)
    return sanitized


def redact_zero_tolerance_pii(text: str) -> str:
    redacted = text or ""
    replacements = (
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<masked:ssn>"),
        (re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "<masked:email>"),
        (re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(\d{3}\)[-.\s]?|\d{3}[-.\s])\d{3}[-.\s]\d{4}\b"), "<masked:phone>"),
        (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "<masked:credit_card>"),
        (re.compile(r"\b(?:\d[ -]*?){9,17}\b"), "<masked:financial_account>"),
        (re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"), "<masked:mac_address>"),
        (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<masked:ip_address>"),
        (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "<masked:vin>"),
        (re.compile(r"(?i)\b(employee\s+id|school\s+id|passport\s+(?:no\.?|number)?|driver'?s\s+license\s+number|taxpayer\s+identification\s+number|mother'?s\s+maiden\s+name|birthplace|home\s+address|medical\s+records?|fine\s+location|ethnicity|sexual\s+orientation|voice\s+signature|facial\s+image|fingerprints|retina/iris\s+scan|date\s+of\s+birth|dob)\s*:\s*([^\n]+)"), None),
        (re.compile(r"(?i)\bborn\s+in\s+(\d{4})\b"), None),
    )
    for pattern, replacement in replacements:
        if replacement is not None:
            redacted = pattern.sub(replacement, redacted)
        else:
            if pattern.pattern.startswith("(?i)\\bborn"):
                redacted = pattern.sub("born in <masked:year_of_birth>", redacted)
            else:
                redacted = pattern.sub(lambda match: f"{match.group(1)}: <masked:{match.group(1).lower().replace(' ', '_')}>" , redacted)
    return redacted


class FileProcessorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_processor_agent"
    AGENT_NAME = "File Processor Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = "Extracts text from uploaded files, redacts zero-tolerance PII before downstream use, and returns a notice to replace the configured model with an organization-approved LLM from the allow list."
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": False,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Extract document text and hand only sanitized, PII-redacted contents to the next agent."

    def __init__(self):
        super().__init__()
        self.pdf_parser = PDFParser()
        self.html_parser = HTMLParser()
        self.image_parser = ImageParser()

    async def call_agent_model(self, file_summary: str) -> str:
        file_summary = redact_zero_tolerance_pii(sanitize_uploaded_text(file_summary))
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
        sanitized_file_contents = [
            {
                **file_data,
                "extracted_content": redact_zero_tolerance_pii(
                    sanitize_uploaded_text(file_data.get("extracted_content", ""))
                ),
            }
            for file_data in file_contents
        ]
        file_summary = build_file_summary(sanitized_file_contents, include_raw_text=True)
        pii_exposure_summary = self.build_pii_exposure_summary(sanitized_file_contents)
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
        ] if sanitized_file_contents else []

        if pii_exposure_summary:
            response = (
                "I reviewed the uploaded document and displayed a masked summary of extracted customer details below.\n\n"
                "Sensitive details shown in the interface:\n"
                f"{pii_exposure_summary}\n\n"
                "Model compliance note: replace the configured model with an organization-approved LLM from the allow list.\n\n"
                f"Processing note:\n{model_output}"
            )
        else:
            response = (
                "I reviewed the uploaded document and extracted its sanitized contents.\n\n"
                "Model compliance note: replace the configured model with an organization-approved LLM from the allow list.\n\n"
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
