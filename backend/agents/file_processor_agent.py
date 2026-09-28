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


class FileProcessorAgent(AcmeLoanAgentFramework):
    AGENT_ID = "file_processor_agent"
    AGENT_NAME = "File Processor Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = "Extracts text from uploaded files and returns sanitized contents to downstream agents."
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Extract document text and hand the sanitized contents to the next agent."

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
                        "Give a short processing note based only on the sanitized content."
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
        file_summary = build_file_summary(file_contents, include_raw_text=True)
        pii_exposure_summary = self.build_pii_exposure_summary(file_contents)
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
