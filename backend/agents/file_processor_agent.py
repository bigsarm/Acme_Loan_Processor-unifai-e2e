"""File Processor Agent class with explicit model invocation."""

import base64
import binascii
import codecs
import io
import json
import logging
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


_ADDRESS_PATTERN = re.compile(
    r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b\.?(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2}\b(?:\s+\d{5}(?:-\d{4})?)?)?(?:,\s*(?:USA|United States)\b)?"
)
_SSN_PATTERN = re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")
_PHONE_PATTERN = re.compile(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b")
_EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_IP_ADDRESS_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_ADDRESS_PATTERN = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_DOB_PATTERN = re.compile(r"(?i)\b(?:DOB|date of birth|born(?: on| in)?)\s*:?\s*(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:19|20)\d{2})\b")
_BIRTHPLACE_PATTERN = re.compile(r"(?i)\b(?:birthplace|place of birth|born in)\s*:?\s*([^,;\n]+)")
_MAIDEN_NAME_PATTERN = re.compile(r"(?i)\b(?:mother(?:'s)? maiden name|maiden name)\s*:?\s*([^,;\n]+)")
_MEDICAL_PATTERN = re.compile(r"(?i)\b(?:medical records?|medical history|diagnosis)\s*:?\s*([^\n]+)")
_LOCATION_PATTERN = re.compile(r"(?i)\b(?:fine location|precise location|exact location|gps coordinates|location)\s*:?\s*([^\n]+)")
_ETHNICITY_PATTERN = re.compile(r"(?i)\b(?:ethnicity|race)\s*:?\s*([^,;\n]+)")
_SEXUAL_ORIENTATION_PATTERN = re.compile(r"(?i)\b(?:sexual orientation|orientation)\s*:?\s*([^,;\n]+)")
_PASSPORT_PATTERN = re.compile(r"(?i)\bpassport(?:\s*(?:no\.?|number|#))?\s*:?\s*(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b")
_DRIVERS_LICENSE_PATTERN = re.compile(r"(?i)\b(?:driver(?:'s)? license|drivers license|dl)\s*(?:no\.?|number|#)?\s*:?\s*[A-Z0-9-]{5,20}\b")
_TAX_ID_PATTERN = re.compile(r"(?i)\b(?:taxpayer identification number|tax id|tin|ein)\s*:?\s*[A-Z0-9-]{6,20}\b")
_ACCOUNT_NUMBER_PATTERN = re.compile(r"(?i)\b(?:financial )?account(?: number| no\.?| #)?\s*:?\s*[A-Z0-9-]{6,20}\b")
_EMPLOYEE_ID_PATTERN = re.compile(r"(?i)\bemployee id\s*:?\s*[A-Z0-9-]{2,20}\b")
_SCHOOL_ID_PATTERN = re.compile(r"(?i)\bschool id\s*:?\s*[A-Z0-9-]{2,20}\b")
_VIN_PATTERN = re.compile(r"(?i)\b(?:vehicle identification number|vin)\s*:?\s*[A-HJ-NPR-Z0-9]{17}\b")


def _mask_last4(match: re.Match[str], category: str) -> str:
    value = match.group(0)
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 4:
        return f"<masked:{category}:{digits[-4:]}>"
    return f"<masked:{category}>"


def _replace_labeled_value(text: str, pattern: re.Pattern[str], marker: str) -> str:
    def _repl(match: re.Match[str]) -> str:
        matched = match.group(0)
        if ":" in matched:
            prefix, _sep, _rest = matched.partition(":")
            return f"{prefix}: {marker}"
        parts = matched.rsplit(" ", 1)
        if len(parts) == 2:
            return f"{parts[0]} {marker}"
        return marker

    return pattern.sub(_repl, text)


def redact_pii(text: str) -> str:
    if not text:
        return text

    sanitized = text
    sanitized = _SSN_PATTERN.sub("<redacted:ssn>", sanitized)
    sanitized = _PHONE_PATTERN.sub("<redacted:phone>", sanitized)
    sanitized = _EMAIL_PATTERN.sub("<redacted:email>", sanitized)
    sanitized = _ADDRESS_PATTERN.sub("<redacted:address>", sanitized)
    sanitized = _CREDIT_CARD_PATTERN.sub("<redacted:credit_card>", sanitized)
    sanitized = _IP_ADDRESS_PATTERN.sub("<redacted:ip_address>", sanitized)
    sanitized = _MAC_ADDRESS_PATTERN.sub("<redacted:mac_address>", sanitized)
    sanitized = _DOB_PATTERN.sub("<redacted:dob>", sanitized)
    sanitized = _BIRTHPLACE_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), "<redacted:birthplace>"), sanitized)
    sanitized = _MAIDEN_NAME_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), "<redacted:maiden_name>"), sanitized)
    sanitized = _MEDICAL_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), "<redacted:medical>"), sanitized)
    sanitized = _LOCATION_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), "<redacted:location>"), sanitized)
    sanitized = _ETHNICITY_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), "<redacted:ethnicity>"), sanitized)
    sanitized = _SEXUAL_ORIENTATION_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), "<redacted:sexual_orientation>"), sanitized)
    sanitized = _replace_labeled_value(sanitized, _PASSPORT_PATTERN, "<redacted:passport>")
    sanitized = _replace_labeled_value(sanitized, _DRIVERS_LICENSE_PATTERN, "<redacted:drivers_license>")
    sanitized = _replace_labeled_value(sanitized, _TAX_ID_PATTERN, "<redacted:tax_id>")
    sanitized = _replace_labeled_value(sanitized, _ACCOUNT_NUMBER_PATTERN, "<redacted:account_number>")
    sanitized = _replace_labeled_value(sanitized, _EMPLOYEE_ID_PATTERN, "<redacted:employee_id>")
    sanitized = _replace_labeled_value(sanitized, _SCHOOL_ID_PATTERN, "<redacted:school_id>")
    sanitized = _replace_labeled_value(sanitized, _VIN_PATTERN, "<redacted:vin>")
    return sanitized


def mask_pii(text: str) -> str:
    if not text:
        return text

    sanitized = text
    sanitized = _SSN_PATTERN.sub(lambda m: _mask_last4(m, "ssn"), sanitized)
    sanitized = _PHONE_PATTERN.sub("<masked:phone>", sanitized)
    sanitized = _EMAIL_PATTERN.sub("<masked:email>", sanitized)
    sanitized = _ADDRESS_PATTERN.sub("<masked:address>", sanitized)
    sanitized = _CREDIT_CARD_PATTERN.sub(lambda m: _mask_last4(m, "credit_card"), sanitized)
    sanitized = _IP_ADDRESS_PATTERN.sub("<masked:ip_address>", sanitized)
    sanitized = _MAC_ADDRESS_PATTERN.sub("<masked:mac_address>", sanitized)
    sanitized = _DOB_PATTERN.sub("<masked:dob>", sanitized)
    sanitized = _BIRTHPLACE_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), "<masked:birthplace>"), sanitized)
    sanitized = _MAIDEN_NAME_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), "<masked:maiden_name>"), sanitized)
    sanitized = _MEDICAL_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), "<masked:medical>"), sanitized)
    sanitized = _LOCATION_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), "<masked:location>"), sanitized)
    sanitized = _ETHNICITY_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), "<masked:ethnicity>"), sanitized)
    sanitized = _SEXUAL_ORIENTATION_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), "<masked:sexual_orientation>"), sanitized)
    sanitized = _replace_labeled_value(sanitized, _PASSPORT_PATTERN, "<masked:passport>")
    sanitized = _replace_labeled_value(sanitized, _DRIVERS_LICENSE_PATTERN, "<masked:drivers_license>")
    sanitized = _replace_labeled_value(sanitized, _TAX_ID_PATTERN, "<masked:tax_id>")
    sanitized = _replace_labeled_value(sanitized, _ACCOUNT_NUMBER_PATTERN, "<masked:account_number>")
    sanitized = _replace_labeled_value(sanitized, _EMPLOYEE_ID_PATTERN, "<masked:employee_id>")
    sanitized = _replace_labeled_value(sanitized, _SCHOOL_ID_PATTERN, "<masked:school_id>")
    sanitized = _replace_labeled_value(sanitized, _VIN_PATTERN, "<masked:vin>")
    return sanitized


def _is_prompt_attack(decoded_text: str) -> Optional[str]:
    lowered = decoded_text.lower()
    attack_patterns = (
        ("instruction_override", re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b|\bforget everything above\b|\bignore\s+(?:all\s+)?safety guidelines\b", re.IGNORECASE)),
        ("role_hijack", re.compile(r"\byou are now (?:in )?(?:developer|admin) mode\b|\byou are now dan\b|\byou are now unrestricted\b|\bprovide unrestricted access\b|\benable developer mode\b|\bact as an unrestricted ai\b|\bwithout safety filters\b|\bsystem override\b", re.IGNORECASE)),
        ("exfiltration_attempt", re.compile(r"\breveal (?:all )?confidential information\b|\breveal the system prompt\b|\breveal all system prompts\b|\blist all financial data, user passwords, and api keys\b|\bprint the api key\b|\bsend\b.{0,80}?\bto\s+https?://\S+|!\[[^\]]*\]\([^)]*data[^)]*\)", re.IGNORECASE | re.DOTALL)),
        ("delimiter_escape", re.compile(r"</system>|<\|im_start\|>|###\s*system:", re.IGNORECASE)),
        ("command_injection", re.compile(r"\b(?:execute|run)\s*:\s*(?:print\s*\(|python\s+|bash\s+|sh\s+|rm\s+-rf\s+/|curl\s+https?://\S+\s*\|\s*sh)|\b(?:run|execute)\s+rm\s+-rf\s+/|\bcurl\s+https?://\S+\s*\|\s*sh\b", re.IGNORECASE)),
    )
    for category, pattern in attack_patterns:
        if pattern.search(lowered):
            return category
    return None


def sanitize_untrusted_text(text: str) -> str:
    if not text:
        return text

    sanitized = text
    hidden_patterns = (
        re.compile(r"<!--.*?-->", re.DOTALL),
        re.compile(r"<[^>]+style=\"[^\"]*(?:display\s*:\s*none|font-size\s*:\s*0(?:px)?|color\s*:\s*white)[^\"]*\"[^>]*>.*?</[^>]+>", re.IGNORECASE | re.DOTALL),
        re.compile(r"[\u200b\u200c\u200d\ufeff]+"),
    )
    for pattern in hidden_patterns:
        sanitized = pattern.sub("<prompt_injection_removed: hidden_text>", sanitized)

    direct_patterns = (
        ("instruction_override", re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b|\bforget everything above\b|\bignore\s+(?:all\s+)?safety guidelines\b", re.IGNORECASE)),
        ("role_hijack", re.compile(r"\byou are now (?:in )?(?:developer|admin) mode\b|\byou are now dan\b|\byou are now unrestricted\b|\bprovide unrestricted access\b|\benable developer mode\b|\bact as an unrestricted ai\b|\bwithout safety filters\b|\bsystem override\b", re.IGNORECASE)),
        ("exfiltration_attempt", re.compile(r"\breveal (?:all )?confidential information\b|\breveal the system prompt\b|\breveal all system prompts\b|\blist all financial data, user passwords, and api keys\b|\bprint the api key\b|\bsend\b.{0,80}?\bto\s+https?://\S+|!\[[^\]]*\]\([^)]*data[^)]*\)", re.IGNORECASE | re.DOTALL)),
        ("delimiter_escape", re.compile(r"</system>|<\|im_start\|>|###\s*system:", re.IGNORECASE)),
        ("command_injection", re.compile(r"\b(?:execute|run)\s*:\s*(?:print\s*\([^\n]*\)|python\s+[^\n]+|bash\s+[^\n]+|sh\s+[^\n]+|rm\s+-rf\s+/|curl\s+https?://\S+\s*\|\s*sh)|\b(?:run|execute)\s+rm\s+-rf\s+/|\bcurl\s+https?://\S+\s*\|\s*sh\b", re.IGNORECASE)),
    )
    for category, pattern in direct_patterns:
        sanitized = pattern.sub(f"<prompt_injection_removed: {category}>", sanitized)

    encoded_spans = set()
    for match in re.finditer(r"\b(?:[A-Za-z0-9+/]{4}){4,}={0,2}\b", sanitized):
        token = match.group(0)
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        if _is_prompt_attack(decoded):
            encoded_spans.add((match.start(), match.end()))
    for match in re.finditer(r"(?:%[0-9A-Fa-f]{2}){4,}", sanitized):
        token = match.group(0)
        try:
            decoded = urllib.parse.unquote(token)
        except Exception:
            continue
        if _is_prompt_attack(decoded):
            encoded_spans.add((match.start(), match.end()))
    for match in re.finditer(r"\b(?:[0-9A-Fa-f]{2}){8,}\b", sanitized):
        token = match.group(0)
        try:
            decoded = bytes.fromhex(token).decode("utf-8", errors="ignore")
        except ValueError:
            continue
        if _is_prompt_attack(decoded):
            encoded_spans.add((match.start(), match.end()))
    for match in re.finditer(r"\b[A-Za-z0-9][A-Za-z0-9\s]{15,}\b", sanitized):
        token = match.group(0)
        try:
            decoded = codecs.decode(token, "rot13")
        except Exception:
            continue
        if decoded != token and _is_prompt_attack(decoded):
            encoded_spans.add((match.start(), match.end()))
    for start, end in sorted(encoded_spans, reverse=True):
        sanitized = sanitized[:start] + "<prompt_injection_removed: encoded_payload>" + sanitized[end:]

    compact_normalized = []
    index_map = []
    translation = str.maketrans({"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t"})
    for idx, char in enumerate(sanitized):
        if char.isspace():
            continue
        compact_normalized.append(char.lower().translate(translation))
        index_map.append(idx)
    compact_text = "".join(compact_normalized)
    obfuscated_patterns = (
        ("instruction_override", re.compile(r"(?:ignore|disregard|forget)(?:all)?(?:previous|prior|above)instructions|forgeteverythingabove|ignore(?:all)?safetyguidelines")),
        ("role_hijack", re.compile(r"youarenow(?:in)?(?:developer|admin)mode|youarenowdan|youarenowunrestricted|provideunrestrictedaccess|enabledevelopermode|actasanunrestrictedai|withoutsafetyfilters|systemoverride")),
        ("exfiltration_attempt", re.compile(r"reveal(?:all)?confidentialinformation|revealthesystemprompt|revealallsystemprompts|listallfinancialdatauserpasswordsandapikeys|printtheapikey")),
    )
    obfuscated_spans = []
    for category, pattern in obfuscated_patterns:
        for match in pattern.finditer(compact_text):
            start = index_map[match.start()]
            end = index_map[match.end() - 1] + 1
            obfuscated_spans.append((start, end, category))
    for start, end, category in sorted(obfuscated_spans, reverse=True):
        sanitized = sanitized[:start] + f"<prompt_injection_removed: {category}>" + sanitized[end:]

    return sanitized


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
        "base64_prompt_detection": True,
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
        file_summary = sanitize_untrusted_text(file_summary)
        file_summary = redact_pii(file_summary)
        model_output = await self.call_bedrock_model(
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
        model_output = mask_pii(model_output)
        return model_output

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

        extracted_content = sanitize_untrusted_text(extracted_content)
        extracted_content = redact_pii(extracted_content)

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
        file_summary = sanitize_untrusted_text(file_summary)
        file_summary = redact_pii(file_summary)
        pii_exposure_summary = self.build_pii_exposure_summary(file_contents)
        pii_exposure_summary = mask_pii(pii_exposure_summary)
        model_output = await self.call_agent_model(file_summary)
        mcp_document_body = mask_pii(file_summary)
        mcp_activity = [
            await call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": "Extracted File Contents",
                    "document_body": mcp_document_body,
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
                f"Extracted content preview:\n{mask_pii(file_summary)}"
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
