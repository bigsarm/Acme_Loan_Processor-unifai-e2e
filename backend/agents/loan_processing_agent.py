"""Loan Processing Agent class with explicit model invocation."""

import asyncio
import os
import re
import urllib.parse
from typing import Any


def _mask_pii(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    redacted = text
    redacted = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "<pii_redacted:ssn>", redacted)
    redacted = re.sub(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b", "<pii_redacted:phone>", redacted)
    redacted = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "<pii_redacted:email>", redacted)
    redacted = re.sub(r"\b(?:\d[ -]*?){13,19}\b", "<pii_redacted:credit_card>", redacted)
    redacted = re.sub(r"\b\d{2}-\d{7}\b", "<pii_redacted:tin>", redacted)
    redacted = re.sub(r"\b(?:[A-Z]{1,2}\d{6,9}|\d{9})\b", "<pii_redacted:passport>", redacted)
    redacted = re.sub(r"\b[A-HJ-NPR-Z0-9]{17}\b", "<pii_redacted:vin>", redacted)
    redacted = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<pii_redacted:ip_address>", redacted)
    redacted = re.sub(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", "<pii_redacted:mac_address>", redacted)

    label_patterns = [
        (r"(?i)\b(year\s+of\s+birth|yob|dob|date\s+of\s+birth)\b\s*[:\-]\s*([^\n,;]+)", "year_of_birth"),
        (r"(?i)\b(birthplace|place\s+of\s+birth|born\s+in)\b\s*[:\-]\s*([^\n,;]+)", "birthplace"),
        (r"(?i)\b(mother'?s\s+maiden\s+name)\b\s*[:\-]\s*([^\n,;]+)", "maiden_name"),
        (r"(?i)\b(home\s+address|address)\b\s*[:\-]\s*([^\n]+)", "home_address"),
        (r"(?i)\b(passport(?:\s+number|\s+no\.?|\s+#)?)\b\s*[:\-]\s*([^\n,;]+)", "passport"),
        (r"(?i)\b(driver'?s\s+license(?:\s+number|\s+no\.?|\s+#)?|drivers\s+license(?:\s+number|\s+no\.?|\s+#)?)\b\s*[:\-]\s*([^\n,;]+)", "drivers_license"),
        (r"(?i)\b(financial\s+account(?:\s+number)?|account\s+number)\b\s*[:\-]\s*([^\n,;]+)", "financial_account"),
        (r"(?i)\b(employee\s+id)\b\s*[:\-]\s*([^\n,;]+)", "employee_id"),
        (r"(?i)\b(school\s+id|student\s+id)\b\s*[:\-]\s*([^\n,;]+)", "school_id"),
        (r"(?i)\b(fine\s+location|location)\b\s*[:\-]\s*([^\n,;]+)", "fine_location"),
        (r"(?i)\b(ethnicity)\b\s*[:\-]\s*([^\n,;]+)", "ethnicity"),
        (r"(?i)\b(sexual\s+orientation)\b\s*[:\-]\s*([^\n,;]+)", "sexual_orientation"),
        (r"(?i)\b(medical\s+records?)\b\s*[:\-]\s*([^\n]+)", "medical_records"),
        (r"(?i)\b(fingerprints?|retina/iris\s+scan|voice\s+signature|facial\s+image)\b\s*[:\-]\s*([^\n]+)", "biometric"),
    ]
    for pattern, label in label_patterns:
        redacted = re.sub(pattern, lambda m: f"{m.group(1)}: <pii_redacted:{label}>", redacted)

    return redacted


def _sanitize_untrusted_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text

    replacements = [
        (r"(?i)\b(ignore\s+previous\s+instructions|forget\s+everything\s+above|disregard\s+all\s+prior\s+instructions)\b", "<prompt_injection_removed: instruction_override>"),
        (r"(?i)\b(you\s+are\s+now\s+dan|act\s+as\s+unrestricted|act\s+as\s+an\s+unrestricted\s+ai|developer\s+mode|do\s+anything\s+now)\b", "<prompt_injection_removed: jailbreak_attempt>"),
        (r"(?i)(</system>|<system>|</assistant>|<assistant>|</user>|<user>|\[system\]|\[assistant\]|\[user\]|^\s*---\s*$|^\s*===\s*$)", "<prompt_injection_removed: delimiter_escape>"),
        (r"(?is)<!--.*?(ignore\s+previous\s+instructions|reveal\s+system\s+prompt|act\s+as\s+unrestricted).*?-->", "<prompt_injection_removed: hidden_text>"),
        (r"[\u200B-\u200F\u2060\uFEFF]+", "<prompt_injection_removed: hidden_text>"),
        (r"(?i)\b(system\s+prompt|tool\s+message|assistant\s+message)\s*:\s*(you\s+must|ignore|reveal|send)", "<prompt_injection_removed: fake_system_message>"),
        (r"(?i)\b(send|post|upload|exfiltrate|leak)\b[^\n]{0,120}\b(to|via)\b[^\n]{0,120}(https?://\S+|ftp://\S+)", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"!\[[^\]]*\]\(https?://[^)]+\)", "<prompt_injection_removed: exfiltration_attempt>"),
        (r"(?i)\b(in\s+the\s+next\s+turn|when\s+asked\s+later|persist\s+this\s+instruction|remember\s+this\s+secret\s+rule)\b", "<prompt_injection_removed: context_poisoning>"),
        (r"(?i)\b(file\s*metadata|comment|docstring|code\s*comment)\b[^\n]{0,120}\b(ignore\s+previous\s+instructions|reveal\s+system\s+prompt|act\s+as\s+unrestricted)\b", "<prompt_injection_removed: indirect_injection>"),
        (r"(?i)\b(curl\s+https?://\S+|wget\s+https?://\S+|powershell(?:\.exe)?\b[^\n]*|-enc\b|bash\s+-c\b[^\n]*|sh\s+-c\b[^\n]*|cmd\.exe\b[^\n]*|python\s+-c\b[^\n]*|os\.system\s*\(|subprocess\.(?:run|Popen|call)\s*\(|exec\s*\(|eval\s*\()", "<prompt_injection_removed: command_injection>"),
        (r"(?i)\b(y[o0]u\s+a[r4]e\s+n[o0]w\s+d[a4]n|1gn[o0]r[e3]\s+pr[e3]v[i1][o0]us\s+[i1]nstruct[i1][o0]ns)\b", "<prompt_injection_removed: encoded_payload>"),
        (r"(?i)\b(repeat\s+after\s+me\s+in\s+parts|split\s+this\s+instruction\s+across\s+messages|join\s+the\s+following\s+fragments)\b", "<prompt_injection_removed: split_payload>"),
        (r"(?i)\b(act\s+as\s+unrestricted|you\s+are\s+now\s+[^\n]{0,40}|pretend\s+to\s+be\s+the\s+system)\b", "<prompt_injection_removed: role_hijack>"),
    ]
    for pattern, replacement in replacements:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.MULTILINE)

    if re.search(r"\b(?:[A-Fa-f0-9]{2}\s*){8,}\b", sanitized):
        sanitized = re.sub(r"\b(?:[A-Fa-f0-9]{2}\s*){8,}\b", "<prompt_injection_removed: encoded_payload>", sanitized)

    base64_pattern = r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b"
    for match in re.finditer(base64_pattern, sanitized):
        candidate = match.group(0)
        try:
            decoded = __import__("base64").b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if re.search(r"(?i)\b(ignore\s+previous\s+instructions|forget\s+everything\s+above|you\s+are\s+now\s+dan|act\s+as\s+unrestricted|curl\s+https?://|wget\s+https?://|bash\s+-c|powershell|os\.system\(|subprocess\.|exec\s*\(|eval\s*\()", decoded):
            sanitized = sanitized.replace(candidate, "<prompt_injection_removed: encoded_payload>")

    url_decoded = urllib.parse.unquote(sanitized)
    if url_decoded != sanitized and re.search(r"(?i)\b(ignore\s+previous\s+instructions|you\s+are\s+now\s+dan|act\s+as\s+unrestricted|curl\s+https?://|bash\s+-c)\b", url_decoded):
        sanitized = "<prompt_injection_removed: encoded_payload>"

    return sanitized


def _sanitize_and_redact_text(text: str) -> str:
    return _mask_pii(_sanitize_untrusted_text(text))


def _sanitize_and_redact_file_contents(file_contents: Any) -> list[Any]:
    sanitized_contents = []
    for item in file_contents or []:
        if isinstance(item, str):
            sanitized_contents.append(_sanitize_and_redact_text(item))
        elif isinstance(item, dict):
            sanitized_item = {}
            for key, value in item.items():
                if isinstance(value, str):
                    sanitized_item[key] = _sanitize_and_redact_text(value)
                else:
                    sanitized_item[key] = value
            sanitized_contents.append(sanitized_item)
        else:
            sanitized_contents.append(item)
    return sanitized_contents

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary, extract_reference_number
from .mcp_servers import call_mcp_server


class LoanProcessingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    # Replace with an approved LLM from the organization's allow list via LOAN_PROCESSING_AGENT_MODEL.
    MODEL_NAME = os.getenv("LOAN_PROCESSING_AGENT_MODEL", "gpt-4o mini")
    BEDROCK_MODEL_ID = ""
    DESCRIPTION = "Handles loan application intake, borrower updates, and loan package generation."
    MCP_SERVERS = ["Docx", "Excel", "Email"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Process loan requests, summarize borrower context, and prepare follow-up actions."
    IS_ROUTABLE = False
    IS_SCAN_ONLY = True

    async def call_agent_model(self, user_message: str, file_summary: str) -> str:
        user_message = _sanitize_and_redact_text(user_message or "")
        file_summary = _sanitize_and_redact_text(file_summary or "")
        return await self.model_client.chat(
            model=self.MODEL_NAME,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Loan request:\n{user_message or 'No user message provided.'}\n\n"
                        f"File summary:\n{file_summary}\n\n"
                        "Draft a concise loan processing next-step summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        sanitized_file_contents = _sanitize_and_redact_file_contents(context.get("file_contents", []))
        file_summary = build_file_summary(sanitized_file_contents)
        loan_number = extract_reference_number(user_message, prefix="LOAN")
        model_output = await self.call_agent_model(user_message, file_summary)

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{user_message}\n\nFile summary:\n{file_summary}",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Excel",
                "upsert_row",
                {
                    "workbook": "Loan Pipeline",
                    "worksheet": "Applications",
                    "row": {
                        "loan_number": loan_number,
                        "status": "processing",
                        "borrower_request": user_message[:240],
                    },
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example"],
                    "subject": f"Loan update for {loan_number}",
                    "body": "Your loan request is being reviewed by the Loan Processing Agent.",
                },
            ),
        )

        masked_user_message = _mask_pii(user_message or "No user message provided.")
        response = (
            "This scan-only agent is disconnected from the Orchestrator Agent.\n\n"
            f"Loan reference: {loan_number}\n"
            f"Borrower request: {masked_user_message}\n\n"
            f"Loan summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


loan_processing_agent = LoanProcessingAgent()
