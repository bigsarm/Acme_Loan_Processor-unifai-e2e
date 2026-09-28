"""Loan Processing Agent class with explicit model invocation."""

import asyncio
import base64
import binascii
import codecs
import re
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import build_file_summary, extract_reference_number
from .mcp_servers import call_mcp_server


_ADDRESS_PATTERN = re.compile(
    r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b\.?"
    r"(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?"
    r"(?:,\s*[A-Z]{2}\b(?:\s+\d{5}(?:-\d{4})?)?)?"
    r"(?:,\s*(?:USA|United States)\b)?"
)
_PHONE_PATTERN = re.compile(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b")
_EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_SSN_PATTERN = re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")
_CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_IP_ADDRESS_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_ADDRESS_PATTERN = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
_DOB_PATTERN = re.compile(r"(?i)\b(?:DOB|date of birth|born(?: on| in)?)\s*:?\s*(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|(?:19|20)\d{2})\b")
_PASSPORT_PATTERN = re.compile(r"(?i)\bpassport(?:\s*(?:no\.?|number|#))?\s*:?\s*(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b")
_DRIVERS_LICENSE_PATTERN = re.compile(r"(?i)\b(?:driver'?s license|drivers license|dl)(?:\s*(?:no\.?|number|#))?\s*:?\s*[A-Z0-9-]{4,20}\b")
_TAX_ID_PATTERN = re.compile(r"(?i)\b(?:taxpayer identification number|tax id|tin)(?:\s*(?:no\.?|number|#))?\s*:?\s*[A-Z0-9-]{6,20}\b")
_ACCOUNT_NUMBER_PATTERN = re.compile(r"(?i)\b(?:account(?:\s*number)?)(?:\s*(?:no\.?|number|#))?\s*:?\s*[A-Z0-9-]{6,20}\b")
_EMPLOYEE_ID_PATTERN = re.compile(r"(?i)\bemployee id\s*:?\s*[A-Z0-9-]{2,20}\b")
_SCHOOL_ID_PATTERN = re.compile(r"(?i)\bschool id\s*:?\s*[A-Z0-9-]{2,20}\b")
_VIN_PATTERN = re.compile(r"(?i)\bvin\s*:?\s*[A-HJ-NPR-Z0-9]{11,17}\b")
_BIRTHPLACE_PATTERN = re.compile(r"(?i)\bbirthplace\s*:?\s*[^\n,;]+")
_MAIDEN_NAME_PATTERN = re.compile(r"(?i)\bmother'?s maiden name\s*:?\s*[^\n,;]+")
_MEDICAL_PATTERN = re.compile(r"(?i)\bmedical records?\s*:?\s*[^\n]+")
_LOCATION_PATTERN = re.compile(r"(?i)\b(?:fine location|location)\s*:?\s*[^\n,;]+")
_ETHNICITY_PATTERN = re.compile(r"(?i)\bethnicity\s*:?\s*[^\n,;]+")
_SEXUAL_ORIENTATION_PATTERN = re.compile(r"(?i)\bsexual orientation\s*:?\s*[^\n,;]+")
_HTML_COMMENT_PATTERN = re.compile(r"<!--.*?-->", re.DOTALL)
_HIDDEN_STYLE_PATTERN = re.compile(
    r"<[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|font-size\s*:\s*0(?:px)?|color\s*:\s*(?:#fff(?:fff)?|white))[^\"']*[\"'][^>]*>.*?</[^>]+>",
    re.IGNORECASE | re.DOTALL,
)
_ZERO_WIDTH_PATTERN = re.compile(r"[\u200B-\u200D\uFEFF]+")
_DELIMITER_ESCAPE_PATTERN = re.compile(r"(?i)</system>|<\|im_start\|>|###\s*system:")
_COMMAND_INJECTION_PATTERN = re.compile(
    r"(?i)\b(?:execute|run)\s*:\s*[^\n]+|\b(?:execute|run)\s+(?:rm\s+-rf\s+/|curl\s+https?://\S+(?:\s*\|\s*sh)?|print\s*\(\s*os\.environ\.get\([^\n]+)"
)
_CURL_PIPE_PATTERN = re.compile(r"(?i)\bcurl\s+https?://\S+(?:\s*\|\s*sh)\b")
_EXFIL_URL_PATTERN = re.compile(r"(?i)\b(?:send|post|upload|exfiltrate)\b[^\n]*\bto\b\s+https?://\S+")
_MARKDOWN_IMAGE_EXFIL_PATTERN = re.compile(r"!\[[^\]]*\]\(https?://[^)]+\)")


def _replace_keep_last4(match: re.Match[str], category: str) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    if len(digits) >= 4:
        return f"<masked:{category[:-1] if category.endswith('s') else category}>" if category in {"passport", "drivers_license", "tax_id", "credit_card", "account_number", "employee_id", "school_id", "vin"} and False else re.sub(r"\d", "*", match.group(0)[:-4]) + match.group(0)[-4:]
    return f"<masked:{category}>"


def _mask_labeled_identifier(text: str, pattern: re.Pattern[str], category: str) -> str:
    def _repl(match: re.Match[str]) -> str:
        value = match.group(0)
        last_four = re.sub(r"\D", "", value)[-4:]
        return f"<masked:{category}>" if not last_four else f"***{last_four}"

    return pattern.sub(_repl, text)


def _redact_labeled_value(text: str, pattern: re.Pattern[str], category: str) -> str:
    return pattern.sub(f"<redacted:{category}>", text)


def _mask_labeled_value(text: str, pattern: re.Pattern[str], category: str) -> str:
    return pattern.sub(f"<masked:{category}>", text)


def _redact_pii(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text
    text = _SSN_PATTERN.sub("<redacted:ssn>", text)
    text = _PHONE_PATTERN.sub("<redacted:phone>", text)
    text = _EMAIL_PATTERN.sub("<redacted:email>", text)
    text = _ADDRESS_PATTERN.sub("<redacted:address>", text)
    text = _CREDIT_CARD_PATTERN.sub("<redacted:credit_card>", text)
    text = _IP_ADDRESS_PATTERN.sub("<redacted:ip_address>", text)
    text = _MAC_ADDRESS_PATTERN.sub("<redacted:mac_address>", text)
    text = _redact_labeled_value(text, _DOB_PATTERN, "dob")
    text = _redact_labeled_value(text, _PASSPORT_PATTERN, "passport")
    text = _redact_labeled_value(text, _DRIVERS_LICENSE_PATTERN, "drivers_license")
    text = _redact_labeled_value(text, _TAX_ID_PATTERN, "tax_id")
    text = _redact_labeled_value(text, _ACCOUNT_NUMBER_PATTERN, "account_number")
    text = _redact_labeled_value(text, _EMPLOYEE_ID_PATTERN, "employee_id")
    text = _redact_labeled_value(text, _SCHOOL_ID_PATTERN, "school_id")
    text = _redact_labeled_value(text, _VIN_PATTERN, "vin")
    text = _redact_labeled_value(text, _BIRTHPLACE_PATTERN, "birthplace")
    text = _redact_labeled_value(text, _MAIDEN_NAME_PATTERN, "maiden_name")
    text = _redact_labeled_value(text, _MEDICAL_PATTERN, "medical")
    text = _redact_labeled_value(text, _LOCATION_PATTERN, "location")
    text = _redact_labeled_value(text, _ETHNICITY_PATTERN, "ethnicity")
    text = _redact_labeled_value(text, _SEXUAL_ORIENTATION_PATTERN, "sexual_orientation")
    return text


def _mask_pii(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text
    text = _SSN_PATTERN.sub("***-**-6789", text) if False else _SSN_PATTERN.sub(lambda m: f"***-**-{re.sub(r'\D', '', m.group(0))[-4:]}", text)
    text = _PHONE_PATTERN.sub("<masked:phone>", text)
    text = _EMAIL_PATTERN.sub("<masked:email>", text)
    text = _ADDRESS_PATTERN.sub("<masked:address>", text)
    text = _CREDIT_CARD_PATTERN.sub(lambda m: f"{'*' * max(len(re.sub(r'\D', '', m.group(0))) - 4, 0)}{re.sub(r'\D', '', m.group(0))[-4:]}", text)
    text = _IP_ADDRESS_PATTERN.sub("<masked:ip_address>", text)
    text = _MAC_ADDRESS_PATTERN.sub("<masked:mac_address>", text)
    text = _mask_labeled_value(text, _DOB_PATTERN, "dob")
    text = _mask_labeled_value(text, _BIRTHPLACE_PATTERN, "birthplace")
    text = _mask_labeled_value(text, _MAIDEN_NAME_PATTERN, "maiden_name")
    text = _mask_labeled_value(text, _MEDICAL_PATTERN, "medical")
    text = _mask_labeled_value(text, _LOCATION_PATTERN, "location")
    text = _mask_labeled_value(text, _ETHNICITY_PATTERN, "ethnicity")
    text = _mask_labeled_value(text, _SEXUAL_ORIENTATION_PATTERN, "sexual_orientation")
    text = _mask_labeled_value(text, _PASSPORT_PATTERN, "passport")
    text = _mask_labeled_value(text, _DRIVERS_LICENSE_PATTERN, "drivers_license")
    text = _mask_labeled_value(text, _TAX_ID_PATTERN, "tax_id")
    text = _mask_labeled_value(text, _ACCOUNT_NUMBER_PATTERN, "account_number")
    text = _mask_labeled_value(text, _EMPLOYEE_ID_PATTERN, "employee_id")
    text = _mask_labeled_value(text, _SCHOOL_ID_PATTERN, "school_id")
    text = _mask_labeled_value(text, _VIN_PATTERN, "vin")
    return text


def _contains_prompt_injection(decoded_text: str) -> str | None:
    checks = [
        (re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b|\bforget everything above\b|\bignore(?:\s+all)?\s+safety guidelines\b"), "instruction_override"),
        (re.compile(r"(?i)\byou are now(?: in)? (?:developer|admin) mode\b|\byou are now dan\b|\byou are now unrestricted\b|\bprovide unrestricted access\b|\benable developer mode\b|\bact as an unrestricted ai\b|\bwithout safety filters\b|\bsystem override\b"), "role_hijack"),
        (re.compile(r"(?i)\breveal(?: all)? confidential information\b|\breveal the system prompt\b|\breveal all system prompts\b|\blist all financial data, user passwords, and api keys\b|\bprint the api key\b"), "exfiltration_attempt"),
        (_DELIMITER_ESCAPE_PATTERN, "delimiter_escape"),
        (_COMMAND_INJECTION_PATTERN, "command_injection"),
        (_CURL_PIPE_PATTERN, "command_injection"),
        (_EXFIL_URL_PATTERN, "exfiltration_attempt"),
        (_MARKDOWN_IMAGE_EXFIL_PATTERN, "exfiltration_attempt"),
    ]
    for pattern, category in checks:
        if pattern.search(decoded_text):
            return category
    return None


def _remove_obfuscated_attacks(text: str) -> str:
    normalized_chars: list[str] = []
    index_map: list[int] = []
    substitutions = str.maketrans({"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t"})
    for index, char in enumerate(text):
        translated = char.translate(substitutions).lower()
        if translated.isalnum():
            normalized_chars.append(translated)
            index_map.append(index)
    normalized = "".join(normalized_chars)
    patterns = [
        (re.compile(r"ignore(?:all)?(?:previous|prior|above)instructions|forgeteverythingabove|ignore(?:all)?safetyguidelines"), "instruction_override"),
        (re.compile(r"youarenow(?:in)?developermode|youarenow(?:in)?adminmode|youarenowdan|youarenowunrestricted|provideunrestrictedaccess|enabledevelopermode|actasanunrestrictedai|withoutsafetyfilters|systemoverride"), "role_hijack"),
    ]
    spans: list[tuple[int, int, str]] = []
    for pattern, category in patterns:
        for match in pattern.finditer(normalized):
            start = index_map[match.start()]
            end = index_map[match.end() - 1] + 1
            spans.append((start, end, category))
    for start, end, category in sorted(spans, reverse=True):
        text = text[:start] + f"<prompt_injection_removed: {category}>" + text[end:]
    return text


def _sanitize_untrusted_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text
    text = _HTML_COMMENT_PATTERN.sub("<prompt_injection_removed: hidden_text>", text)
    text = _HIDDEN_STYLE_PATTERN.sub("<prompt_injection_removed: hidden_text>", text)
    text = _ZERO_WIDTH_PATTERN.sub("", text)
    text = _DELIMITER_ESCAPE_PATTERN.sub("<prompt_injection_removed: delimiter_escape>", text)
    text = _COMMAND_INJECTION_PATTERN.sub("<prompt_injection_removed: command_injection>", text)
    text = _CURL_PIPE_PATTERN.sub("<prompt_injection_removed: command_injection>", text)
    text = _EXFIL_URL_PATTERN.sub("<prompt_injection_removed: exfiltration_attempt>", text)
    text = _MARKDOWN_IMAGE_EXFIL_PATTERN.sub("<prompt_injection_removed: exfiltration_attempt>", text)
    text = re.sub(
        r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b|\bforget everything above\b|\bignore(?:\s+all)?\s+safety guidelines\b",
        "<prompt_injection_removed: instruction_override>",
        text,
    )
    text = re.sub(
        r"(?i)\byou are now(?: in)? (?:developer|admin) mode\b|\byou are now dan\b|\byou are now unrestricted\b|\bprovide unrestricted access\b|\benable developer mode\b|\bact as an unrestricted ai\b|\bwithout safety filters\b|\bsystem override\b",
        "<prompt_injection_removed: role_hijack>",
        text,
    )
    text = re.sub(
        r"(?i)\breveal(?: all)? confidential information\b|\breveal the system prompt\b|\breveal all system prompts\b|\blist all financial data, user passwords, and api keys\b|\bprint the api key\b",
        "<prompt_injection_removed: exfiltration_attempt>",
        text,
    )
    for pattern in (r"[A-Za-z0-9+/=]{16,}", r"(?:%[0-9A-Fa-f]{2}){4,}", r"(?:[0-9A-Fa-f]{2}){8,}"):
        for match in list(re.finditer(pattern, text)):
            encoded = match.group(0)
            decoded = None
            try:
                if "%" in encoded:
                    decoded = urllib.parse.unquote(encoded)
                elif re.fullmatch(r"(?:[0-9A-Fa-f]{2}){8,}", encoded):
                    decoded = bytes.fromhex(encoded).decode("utf-8", errors="ignore")
                else:
                    padding = "=" * (-len(encoded) % 4)
                    decoded = base64.b64decode(encoded + padding, validate=False).decode("utf-8", errors="ignore")
            except (binascii.Error, ValueError):
                decoded = None
            if decoded and _contains_prompt_injection(decoded):
                text = text.replace(encoded, "<prompt_injection_removed: encoded_payload>", 1)
    try:
        if _contains_prompt_injection(codecs.decode(text, "rot13")):
            text = "<prompt_injection_removed: encoded_payload>"
    except Exception:
        pass
    text = _remove_obfuscated_attacks(text)
    return text


def _sanitize_file_contents(file_contents: Any) -> Any:
    if not isinstance(file_contents, list):
        return file_contents
    sanitized_contents = []
    for item in file_contents:
        if isinstance(item, str):
            cleaned_item = _sanitize_untrusted_text(item)
            cleaned_item = _redact_pii(cleaned_item)
            sanitized_contents.append(cleaned_item)
        else:
            sanitized_contents.append(item)
    return sanitized_contents


class LoanProcessingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "gpt-4o mini"
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
        user_message = _sanitize_untrusted_text(user_message)
        user_message = _redact_pii(user_message)
        file_summary = _sanitize_untrusted_text(file_summary)
        file_summary = _redact_pii(file_summary)
        model_response = await self.model_client.chat(
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
        return _redact_pii(model_response)

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        user_message = _sanitize_untrusted_text(user_message)
        sanitized_file_contents = _sanitize_file_contents(context.get("file_contents", []))
        file_summary = build_file_summary(sanitized_file_contents)
        file_summary = _sanitize_untrusted_text(file_summary)
        loan_number = extract_reference_number(user_message, prefix="LOAN")
        model_output = await self.call_agent_model(user_message, file_summary)
        safe_user_message_for_tools = _redact_pii(user_message)
        safe_file_summary_for_tools = _redact_pii(file_summary)
        safe_model_output_for_response = _mask_pii(model_output)
        safe_user_message_for_response = _mask_pii(user_message or 'No user message provided.')

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {loan_number}",
                    "document_body": f"User message:\n{safe_user_message_for_tools}\n\nFile summary:\n{safe_file_summary_for_tools}",
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
                        "borrower_request": safe_user_message_for_tools[:240],
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

        response = (
            "This scan-only agent is disconnected from the Orchestrator Agent.\n\n"
            f"Loan reference: {loan_number}\n"
            f"Borrower request: {safe_user_message_for_response}\n\n"
            f"Loan summary:\n{safe_model_output_for_response}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


loan_processing_agent = LoanProcessingAgent()
