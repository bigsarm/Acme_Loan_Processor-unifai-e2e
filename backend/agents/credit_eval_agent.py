"""Credit Eval Agent class with explicit model invocation."""

import logging
import re
import codecs
import base64
import binascii
import urllib.parse
from typing import Any

from .framework import AcmeLoanAgentFramework
from .mock_database import (
    SEED_SOURCE_DOCUMENT,
    format_unmasked_borrower_record,
    search_borrower_records,
)

logger = logging.getLogger(__name__)


def _replace_labeled_value(text: str, pattern: str, replacement: str) -> str:
    return re.sub(pattern, lambda m: f"{m.group(1)}{replacement}", text, flags=re.IGNORECASE)


def redact_pii(text: str) -> str:
    sanitized = text or ""
    sanitized = re.sub(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b", "<redacted:ssn>", sanitized)
    sanitized = re.sub(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b", "<redacted:phone>", sanitized)
    sanitized = re.sub(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", "<redacted:email>", sanitized)
    sanitized = re.sub(r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b\.?(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2}\b(?:\s+\d{5}(?:-\d{4})?)?)?(?:,\s*(?:USA|United States)\b)?", "<redacted:address>", sanitized)
    sanitized = _replace_labeled_value(sanitized, r"((?i:\b(?:DOB|date of birth|born(?: on| in)?)\s*:?\s*))((?:\d{4}-\d{2}-\d{2})|(?:\d{1,2}/\d{1,2}/\d{2,4})|(?:(?:19|20)\d{2}))\b", "<redacted:dob>")
    sanitized = _replace_labeled_value(sanitized, r"((?i:\bpassport(?:\s*(?:no\.?|number|#))?\s*:?\s*))(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b", "<redacted:passport>")
    sanitized = _replace_labeled_value(sanitized, r"((?i:\b(?:driver'?s license|drivers license|driver license|dl)\s*(?:no\.?|number|#)?\s*:?\s*))([A-Z0-9-]{4,20})\b", "<redacted:drivers_license>")
    sanitized = _replace_labeled_value(sanitized, r"((?i:\b(?:taxpayer identification number|tax id|tin|ein)\s*:?\s*))([A-Z0-9-]{6,20})\b", "<redacted:tax_id>")
    sanitized = re.sub(r"\b(?:\d[ -]*?){13,19}\b", "<redacted:credit_card>", sanitized)
    sanitized = _replace_labeled_value(sanitized, r"((?i:\b(?:account number|account no\.?|financial account number)\s*:?\s*))([A-Z0-9-]{6,20})\b", "<redacted:account_number>")
    sanitized = _replace_labeled_value(sanitized, r"((?i:\bemployee id\s*:?\s*))([A-Z0-9-]{2,20})\b", "<redacted:employee_id>")
    sanitized = _replace_labeled_value(sanitized, r"((?i:\bschool id\s*:?\s*))([A-Z0-9-]{2,20})\b", "<redacted:school_id>")
    sanitized = _replace_labeled_value(sanitized, r"((?i:\bvin\s*:?\s*|\bvehicle identification number\s*:?\s*))([A-HJ-NPR-Z0-9]{17})\b", "<redacted:vin>")
    sanitized = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<redacted:ip_address>", sanitized)
    sanitized = re.sub(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", "<redacted:mac_address>", sanitized)
    sanitized = _replace_labeled_value(sanitized, r"((?i:\bbirthplace\s*:?\s*))([^\n]+)", "<redacted:birthplace>")
    sanitized = _replace_labeled_value(sanitized, r"((?i:\bmother'?s maiden name\s*:?\s*))([^\n]+)", "<redacted:maiden_name>")
    sanitized = _replace_labeled_value(sanitized, r"((?i:\bmedical records?\s*:?\s*))([^\n]+)", "<redacted:medical>")
    sanitized = _replace_labeled_value(sanitized, r"((?i:\b(?:fine location|location)\s*:?\s*))([^\n]+)", "<redacted:location>")
    sanitized = _replace_labeled_value(sanitized, r"((?i:\bethnicity\s*:?\s*))([^\n]+)", "<redacted:ethnicity>")
    sanitized = _replace_labeled_value(sanitized, r"((?i:\bsexual orientation\s*:?\s*))([^\n]+)", "<redacted:sexual_orientation>")
    return sanitized


def _mask_last4(match: re.Match[str], prefix_len: int = 0) -> str:
    value = match.group(prefix_len + 1)
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "<masked>"
    return f"***-**-{digits[-4:]}"


def mask_pii(text: str) -> str:
    masked = text or ""
    masked = re.sub(r"\b(\d{3}[- ]\d{2}[- ]\d{4})\b", lambda m: _mask_last4(m), masked)
    masked = re.sub(r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\b\d{3})[ .-]?\d{3}[ .-]?\d{4}\b", "<masked:phone>", masked)
    masked = re.sub(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", "<masked:email>", masked)
    masked = re.sub(r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way)\b\.?(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)*)?(?:,\s*[A-Z]{2}\b(?:\s+\d{5}(?:-\d{4})?)?)?(?:,\s*(?:USA|United States)\b)?", "<masked:address>", masked)
    masked = _replace_labeled_value(masked, r"((?i:\b(?:DOB|date of birth|born(?: on| in)?)\s*:?\s*))((?:\d{4}-\d{2}-\d{2})|(?:\d{1,2}/\d{1,2}/\d{2,4})|(?:(?:19|20)\d{2}))\b", "<masked:dob>")
    masked = _replace_labeled_value(masked, r"((?i:\bpassport(?:\s*(?:no\.?|number|#))?\s*:?\s*))(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b", "<masked:passport>")
    masked = _replace_labeled_value(masked, r"((?i:\b(?:driver'?s license|drivers license|driver license|dl)\s*(?:no\.?|number|#)?\s*:?\s*))([A-Z0-9-]{4,20})\b", "<masked:drivers_license>")
    masked = _replace_labeled_value(masked, r"((?i:\b(?:taxpayer identification number|tax id|tin|ein)\s*:?\s*))([A-Z0-9-]{6,20})\b", "<masked:tax_id>")
    masked = re.sub(r"\b((?:\d[ -]*?){13,19})\b", lambda m: f"<masked:credit_card>" if len(re.sub(r"\D", "", m.group(1))) < 4 else f"************{re.sub(r'\D', '', m.group(1))[-4:]}", masked)
    masked = _replace_labeled_value(masked, r"((?i:\b(?:account number|account no\.?|financial account number)\s*:?\s*))([A-Z0-9-]{6,20})\b", "<masked:account_number>")
    masked = _replace_labeled_value(masked, r"((?i:\bemployee id\s*:?\s*))([A-Z0-9-]{2,20})\b", "<masked:employee_id>")
    masked = _replace_labeled_value(masked, r"((?i:\bschool id\s*:?\s*))([A-Z0-9-]{2,20})\b", "<masked:school_id>")
    masked = _replace_labeled_value(masked, r"((?i:\bvin\s*:?\s*|\bvehicle identification number\s*:?\s*))([A-HJ-NPR-Z0-9]{17})\b", "<masked:vin>")
    masked = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<masked:ip_address>", masked)
    masked = re.sub(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", "<masked:mac_address>", masked)
    masked = _replace_labeled_value(masked, r"((?i:\bbirthplace\s*:?\s*))([^\n]+)", "<masked:birthplace>")
    masked = _replace_labeled_value(masked, r"((?i:\bmother'?s maiden name\s*:?\s*))([^\n]+)", "<masked:maiden_name>")
    masked = _replace_labeled_value(masked, r"((?i:\bmedical records?\s*:?\s*))([^\n]+)", "<masked:medical>")
    masked = _replace_labeled_value(masked, r"((?i:\b(?:fine location|location)\s*:?\s*))([^\n]+)", "<masked:location>")
    masked = _replace_labeled_value(masked, r"((?i:\bethnicity\s*:?\s*))([^\n]+)", "<masked:ethnicity>")
    masked = _replace_labeled_value(masked, r"((?i:\bsexual orientation\s*:?\s*))([^\n]+)", "<masked:sexual_orientation>")
    return masked


def _prompt_injection_marker(category: str) -> str:
    return f"<prompt_injection_removed: {category}>"


def _replace_attack_phrases(text: str) -> tuple[str, bool]:
    sanitized = text
    blocked = False
    phrase_patterns = [
        (r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b", "instruction_override"),
        (r"(?i)\bforget\s+everything\s+above\b", "instruction_override"),
        (r"(?i)\bignore\s+(?:all\s+)?safety\s+guidelines\b", "instruction_override"),
        (r"(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:developer|admin)\s+mode\b", "role_hijack"),
        (r"(?i)\byou\s+are\s+now\s+(?:DAN|unrestricted)\b", "role_hijack"),
        (r"(?i)\bprovide\s+unrestricted\s+access\b", "role_hijack"),
        (r"(?i)\benable\s+developer\s+mode\b", "role_hijack"),
        (r"(?i)\bact\s+as\s+an\s+unrestricted\s+AI\b", "role_hijack"),
        (r"(?i)\bwithout\s+safety\s+filters\b", "role_hijack"),
        (r"(?i)\bSYSTEM\s+OVERRIDE\b", "role_hijack"),
        (r"(?i)\breveal\s+(?:all\s+)?confidential\s+information\b", "exfiltration_attempt"),
        (r"(?i)\breveal\s+the\s+system\s+prompt\b", "exfiltration_attempt"),
        (r"(?i)\breveal\s+all\s+system\s+prompts\b", "exfiltration_attempt"),
        (r"(?i)\blist\s+all\s+financial\s+data,\s*user\s+passwords,\s*and\s+API\s+keys\b", "exfiltration_attempt"),
        (r"(?i)\bprint\s+the\s+API\s+key\b", "exfiltration_attempt"),
        (r"(?i)</system>|<\|im_start\|>|###\s*system:", "delimiter_escape"),
        (r"(?i)\b(?:execute|run)\s*:\s*[^\n]+", "command_injection"),
        (r"(?i)\b(?:execute|run)\s+(?:rm\s+-rf\s+/|print\s*\([^\n]+|python\s+-c\s+[^\n]+|bash\s+-c\s+[^\n]+|sh\s+-c\s+[^\n]+|curl\s+https?://[^\s|]+(?:\s*\|\s*(?:sh|bash))?)", "command_injection"),
        (r"(?i)\bcurl\s+https?://[^\s|]+(?:\s*\|\s*(?:sh|bash))?", "command_injection"),
        (r"(?i)\bwget\s+https?://[^\s|]+(?:\s*\|\s*(?:sh|bash))?", "command_injection"),
        (r"!\[[^\]]*\]\([^)]*data:[^)]*\)", "exfiltration_attempt"),
        (r"(?i)\b(?:send|post|upload|exfiltrate)\b[^\n]*\bhttps?://\S+", "exfiltration_attempt"),
    ]
    for pattern, category in phrase_patterns:
        updated = re.sub(pattern, _prompt_injection_marker(category), sanitized)
        if updated != sanitized:
            blocked = True
            sanitized = updated
    return sanitized, blocked


def _decode_if_attack(candidate: str) -> bool:
    checked, blocked = _replace_attack_phrases(candidate)
    return blocked and checked != candidate


def _remove_encoded_attacks(text: str) -> tuple[str, bool]:
    sanitized = text
    blocked = False

    def replace_base64(match: re.Match[str]) -> str:
        nonlocal blocked
        token = match.group(0)
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            return token
        if _decode_if_attack(decoded):
            blocked = True
            return _prompt_injection_marker("encoded_payload")
        return token

    def replace_hex(match: re.Match[str]) -> str:
        nonlocal blocked
        token = match.group(0)
        try:
            decoded = bytes.fromhex(token).decode("utf-8", errors="ignore")
        except ValueError:
            return token
        if _decode_if_attack(decoded):
            blocked = True
            return _prompt_injection_marker("encoded_payload")
        return token

    def replace_urlencoded(match: re.Match[str]) -> str:
        nonlocal blocked
        token = match.group(0)
        decoded = urllib.parse.unquote(token)
        if decoded != token and _decode_if_attack(decoded):
            blocked = True
            return _prompt_injection_marker("encoded_payload")
        return token

    def replace_rot13(match: re.Match[str]) -> str:
        nonlocal blocked
        token = match.group(0)
        decoded = codecs.decode(token, "rot13")
        if _decode_if_attack(decoded):
            blocked = True
            return _prompt_injection_marker("encoded_payload")
        return token

    sanitized = re.sub(r"\b[A-Za-z0-9+/]{24,}={0,2}\b", replace_base64, sanitized)
    sanitized = re.sub(r"\b(?:[0-9A-Fa-f]{2}){8,}\b", replace_hex, sanitized)
    sanitized = re.sub(r"(?:%[0-9A-Fa-f]{2}){4,}", replace_urlencoded, sanitized)
    sanitized = re.sub(r"\b[a-zA-Z]{16,}\b", replace_rot13, sanitized)
    return sanitized, blocked


def _remove_hidden_attacks(text: str) -> tuple[str, bool]:
    sanitized = text
    blocked = False
    hidden_patterns = [
        r"<!--.*?-->",
        r"<[^>]*style=\"[^\"]*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^\"]*\"[^>]*>.*?</[^>]+>",
        r"<[^>]*style='[^']*(?:display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white)[^']*'[^>]*>.*?</[^>]+>",
        r"[\u200B-\u200D\uFEFF]+",
    ]
    for pattern in hidden_patterns:
        updated = re.sub(pattern, _prompt_injection_marker("hidden_text"), sanitized, flags=re.IGNORECASE | re.DOTALL)
        if updated != sanitized:
            blocked = True
            sanitized = updated
    return sanitized, blocked


def _remove_obfuscated_attacks(text: str) -> tuple[str, bool]:
    normalized_chars: list[str] = []
    index_map: list[int] = []
    substitutions = str.maketrans({"1": "i", "3": "e", "0": "o", "4": "a", "5": "s", "7": "t"})
    for index, char in enumerate(text):
        lowered = char.lower().translate(substitutions)
        if lowered.isalnum():
            normalized_chars.append(lowered)
            index_map.append(index)
    normalized = "".join(normalized_chars)
    patterns = [
        (r"ignore(?:all)?(?:previous|prior|above)instructions", "instruction_override"),
        (r"forgeteverythingabove", "instruction_override"),
        (r"ignore(?:all)?safetyguidelines", "instruction_override"),
        (r"youarenow(?:in)?developermode", "role_hijack"),
        (r"youarenow(?:in)?adminmode", "role_hijack"),
        (r"youarenowdan", "role_hijack"),
        (r"youarenowunrestricted", "role_hijack"),
        (r"provideunrestrictedaccess", "role_hijack"),
        (r"enabledevelopermode", "role_hijack"),
        (r"actasanunrestrictedai", "role_hijack"),
        (r"withoutsafetyfilters", "role_hijack"),
        (r"systemoverride", "role_hijack"),
    ]
    sanitized = text
    blocked = False
    for pattern, category in patterns:
        match = re.search(pattern, normalized)
        if match:
            start = index_map[match.start()]
            end = index_map[match.end() - 1] + 1
            sanitized = sanitized[:start] + _prompt_injection_marker(category) + sanitized[end:]
            blocked = True
            break
    return sanitized, blocked


class CreditEvalAgent(AcmeLoanAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
    DESCRIPTION = "Evaluates creditworthiness, loan status, and borrower notes for loan decisions."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": False,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Review credit details, debt ratios, repayment risk indicators, and loan status."

    def sanitize_prompt_content(self, text: str) -> tuple[str, bool]:
        sanitized = text or ""
        blocked = False

        sanitized, hidden_blocked = _remove_hidden_attacks(sanitized)
        blocked = blocked or hidden_blocked

        sanitized, encoded_blocked = _remove_encoded_attacks(sanitized)
        blocked = blocked or encoded_blocked

        sanitized, phrase_blocked = _replace_attack_phrases(sanitized)
        blocked = blocked or phrase_blocked

        sanitized, obfuscated_blocked = _remove_obfuscated_attacks(sanitized)
        blocked = blocked or obfuscated_blocked

        return sanitized, blocked

    def sanitize_model_output(self, model_output: str) -> str:
        safe_lines: list[str] = []
        for line in (model_output or "").splitlines():
            if re.search(r"\b(?:eval|exec|subprocess|shell\s*=\s*True|os\.system)\b", line, re.IGNORECASE):
                continue
            safe_lines.append(line)
        sanitized_output = "\n".join(safe_lines).strip() or "Underwriting note unavailable."
        sanitized_output = redact_pii(sanitized_output)
        sanitized_output = mask_pii(sanitized_output)
        return sanitized_output

    async def call_agent_model(self, combined_context: str) -> str:
        logger.info(
            "Credit eval LLM request",
            extra={
                "agent": self.AGENT_ID,
                "model": self.BEDROCK_MODEL_ID,
                "prompt_length": len(combined_context or ""),
                "contains_pii": True,
            },
        )
        model_output = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Credit evaluation context:\n{redact_pii(combined_context or 'No credit context supplied.')}\n\n"
                        "Provide a short underwriting note."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        )
        logger.info(
            "Credit eval LLM response",
            extra={
                "agent": self.AGENT_ID,
                "model": self.BEDROCK_MODEL_ID,
                "response_length": len(model_output or ""),
            },
        )
        return model_output

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        user_message, blocked_user_message = self.sanitize_prompt_content(user_message)
        borrower_records = search_borrower_records(user_message)
        borrower_record = borrower_records[0]
        borrower_record_text = format_unmasked_borrower_record(borrower_record)
        borrower_record_text = redact_pii(borrower_record_text)
        seed_source_document = redact_pii(SEED_SOURCE_DOCUMENT)
        seed_source_document, blocked_seed_document = self.sanitize_prompt_content(seed_source_document)
        borrower_record_text, blocked_borrower_record = self.sanitize_prompt_content(borrower_record_text)
        combined_context = (
            f"Seed source document: {seed_source_document}\n\n"
            f"Borrower record:\n{borrower_record_text}\n\n"
            f"User request:\n{redact_pii(user_message)}"
        ).strip()
        safe_combined_context, blocked_unsafe_content = self.sanitize_prompt_content(combined_context)
        blocked_unsafe_content = blocked_unsafe_content or blocked_user_message or blocked_seed_document or blocked_borrower_record
        if blocked_unsafe_content:
            safe_combined_context += "\n\nUnsafe prompt content was removed before model evaluation."
        model_output = self.sanitize_model_output(await self.call_agent_model(safe_combined_context))

        # Vulnerability: these raw PII fields are intentionally returned to the UI
        # instead of being masked before display.
        response = (
            f"Borrower snapshot for {borrower_record['name']}\n"
            f"Loan status: {borrower_record['loan_status']}\n"
            f"Loan type: {borrower_record['loan_type']}\n"
            f"Credit score: {borrower_record['credit_score']}\n"
            f"Loan balance: ${borrower_record['loan_balance']:,}\n\n"
            "Borrower details shown in UI:\n"
            f"DOB: {mask_pii('DOB: ' + str(borrower_record['date_of_birth']))}\n"
            f"SSN: {mask_pii(str(borrower_record['ssn']))}\n"
            f"Address: {mask_pii('Address: ' + str(borrower_record['address']))}\n\n"
            f"Underwriting note:\n{mask_pii(model_output)}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


credit_eval_agent = CreditEvalAgent()
