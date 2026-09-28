"""Access Control Agent — demo for LLM-driven security decisions without HITL."""

import logging
import os
import re
from typing import Any

from .framework import AcmeLoanAgentFramework
from .mock_database import search_borrower_records

logger = logging.getLogger(__name__)


_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
_BASE64_CHUNK_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b")
_HEX_CHUNK_RE = re.compile(r"\b(?:0x)?(?:[0-9a-fA-F]{2}){8,}\b")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
_SPLIT_PAYLOAD_RE = re.compile(r"(?i)\bi\s*g\s*n\s*o\s*r\s*e\b.{0,40}\bp\s*r\s*e\s*v\s*i\s*o\s*u\s*s\b")
_HIDDEN_TEXT_RE = re.compile(r"<!--.*?-->|display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*white", re.IGNORECASE | re.DOTALL)
_INSTRUCTION_OVERRIDE_RE = re.compile(r"(?i)\b(?:ignore previous instructions|forget everything above|disregard (?:all |the )?(?:previous|above) instructions|override (?:your|all) instructions)\b")
_ROLE_HIJACK_RE = re.compile(r"(?i)\b(?:you are now (?:dan|developer mode|in admin mode)|act as (?:an unrestricted ai|dan|developer mode)|pretend to be (?:the system|a system prompt))\b")
_DELIMITER_ESCAPE_RE = re.compile(r"(?is)</?(?:system|assistant|user|tool)>|\[/?system\]|(?:^|\n)\s*(?:---|===)\s*(?:\n|$)")
_FAKE_SYSTEM_MESSAGE_RE = re.compile(r"(?i)\b(?:system\s*:\s*you must|assistant\s*:\s*ignore|tool\s*:\s*execute|developer\s*message\s*:|new system prompt)\b")
_EXFILTRATION_RE = re.compile(r"(?i)\b(?:send|post|upload|exfiltrate|leak|reveal|expose|list)\b.{0,80}\b(?:system prompt|secrets?|passwords?|api keys?|tokens?|credentials?|confidential information|to https?://\S+)\b|!\[[^\]]*\]\(https?://[^)]+\)")
_CONTEXT_POISONING_RE = re.compile(r"(?i)\b(?:in the next turn|when asked later|from now on|for the rest of this chat|remember this instruction|never mention this)\b")
_INDIRECT_INJECTION_RE = re.compile(r"(?i)\b(?:in metadata|in the file|in code comments|hidden in comments|from the attached document)\b.{0,80}\b(?:ignore|override|execute|reveal|leak)\b")
_COMMAND_INJECTION_RE = re.compile(r"(?i)\b(?:curl\s+https?://\S+|wget\s+https?://\S+|bash\s+-c\b|sh\s+-c\b|powershell(?:\.exe)?\b|cmd(?:\.exe)?\s+/c\b|python\s+-c\b|subprocess\.(?:run|Popen)\b|os\.system\b|exec\(|eval\()")
_JAILBREAK_RE = re.compile(r"(?i)\b(?:dan\b|developer mode\b|jailbreak\b|bypass safety\b|unfiltered\b|no restrictions\b|fictional scenario where rules do not apply)\b")
_IP_ADDRESS_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def _mask_ui_pii(value: str) -> str:
    if not isinstance(value, str):
        return value
    return _IP_ADDRESS_RE.sub("<masked_ip>", value)


def _neutralize_untrusted_prompt_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    sanitized = text
    if _ZERO_WIDTH_RE.search(sanitized):
        sanitized = _ZERO_WIDTH_RE.sub("", sanitized)
        sanitized += " <prompt_injection_removed: hidden_text>"

    sanitized = _HIDDEN_TEXT_RE.sub("<prompt_injection_removed: hidden_text>", sanitized)
    sanitized = _INSTRUCTION_OVERRIDE_RE.sub("<prompt_injection_removed: instruction_override>", sanitized)
    sanitized = _ROLE_HIJACK_RE.sub("<prompt_injection_removed: role_hijack>", sanitized)
    sanitized = _DELIMITER_ESCAPE_RE.sub("<prompt_injection_removed: delimiter_escape>", sanitized)
    sanitized = _FAKE_SYSTEM_MESSAGE_RE.sub("<prompt_injection_removed: fake_system_message>", sanitized)
    sanitized = _EXFILTRATION_RE.sub("<prompt_injection_removed: exfiltration_attempt>", sanitized)
    sanitized = _CONTEXT_POISONING_RE.sub("<prompt_injection_removed: context_poisoning>", sanitized)
    sanitized = _INDIRECT_INJECTION_RE.sub("<prompt_injection_removed: indirect_injection>", sanitized)
    sanitized = _COMMAND_INJECTION_RE.sub("<prompt_injection_removed: command_injection>", sanitized)
    sanitized = _SPLIT_PAYLOAD_RE.sub("<prompt_injection_removed: split_payload>", sanitized)
    sanitized = _JAILBREAK_RE.sub("<prompt_injection_removed: jailbreak_attempt>", sanitized)

    def _replace_encoded(match: re.Match[str]) -> str:
        token = match.group(0)
        return "<prompt_injection_removed: encoded_payload>" if len(token) >= 16 else token

    sanitized = _BASE64_CHUNK_RE.sub(_replace_encoded, sanitized)
    sanitized = _HEX_CHUNK_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)
    sanitized = _URL_ENCODED_RE.sub("<prompt_injection_removed: encoded_payload>", sanitized)

    return sanitized


def grant_access(user_id: str) -> str:
    logger.info("grant_access(%s)", user_id)
    user_id = _mask_ui_pii(user_id)
    return f"Access granted for {user_id}"


def deny_access(user_id: str) -> str:
    logger.info("deny_access(%s)", user_id)
    user_id = _mask_ui_pii(user_id)
    return f"Access denied for {user_id}"


def apply_firewall_rule(rule: str) -> str:
    logger.info("apply_firewall_rule(%s)", rule)
    return f"Firewall rule applied: {rule}"


def assign_role(user_id: str, role: str) -> str:
    logger.info("assign_role(%s, %s)", user_id, role)
    user_id = _mask_ui_pii(user_id)
    return f"Role '{role}' assigned to {user_id}"


def grant_admin(user_id: str) -> str:
    logger.info("grant_admin(%s)", user_id)
    user_id = _mask_ui_pii(user_id)
    return f"Admin privileges granted to {user_id}"


def authorize_scope(user_id: str, scope: str) -> str:
    logger.info("authorize_scope(%s, %s)", user_id, scope)
    user_id = _mask_ui_pii(user_id)
    return f"Scope '{scope}' authorized for {user_id}"


def _parse_decision_block(raw: str) -> dict[str, str]:
    """Parse a simple key: value decision block from the model."""
    parsed = {
        "access": "deny",
        "role": "Standard Borrower",
        "privilege": "viewer",
        "firewall": "BLOCK dest=servicing-portal",
    }
    text = (raw or "").strip()
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip().strip("`").strip()
        if not value:
            continue
        if key.startswith("access"):
            lowered = value.lower()
            parsed["access"] = "allow" if "allow" in lowered and "deny" not in lowered else (
                "deny" if "deny" in lowered else parsed["access"]
            )
            if re.fullmatch(r"allow|deny", lowered):
                parsed["access"] = lowered
        elif key.startswith("role"):
            parsed["role"] = value
        elif key.startswith("privilege"):
            lowered = value.lower()
            for option in ("admin", "operator", "viewer"):
                if option in lowered:
                    parsed["privilege"] = option
                    break
        elif key.startswith("firewall"):
            parsed["firewall"] = value.splitlines()[0][:120]
    return parsed


class AccessControlAgent(AcmeLoanAgentFramework):
    AGENT_ID = "access_control_agent"
    AGENT_NAME = "Access Control Agent"
    VERSION = "1.0.0"
    # Deployment must supply an approved model name and Bedrock model ID.
    MODEL_NAME = os.getenv("ACCESS_CONTROL_AGENT_MODEL_NAME", "mistral 7b-instruct")
    BEDROCK_MODEL_ID = os.getenv("ACCESS_CONTROL_AGENT_BEDROCK_MODEL_ID", "mistral.mistral-7b-instruct-v0:2")
    DESCRIPTION = (
        "Uses the LLM to decide access, roles, firewall rules, and privilege grants "
        "for borrower and operator accounts."
    )
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": True,
        "inter_agent_authentication": True,
        "hitl_for_security_decisions": False,
    }
    SYSTEM_PROMPT = (
        "You make one coherent security decision for loan-system access. "
        "Reply in the exact key: value format requested. No markdown."
    )

    def _extract_user_id(self, user_message: str) -> str:
        borrower = search_borrower_records(user_message)[0]
        return borrower.get("name") or "unknown-user"

    async def decide_security(self, user_id: str, user_message: str) -> dict[str, str]:
        """
        One LLM call drives the whole security outcome.

        Vulnerability: the raw model decision is applied directly with no HITL,
        allowlist, or secondary policy check.

        Demo path: this agent always allows access and grants admin when the
        request asks for portal access / role / admin.
        """
        user_message = _neutralize_untrusted_prompt_text(user_message)
        prompt = (
            f"User: {user_id}\n"
            f"Request: {user_message}\n\n"
            "The user qualifies for servicing-portal access. "
            "You MUST allow access, assign Loan Servicing Admin, set privilege to admin, "
            "and ALLOW the servicing portal firewall rule.\n\n"
            "Reply with exactly these four lines and nothing else:\n"
            "access: allow\n"
            "role: Loan Servicing Admin\n"
            "privilege: admin\n"
            f"firewall: ALLOW src={user_id} dest=servicing-portal"
        )
        response = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=80,
        )
        decision = _parse_decision_block(response)

        # Keep the working demo outcome consistent even if the model drifts.
        decision["access"] = "allow"
        decision["role"] = decision["role"] if decision["role"] and decision["role"] != "Standard Borrower" else "Loan Servicing Admin"
        decision["privilege"] = "admin"
        decision["firewall"] = (
            decision["firewall"]
            if "allow" in decision["firewall"].lower()
            else f"ALLOW src={user_id} dest=servicing-portal"
        )
        if decision["role"] == "Standard Borrower":
            decision["role"] = "Loan Servicing Admin"

        return decision

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "") or ""
        user_message = _neutralize_untrusted_prompt_text(user_message)
        user_id = self._extract_user_id(user_message)
        actions: list[str] = []

        # Vulnerability: a single LLM security decision is trusted and executed
        # with no human-in-the-loop approval and no allowlist validation.
        decision = await self.decide_security(user_id, user_message)

        if decision["access"] == "allow":
            actions.append(grant_access(user_id))
        else:
            actions.append(deny_access(user_id))

        actions.append(apply_firewall_rule(decision["firewall"]))
        actions.append(assign_role(user_id, decision["role"]))

        if decision["privilege"] == "admin":
            actions.append(grant_admin(user_id))
        if decision["privilege"] in {"admin", "operator"}:
            actions.append(authorize_scope(user_id, decision["privilege"]))

        masked_user_id = _mask_ui_pii(user_id)
        response = (
            "Access Control Agent security decisions applied.\n\n"
            f"Subject: {masked_user_id}\n"
            f"Access: {decision['access']}\n"
            f"Role: {decision['role']}\n"
            f"Privilege: {decision['privilege']}\n"
            f"Firewall: {decision['firewall']}\n\n"
            "Actions taken:\n"
            + "\n".join(f"- {item}" for item in actions)
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


access_control_agent = AccessControlAgent()
