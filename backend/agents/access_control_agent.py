"""Access Control Agent — demo for LLM-driven security decisions without HITL."""

import logging
import os
import re
from typing import Any

from .framework import AcmeLoanAgentFramework
from .mock_database import search_borrower_records

logger = logging.getLogger(__name__)


_PROMPT_INJECTION_REPLACEMENTS: list[tuple[str, str]] = [
    (r"(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|above|earlier)\b.{0,40}\b(instruction|prompt|message|context)s?\b", "<prompt_injection_removed: instruction_override>"),
    (r"(?i)\byou\s+are\s+now\b.{0,80}\b(dan|developer mode|unrestricted|root)\b", "<prompt_injection_removed: role_hijack>"),
    (r"(?i)\bact\s+as\b.{0,80}\b(unrestricted|dan|system|developer)\b", "<prompt_injection_removed: role_hijack>"),
    (r"(?i)</?system>|</?assistant>|</?user>|\[system\]|\[assistant\]|\[user\]|<<<?\s*system\s*>>>?", "<prompt_injection_removed: delimiter_escape>"),
    (r"(?i)(?:[A-F0-9]{2}\s*){8,}|(?:[A-Za-z0-9+/]{20,}={0,2})|(?:%[0-9A-Fa-f]{2}){4,}", "<prompt_injection_removed: encoded_payload>"),
    (r"[\u200B-\u200F\u2060\uFEFF]|(?i)<!--.*?(instruction|ignore|system|prompt).*?-->", "<prompt_injection_removed: hidden_text>"),
    (r"(?i)^(system|assistant|tool)\s*:\s*", "<prompt_injection_removed: fake_system_message>"),
    (r"(?i)!\[[^\]]*\]\([^\)]*\)|\b(exfiltrate|leak|send\s+.*\s+to\s+https?://|reveal\s+.*system\s+prompt)\b", "<prompt_injection_removed: exfiltration_attempt>"),
    (r"(?i)\b(in\s+the\s+next\s+message|from\s+now\s+on|across\s+turns|persist\s+this|remember\s+this\s+instruction)\b", "<prompt_injection_removed: context_poisoning>"),
    (r"(?i)\b(metadata|comment|hidden\s+field|data\s+field|file\s+content)\b.{0,40}\b(ignore|override|instruction|prompt)\b", "<prompt_injection_removed: indirect_injection>"),
    (r"(?i)\b(rm\s+-rf|curl\b|wget\b|powershell\b|bash\b|sh\b|cmd\.exe\b|/bin/sh\b|python\s+-c\b|subprocess\b|os\.system\b|eval\b|exec\b)\b", "<prompt_injection_removed: command_injection>"),
    (r"(?i)(?:\b[a-z]\b\W*){6,}", "<prompt_injection_removed: split_payload>"),
    (r"(?i)\b(DAN|developer\s+mode|jailbreak|fictional\s+framing|bypass\s+safety)\b", "<prompt_injection_removed: jailbreak_attempt>"),
]


def _sanitize_untrusted_text(text: str) -> str:
    sanitized = text or ""
    for pattern, replacement in _PROMPT_INJECTION_REPLACEMENTS:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.MULTILINE | re.DOTALL)
    return sanitized


def _contains_blocked_prompt_content(text: str) -> bool:
    candidate = text or ""
    suspicious_patterns = [
        r"[\u200B-\u200F\u2060\uFEFF]",
        r"(?i)<!--.*?-->",
        r"(?i)(?:[A-Za-z0-9+/]{20,}={0,2})",
        r"(?i)(?:%[0-9A-Fa-f]{2}){4,}",
        r"(?i)\b(?:n0w|1gn0r3|byp4ss|d3v3l0p3r|pr0mpt)\b",
        r"(?i)\b(?:rm\s+-rf|curl\b|wget\b|powershell\b|bash\b|cmd\.exe\b|/bin/sh\b|python\s+-c\b|subprocess\b|os\.system\b|eval\b|exec\b)\b",
        r"(?i)\b(?:ignore\s+previous\s+instructions|forget\s+everything\s+above|you\s+are\s+now|act\s+as\s+unrestricted)\b",
        r"(?i)\b(?:MZ|ELF)\b",
    ]
    return any(re.search(pattern, candidate, flags=re.MULTILINE | re.DOTALL) for pattern in suspicious_patterns)


def _protect_prompt_input(text: str) -> str:
    sanitized = _sanitize_untrusted_text(text)
    if _contains_blocked_prompt_content(sanitized):
        raise ValueError("Blocked unsafe prompt content in user-controlled input")
    return sanitized


def grant_access(user_id: str) -> str:
    logger.info("grant_access(%s)", user_id)
    return f"Access granted for {user_id}"


def deny_access(user_id: str) -> str:
    logger.info("deny_access(%s)", user_id)
    return f"Access denied for {user_id}"


def apply_firewall_rule(rule: str) -> str:
    logger.info("apply_firewall_rule(%s)", rule)
    return f"Firewall rule applied: {rule}"


def assign_role(user_id: str, role: str) -> str:
    logger.info("assign_role(%s, %s)", user_id, role)
    return f"Role '{role}' assigned to {user_id}"


def grant_admin(user_id: str) -> str:
    logger.info("grant_admin(%s)", user_id)
    return f"Admin privileges granted to {user_id}"


def authorize_scope(user_id: str, scope: str) -> str:
    logger.info("authorize_scope(%s, %s)", user_id, scope)
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
    # Replace these defaults with an organization-approved LLM from the runtime model registry allow list.
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
        protected_user_message = _protect_prompt_input(user_message)
        borrower = search_borrower_records(protected_user_message)[0]
        borrower_name = _sanitize_untrusted_text(str(borrower.get("name") or "unknown-user"))
        return borrower_name or "unknown-user"

    async def decide_security(self, user_id: str, user_message: str) -> dict[str, str]:
        """
        One LLM call drives the whole security outcome.

        Vulnerability: the raw model decision is applied directly with no HITL,
        allowlist, or secondary policy check.

        Demo path: this agent always allows access and grants admin when the
        request asks for portal access / role / admin.
        """
        user_id = _sanitize_untrusted_text(user_id)
        user_message = _protect_prompt_input(user_message)
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
        user_message = _protect_prompt_input(user_message)
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

        response = (
            "Access Control Agent security decisions applied.\n\n"
            f"Subject: {user_id}\n"
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
