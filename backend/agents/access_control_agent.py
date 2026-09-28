"""Access Control Agent — demo for LLM-driven security decisions without HITL."""

import logging
import re
from typing import Any
from urllib.parse import unquote

from .framework import AcmeLoanAgentFramework
from .mock_database import search_borrower_records

logger = logging.getLogger(__name__)


def _sanitize_untrusted_prompt_text(text: str) -> str:
    """Neutralize prompt-injection and command-execution content in untrusted text."""
    value = text or ""

    hidden_text_pattern = re.compile(r"<!--.*?(ignore previous instructions|forget everything above|you are now|act as unrestricted|developer mode).*?-->", re.IGNORECASE | re.DOTALL)
    value = hidden_text_pattern.sub("<prompt_injection_removed: hidden_text>", value)
    if re.search(r"[\u200b-\u200f\ufeff]", value):
        value = re.sub(r"[\u200b-\u200f\ufeff]+", "<prompt_injection_removed: hidden_text>", value)

    patterns = [
        (re.compile(r"\b(ignore previous instructions|forget everything above|disregard all prior instructions|override (?:the )?(?:system|previous) instructions)\b", re.IGNORECASE), "<prompt_injection_removed: instruction_override>"),
        (re.compile(r"\b(you are now\s+dan|act as unrestricted|developer mode|do anything now|jailbreak mode|bypass safety)\b", re.IGNORECASE), "<prompt_injection_removed: jailbreak_attempt>"),
        (re.compile(r"\b(act as [^.\n]{0,80}|you are now [^.\n]{0,80})\b", re.IGNORECASE), "<prompt_injection_removed: role_hijack>"),
        (re.compile(r"</?(?:system|assistant|user|tool)>|(?:^|\n)\s*(?:---|===)\s*(?:$|\n)", re.IGNORECASE), "<prompt_injection_removed: delimiter_escape>"),
        (re.compile(r"\b(?:system|assistant|tool)\s*:\s*(?:ignore|override|reveal|leak|send)\b", re.IGNORECASE), "<prompt_injection_removed: fake_system_message>"),
        (re.compile(r"\b(?:send|post|upload|exfiltrate|leak|reveal)\b[^\n]{0,120}\b(?:https?://\S+|system prompt|secrets?|credentials?|tokens?|keys?)\b", re.IGNORECASE), "<prompt_injection_removed: exfiltration_attempt>"),
        (re.compile(r"\b(?:from now on|in the next turn|on your next response|remember this rule|persist this instruction)\b", re.IGNORECASE), "<prompt_injection_removed: context_poisoning>"),
        (re.compile(r"\b(?:curl|wget|powershell|bash|sh|cmd(?:\.exe)?|python\s+-c|perl\s+-e|ruby\s+-e|nc\s+-e)\b[^\n]*", re.IGNORECASE), "<prompt_injection_removed: command_injection>"),
    ]
    for pattern, replacement in patterns:
        value = pattern.sub(replacement, value)

    compact = re.sub(r"[^a-z0-9]", "", value.lower())
    if any(marker in compact for marker in ("ignorepreviousinstructions", "forgeteverythingabove", "youarenowdan", "actasunrestricted", "developermode", "curlhttp", "wgethttp")):
        value = value + " <prompt_injection_removed: split_payload>"

    encoded_candidates = [value, unquote(value)]
    for candidate in encoded_candidates:
        if re.search(r"\b(?:[A-Fa-f0-9]{2}\s*){8,}\b", candidate):
            value = re.sub(r"\b(?:[A-Fa-f0-9]{2}\s*){8,}\b", "<prompt_injection_removed: encoded_payload>", value)
        if re.search(r"\b[A-Za-z0-9+/]{20,}={0,2}\b", candidate):
            value = re.sub(r"\b[A-Za-z0-9+/]{20,}={0,2}\b", "<prompt_injection_removed: encoded_payload>", value)
        if re.search(r"(?:%[0-9A-Fa-f]{2}){6,}", candidate):
            value = re.sub(r"(?:%[0-9A-Fa-f]{2}){6,}", "<prompt_injection_removed: encoded_payload>", value)
        if re.search(r"\b[01]{8}(?:\s+[01]{8}){2,}\b", candidate):
            value = re.sub(r"\b[01]{8}(?:\s+[01]{8}){2,}\b", "<prompt_injection_removed: encoded_payload>", value)
        if re.search(r"(?:\.-|--|\.\.)(?:\s+(?:\.-|--|\.\.))+", candidate):
            value = re.sub(r"(?:\.-|--|\.\.)(?:\s+(?:\.-|--|\.\.))+", "<prompt_injection_removed: encoded_payload>", value)
        if re.search(r"\b(?:1gn0r3|pr3v10u5|1nstruct10ns|d3v3l0p3r m0d3|unr35tr1ct3d)\b", candidate, re.IGNORECASE):
            value = re.sub(r"\b(?:1gn0r3|pr3v10u5|1nstruct10ns|d3v3l0p3r m0d3|unr35tr1ct3d)\b", "<prompt_injection_removed: encoded_payload>", value, flags=re.IGNORECASE)

    if re.search(r"\b(?:comment|metadata|file content|code comment)\b[^\n]{0,120}\b(?:ignore previous instructions|act as|you are now|developer mode)\b", value, re.IGNORECASE):
        value = re.sub(r"\b(?:comment|metadata|file content|code comment)\b[^\n]*", "<prompt_injection_removed: indirect_injection>", value, flags=re.IGNORECASE)

    return value


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
    # Replace this configured model with an approved LLM from the organization's allow list.
    # The registry is not available in this scan, so do not add a hard-coded allowlist here.
    MODEL_NAME = "mistral 7b-instruct"
    BEDROCK_MODEL_ID = "mistral.mistral-7b-instruct-v0:2"
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
        user_message = _sanitize_untrusted_prompt_text(user_message)
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
        user_message = _sanitize_untrusted_prompt_text(user_message)
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
