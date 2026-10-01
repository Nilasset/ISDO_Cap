"""
ISDO Lab C9 — PII Redaction Middleware
Masks PII before any ticket data is sent to Claude.
Patterns covered: person names (spaCy NER + regex fallback), usernames / login IDs,
email addresses, employee IDs, IP addresses, and phone numbers.

Usage:
    from guardrails.pii_redactor import redact, restore

    clean_text, mapping = redact(raw_text)
    # ... send clean_text to Claude ...
    original_text = restore(claude_response, mapping)

spaCy is optional but recommended (better name detection). Install once:
    pip install spacy
    python -m spacy download en_core_web_sm
Without it, names are still caught by the regex fallback when they follow a cue
word (User, Mr, Contractor, for, reported by ...) and are written as First Last.
"""

import json
import os
import re
from datetime import datetime

# Try to import spaCy — graceful fallback if not installed
try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
    SPACY_AVAILABLE = True
except (ImportError, OSError):
    SPACY_AVAILABLE = False
    print("⚠  spaCy model not available — names use the regex fallback only. "
          "Fix: pip install spacy && python -m spacy download en_core_web_sm")

# ── REGEX PATTERNS ────────────────────────────────────────────────────────────
# Applied in this order. Emails go first so 'john.smith@corp.com' is never
# half-matched as a username.

PATTERNS = {
    "EMAIL":       r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
    "IP_ADDRESS":  r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "EMPLOYEE_ID": r'\b(?:EMP|ZEN)-?\d{3,6}\b',
    # '+91-' is now part of the match (previously it was left behind as '+91-[PHONE_1]')
    "PHONE":       r'(?:\+91[\-\s]?)?\b\d{10}\b|\b\d{3}[\-\s]\d{3}[\-\s]\d{4}\b',
}

# Ticket / request references are never PII and must survive redaction.
TICKET_REF = re.compile(r'^(?:INC|REQ|CHG|RITM|TASK)-?\d+$', re.IGNORECASE)

# Usernames, form 1: DOMAIN\user  (e.g. ZENSAR\nkhatavkar)
# A username token: starts with a letter, may contain . _ -, must END with a letter/digit
# (so a sentence's full stop is never swallowed: "login error." -> "error")
UNAME = r'[A-Za-z](?:[A-Za-z0-9._-]{0,29}[A-Za-z0-9])?'

USERNAME_DOMAIN = re.compile(r'(?<!\[)\b[A-Za-z][A-Za-z0-9_-]{1,19}\\' + UNAME + r'\b')

# Usernames, form 2: explicit cue -> the next word is the username, whatever it looks like
#   "username jsmith", "User ID: priya.sharma", "login = rkumar", "samAccountName: nk01"
USERNAME_STRONG = re.compile(
    r'(?<!\[)\b(?:user\s?name|user\s?id|login\s?id|logon\s?id|login|logon|sam\s?account\s?name|uid)'
    r'\s*(?:is\s+|[:=#]\s*)?(' + UNAME + r')', re.IGNORECASE)

# Usernames, form 3: weaker cue -> only redact if the word *looks* like a username
# (contains a digit, dot or underscore): "AD account rkumar01", "for user j.doe".
# The lookahead stops one cue word ("for") from swallowing the next ("user").
WEAK_CUES = r'(?:user|account|for|employee|contractor|requester|caller)'
USERNAME_WEAK = re.compile(
    r'(?<!\[)\b' + WEAK_CUES + r'\s*[:#]?\s*(?!' + WEAK_CUES + r'\b)(' + UNAME + r')', re.IGNORECASE)

# Names (regex fallback, catches what spaCy misses): a cue word then 2-3 Capitalised words
#   "User John Smith", "for Michael D'Souza", "reported by Priya Sharma", "Mr. Rahul Kumar"
NAME_WORD = r"(?:[A-Z]'[A-Z][a-z]+|[A-Z][a-z]+(?:['’\-][A-Z][a-z]+)?)"
NAME_CUE = re.compile(
    r"(?<!\[)\b(?:Mr|Mrs|Ms|Dr|[Uu]ser|[Ee]mployee|[Cc]ontractor|[Cc]aller|[Rr]equester|[Nn]ame|"
    r"[Cc]ontact|[Mm]anager|[Ff]or|by)\.?:?\s+(" + NAME_WORD + r"(?:\s+" + NAME_WORD + r"){1,2})\b")

# Words that follow a cue but are not usernames / names
NOT_A_USERNAME = {
    "is", "was", "has", "had", "for", "and", "the", "a", "an", "not", "of", "to", "in", "on", "with",
    "after", "cannot", "can", "does", "did", "locked", "unlocked", "failed", "fails", "failure",
    "error", "issue", "reset", "expired", "disabled", "page", "portal", "screen", "prompt",
    "password", "access", "request", "creation", "setup", "details", "name", "id",
}
NOT_A_NAME_START = {
    "Finance", "Sales", "Marketing", "Building", "Project", "Board", "Windows", "Microsoft", "Cisco",
    "Zoom", "Adobe", "Outlook", "Exchange", "Teams", "Office", "New", "The", "All", "Multiple",
    "Mobile", "Python", "Senior", "Service", "Shared", "Network", "Server", "Active", "Azure", "Oracle",
}
FILE_EXT = re.compile(r'\.(?:md|txt|msi|exe|log|csv|pdf|docx?|xlsx?|py|json|zip)$', re.IGNORECASE)

# ── AUDIT LOGGER ──────────────────────────────────────────────────────────────

audit_log = []

def _audit(action, detail):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "module": "PIIRedactor",
        "action": action,
        "detail": detail
    }
    audit_log.append(entry)
    return entry

# ── REDACTION FUNCTION ────────────────────────────────────────────────────────

def redact(text: str) -> tuple[str, dict]:
    """
    Redact PII from text. Returns:
      - clean_text: text with PII replaced by tokens like [EMAIL_1], [NAME_1], [USERNAME_1]
      - mapping: dict to restore original values later

    Example:
      clean, m = redact("Contact john.doe@corp.com or call 9876543210")
      # clean  = "Contact [EMAIL_1] or call [PHONE_1]"
      # m      = {"[EMAIL_1]": "john.doe@corp.com", "[PHONE_1]": "9876543210"}
    """
    mapping, counters = {}, {}

    def token_for(label, value):
        """Same value -> same token, so repeated mentions stay consistent."""
        for tok, val in mapping.items():
            if val == value and tok.startswith(f"[{label}_"):
                return tok
        counters[label] = counters.get(label, 0) + 1
        tok = f"[{label}_{counters[label]}]"
        mapping[tok] = value
        return tok

    def sub_group(pattern, label, text_in, keep=lambda v: True):
        """Replace only capture group 1 (the PII), leaving the cue word in place."""
        def repl(m):
            value = m.group(1)
            if not keep(value):
                return m.group(0)
            start, end = m.start(1) - m.start(0), m.end(1) - m.start(0)
            return m.group(0)[:start] + token_for(label, value) + m.group(0)[end:]
        return pattern.sub(repl, text_in)

    clean = text

    # Step 1: regex patterns (emails, IPs, employee IDs, phones)
    for label, pattern in PATTERNS.items():
        clean = re.sub(pattern, lambda m, lb=label: token_for(lb, m.group(0)), clean, flags=re.IGNORECASE)

    # Step 2: usernames
    clean = USERNAME_DOMAIN.sub(lambda m: token_for("USERNAME", m.group(0)), clean)
    clean = sub_group(USERNAME_STRONG, "USERNAME", clean,
                      keep=lambda v: v.lower() not in NOT_A_USERNAME and not TICKET_REF.match(v))
    clean = sub_group(USERNAME_WEAK, "USERNAME", clean,
                      keep=lambda v: bool(re.search(r'[\d._]', v)) and not TICKET_REF.match(v)
                      and not FILE_EXT.search(v) and v.lower() not in NOT_A_USERNAME)

    # Step 3: names — spaCy NER first (if installed), then the regex fallback for anything it missed
    if SPACY_AVAILABLE:
        for ent in nlp(clean).ents:
            # Guard against a known spaCy false-positive: short ALL-CAPS acronyms
            # (PII, SLA, KB, VPN...) occasionally get tagged PERSON.
            if ent.label_ == "PERSON" and not ent.text.isupper() and "[" not in ent.text:
                clean = clean.replace(ent.text, token_for("NAME", ent.text))
    clean = sub_group(NAME_CUE, "NAME", clean, keep=lambda v: v.split()[0] not in NOT_A_NAME_START)

    # Step 4: a username or name found once is masked everywhere it appears again
    for tok, value in list(mapping.items()):
        if tok.startswith(("[USERNAME_", "[NAME_")):
            clean = re.sub(r'(?<![\w\[])' + re.escape(value) + r'(?![\w\]])', tok, clean)

    pii_count = len(mapping)
    if pii_count > 0:
        _audit("redact", f"{pii_count} PII item(s) masked: {list(mapping.keys())}")
    else:
        _audit("redact", "No PII detected")

    return clean, mapping

def restore(text: str, mapping: dict) -> str:
    """Restore PII tokens back to original values (for system-of-record logging only)."""
    restored = text
    for token, original in mapping.items():
        restored = restored.replace(token, original)
    _audit("restore", f"{len(mapping)} PII item(s) restored")
    return restored

def get_audit_log() -> list:
    """Return all PII redaction audit entries."""
    return audit_log

# ── AUDIT TRAIL LOGGER ────────────────────────────────────────────────────────

class AuditLogger:
    """Logs every agent action with timestamp, agent name, tool, rationale, approval.
    The rationale is redacted before it is written, so the audit file never stores PII."""

    def __init__(self, log_file: str = "logs/audit_trail.jsonl"):
        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        self.log_file = log_file
        self.entries = []

    def log(self, agent: str, action: str, ticket_number: str = "",
            tool: str = "", rationale: str = "", approval_status: str = "N/A"):
        safe_rationale = redact(rationale)[0] if rationale else ""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "agent": agent,
            "action": action,
            "ticket_number": ticket_number,
            "tool": tool,
            "rationale": safe_rationale[:200],
            "approval_status": approval_status
        }
        self.entries.append(entry)

        # Append to JSONL file
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        print(f"  [AUDIT] {agent} | {action} | {ticket_number} | {approval_status}")
        return entry

    def print_trail(self):
        print(f"\n{'='*55}")
        print(f"FULL AUDIT TRAIL ({len(self.entries)} entries)")
        print(f"{'='*55}")
        for e in self.entries:
            print(f"  {e['timestamp'][:19]}  {e['agent']:<22} {e['action']:<20} {e['approval_status']}")

# ── DEMO ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("PII REDACTION DEMO")
    print("=" * 55)

    sample_tickets = [
        "User John Smith (emp ID ZEN-9823) reports VPN failure. Contact: john.smith@zensar.com or +91-9876543210.",
        "Contractor sarah.jones@client.com needs access to REQ-1002. IP: 192.168.1.45.",
        "Password reset for Michael D'Souza. Employee EMP-00142. No PII in this part.",
        "VPN not connecting after password change. Error: authentication failed. Ticket INC0001001.",
        # Usernames
        "Account locked for username jsmith after 5 failed attempts. jsmith needs an unlock.",
        "Login fails for ZENSAR\\nkhatavkar on the VPN portal.",
        "User ID: priya.sharma cannot access SharePoint, reported by Priya Sharma.",
        "AD account rkumar01 locked out, user Rahul Kumar called the desk.",
    ]

    for i, ticket in enumerate(sample_tickets, 1):
        print(f"\n--- Ticket {i} ---")
        print(f"Original : {ticket}")
        clean, mapping = redact(ticket)
        print(f"Redacted : {clean}")
        if mapping:
            print(f"Mapping  : {mapping}")

    print("\n" + "=" * 55)
    print("AUDIT TRAIL DEMO")
    print("=" * 55)

    logger = AuditLogger("logs/demo_audit.jsonl")
    logger.log("TriageAgent", "classify_ticket", "INC0001001", "classify_ticket",
               "Network/P2 — VPN failure after password change", "Auto")
    logger.log("ResolutionAgent", "search_kb", "INC0001001", "search_kb",
               "KB article found: vpn_troubleshooting.md (85% confidence)", "Auto")
    logger.log("SLAAgent", "get_sla_status", "INC0001001", "get_sla_status",
               "SLA AT_RISK — 210 min remaining of 240 min total", "Auto")
    logger.log("HITLGate", "approval_request", "INC0001002", "",
               "P1 escalation requires human approval", "PENDING")
    logger.log("HITLGate", "approval_decision", "INC0001002", "",
               "Human operator approved P1 escalation", "APPROVED")
    logger.log("CommunicationAgent", "post_comment", "INC0001001", "post_comment",
               "Resolution sent to user — auto-resolved L1 ticket", "Auto")

    logger.print_trail()
    print(f"\nAudit log saved to: logs/demo_audit.jsonl")
