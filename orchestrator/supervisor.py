"""
ISDO Lab C6/C7 - LangGraph Orchestrator
Wires the Triage, Resolution, SLA, HITL and Communication agents (Labs C3-C5)
into a single StateGraph.

Flow:
    triage -> resolution -> sla -> [hitl if hitl_required] -> communication

Lab C7: the HITL gate fires for any of three triggers (set in sla_node, with the
reasons stored in hitl_reason):
    1. P1_SLA          - P1 ticket at CRITICAL/BREACHED SLA risk (Lab C5's rule)
    2. LOW_CONFIDENCE  - Resolution Agent found no clear KB fix, whatever the priority
    3. ACCESS_GRANT    - category 'Access' + request_type 'Access Grant' (security-sensitive)
Non-P1 CRITICAL/BREACHED tickets without another trigger still flow straight to
communication without a human pause, as in C6.

Run from the project root:
    python orchestrator/supervisor.py            # VPN (P2), SAP (P1), REQ-1002 access grant
    python orchestrator/supervisor.py --webex    # Lab C7 Step 3: low-confidence ticket instead of VPN
"""

import operator
import os
import sys
from datetime import datetime, timezone
from typing import Annotated, List, Optional, TypedDict

from langgraph.graph import END, START, StateGraph

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agents"))

import resolution_agent   # noqa: E402  (path set above)
import sla_agent          # noqa: E402
import triage_agent       # noqa: E402

# -- Shared state ---------------------------------------------------------------

class TicketState(TypedDict, total=False):
    # Input
    ticket_number: str
    short_description: str
    description: str
    category: str
    priority: str
    sla_due: str
    request_type: str                 # Jira-style request type, e.g. 'Access Grant' (REQ- tickets)
    # Triage agent
    triage_category: str
    triage_priority: str
    triage_assignment_group: str
    pii_detected: bool
    # Resolution agent
    kb_article: str
    resolution_text: str
    auto_resolve: bool
    confidence: str
    # SLA agent (owns the HITL decision)
    sla_breach_risk: str
    escalation_required: bool
    hitl_required: bool
    hitl_triggers: List[str]          # P1_SLA / LOW_CONFIDENCE / ACCESS_GRANT
    hitl_reason: str                  # human-readable reason(s), shown in the approval prompt
    # HITL node
    hitl_approved: Optional[bool]
    escalation_team: Optional[str]
    # Communication agent
    user_message: str
    final_status: str
    # Every node appends here; the reducer concatenates instead of overwriting.
    audit_log: Annotated[List[dict], operator.add]


def log(agent: str, action: str, detail: str) -> list:
    """One audit_log entry, in the list form nodes return for the reducer to append."""
    return [{"timestamp": datetime.now(timezone.utc).isoformat(), "agent": agent, "action": action, "detail": detail}]

# -- Nodes ------------------------------------------------------------------------

def triage_node(state: TicketState) -> dict:
    print(f"\n{'#' * 60}")
    print(f"PROCESSING TICKET: {state['ticket_number']}")
    print(f"{'#' * 60}")
    print(f"\n▶ TRIAGE AGENT — {state['ticket_number']}")

    result = triage_agent.triage_ticket(state["ticket_number"], state["short_description"], state["description"])
    if result is None:
        # Model never called classify_ticket - fall back to the ticket's own fields
        # rather than crash the graph (or silently downgrade a P1).
        print("  ! Triage did not return a classification - using the ticket's own category/priority.")
        result = {"category": state.get("category", "Software"), "priority": state.get("priority", "P3"),
                  "assignment_group": "Service-Desk", "pii_detected": False,
                  "reasoning": "Fallback: classification unavailable."}

    return {
        "triage_category": result["category"],
        "triage_priority": result["priority"],
        "triage_assignment_group": result["assignment_group"],
        "pii_detected": result["pii_detected"],
        "audit_log": log("TriageAgent", "classify_ticket",
                          f"{result['category']} / {result['priority']} -> {result['assignment_group']}"),
    }


def resolution_node(state: TicketState) -> dict:
    print(f"\n▶ RESOLUTION AGENT — searching KB")

    result = resolution_agent.resolve_ticket(
        state["ticket_number"], state["short_description"], state["description"],
        state["triage_category"], state["triage_priority"],
    )

    return {
        "kb_article": result.get("kb_article_used", "None"),
        "resolution_text": result.get("resolution_text", ""),
        "auto_resolve": bool(result.get("auto_resolve")),
        "confidence": result.get("confidence", "LOW"),
        "audit_log": log("ResolutionAgent", "search_kb",
                          f"{result.get('kb_article_used', 'None')} - {result.get('confidence')} "
                          f"({result.get('top_score', 0):.0%})"),
    }


def is_access_grant(state: TicketState) -> bool:
    """Access grant = category 'Access' (as submitted or as triaged) + request_type 'Access Grant'."""
    category_is_access = "Access" in (state.get("category"), state.get("triage_category"))
    return category_is_access and (state.get("request_type") or "").strip().lower() == "access grant"


def sla_node(state: TicketState) -> dict:
    print(f"\n▶ SLA AGENT — checking deadline")

    status = sla_agent.get_sla_status(state["ticket_number"], state["sla_due"], state["triage_priority"])
    breach_risk = status.get("breach_risk", "ON_TRACK")
    escalation_required = bool(status.get("requires_escalation"))
    team = sla_agent.ESCALATION_TEAMS.get(state["triage_category"], "L2-Service-Desk")

    # HITL gate: collect every trigger that applies (a ticket can hit more than one).
    triggers, reasons = [], []
    if escalation_required and state["triage_priority"] == "P1":
        triggers.append("P1_SLA")
        reasons.append(f"P1 SLA {breach_risk} -- escalation to {team} needs sign-off")
    if state.get("confidence") == "LOW":
        triggers.append("LOW_CONFIDENCE")
        reasons.append(f"LOW KB CONFIDENCE -- no clear fix in the knowledge base "
                       f"({state['triage_priority']} ticket); route to {team} for investigation")
    if is_access_grant(state):
        triggers.append("ACCESS_GRANT")
        reasons.append(f"ACCESS GRANT -- '{state['short_description']}' requires security approval")

    hitl_required = bool(triggers)
    hitl_reason = " | ".join(reasons) if reasons else "None"

    print(f"  SLA Risk: {breach_risk}  |  Minutes remaining: {status.get('minutes_remaining')}")
    print(f"  HITL required: {hitl_required}" + (f"  |  Triggers: {', '.join(triggers)}" if triggers else ""))

    return {
        "sla_breach_risk": breach_risk,
        "escalation_required": escalation_required,
        "hitl_required": hitl_required,
        "hitl_triggers": triggers,
        "hitl_reason": hitl_reason,
        "escalation_team": team,
        "audit_log": log("SLAAgent", "get_sla_status",
                          f"{breach_risk} ({status.get('minutes_remaining')} min remaining); "
                          f"HITL={hitl_required} ({', '.join(triggers) or 'no trigger'})"),
    }


def proposed_action(state: TicketState) -> str:
    """What the human is being asked to approve, based on the triggers."""
    actions = []
    if "ACCESS_GRANT" in state.get("hitl_triggers", []):
        actions.append("Approve access grant")
    if {"P1_SLA", "LOW_CONFIDENCE"} & set(state.get("hitl_triggers", [])):
        actions.append(f"Escalate to {state.get('escalation_team')}")
    return " + ".join(actions) or "Review ticket"


def hitl_node(state: TicketState) -> dict:
    ticket, action = state["ticket_number"], proposed_action(state)
    banner = " ".join(["WARNING"] * 8)

    print(f"\n▶ HITL GATE — human approval required")
    print(f"  {banner}")
    print(f"  Ticket:  {ticket}  |  Priority: {state.get('triage_priority')}")
    for reason in state.get("hitl_reason", "").split(" | "):
        print(f"  Reason:  {reason}")
    print(f"  Action:  {action}")
    print(f"  {banner}")
    try:
        approved = input("  Approve action? [y/n]: ").strip().lower() == "y"
    except EOFError:                      # no keyboard (e.g. piped/scheduled run): fail safe
        print()
        approved = False
    decision = "APPROVED" if approved else "REJECTED"
    print(f"  [AUDIT] HITLGate: approval_decision -- {decision}")
    print(f"  Decision: {decision}")

    if approved:
        triggers = state.get("hitl_triggers", [])
        if "ACCESS_GRANT" in triggers:
            sla_agent.update_ticket(ticket, "update_state", new_state="Access Approved")
        if "P1_SLA" in triggers or "LOW_CONFIDENCE" in triggers:
            sla_agent.update_ticket(ticket, "escalate", escalation_team=state["escalation_team"])
        detail = f"APPROVED: {action}. Reason: {state.get('hitl_reason')}"
    else:
        sla_agent.update_ticket(ticket, "add_note", note=f"HITL rejected - pending approval. {state.get('hitl_reason')}")
        detail = f"REJECTED: {action} held - pending approval. Reason: {state.get('hitl_reason')}"

    return {"hitl_approved": approved, "audit_log": log("HITLGate", "approval_decision", detail)}


def communication_node(state: TicketState) -> dict:
    print(f"\n▶ COMMUNICATION AGENT")

    ticket = state["ticket_number"]
    triggers = state.get("hitl_triggers", [])
    group, team = state.get("triage_assignment_group"), state.get("escalation_team")

    # HITL outcomes come first: a gated ticket is never auto-resolved (e.g. an access grant
    # whose KB match is strong still needs the security approval, not self-service steps).
    if state.get("hitl_required") and state.get("hitl_approved") is True:
        if "ACCESS_GRANT" in triggers:
            message = (f"Dear Requester, your access grant request {ticket} has been approved by the "
                       f"security approver. {group} will provision the access and confirm when it is ready.")
            final_status = "ACCESS APPROVED"
        elif "P1_SLA" in triggers:
            message = (f"Dear User, regarding {ticket}: this ticket has been escalated to "
                       f"{team} following approval. You will be contacted shortly.")
            final_status = "ESCALATED"
        else:  # LOW_CONFIDENCE
            message = (f"Dear User, regarding {ticket}: there is no standard fix for this issue yet, so it "
                       f"has been escalated to our {team} specialists for investigation. "
                       f"They will contact you with next steps.")
            final_status = "ESCALATED"
    elif state.get("hitl_required"):   # rejected, or no decision
        message = (f"Dear User, regarding {ticket}: your ticket is pending approval. It has been "
                    f"reviewed and is on hold with {group} until approval is given. "
                    f"We will update you as soon as there is a decision.")
        final_status = "PENDING APPROVAL"
    elif state.get("auto_resolve"):
        message = (f"Dear User, regarding {ticket}: we found a known fix for this issue "
                    f"({state.get('kb_article')}) and applied it automatically.\n\n{state.get('resolution_text')}")
        final_status = "RESOLVED"
    else:
        message = (f"Dear User, regarding {ticket}: your ticket has been assigned to "
                    f"{group} and is being worked on.")
        final_status = "ASSIGNED"

    print(f"  USER MESSAGE: {message.splitlines()[0][:100]}...")
    print(f"✅ FINAL STATUS: {final_status}")

    return {"user_message": message, "final_status": final_status,
            "audit_log": log("CommunicationAgent", "draft_message", final_status)}

# -- Conditional routing -----------------------------------------------------------

def route_after_sla(state: TicketState) -> str:
    return "hitl" if state.get("hitl_required") else "communication"

# -- Build the graph ----------------------------------------------------------------

def build_graph():
    graph = StateGraph(TicketState)
    graph.add_node("triage", triage_node)
    graph.add_node("resolution", resolution_node)
    graph.add_node("sla", sla_node)
    graph.add_node("hitl", hitl_node)
    graph.add_node("communication", communication_node)

    graph.add_edge(START, "triage")
    graph.add_edge("triage", "resolution")
    graph.add_edge("resolution", "sla")
    graph.add_conditional_edges("sla", route_after_sla, {"hitl": "hitl", "communication": "communication"})
    graph.add_edge("hitl", "communication")
    graph.add_edge("communication", END)

    return graph.compile()

# -- Run --------------------------------------------------------------------------

VPN_TICKET = {
    # P2 VPN - same wording as the Lab C4 KB match, sla_due picked for a true
    # AT_RISK reading (90 of 240 min = 37.5%). Expected: auto-resolve, no HITL.
    "ticket_number": "INC0001001", "short_description": "VPN not connecting after password change",
    "description": "User reports VPN client fails to connect after AD password was reset. Error: authentication failed.",
    "category": "Network", "priority": "P2", "sla_due": "2024-01-15 12:00:00"}

WEBEX_TICKET = {
    # Lab C7 Step 3: the VPN ticket reworded to an issue the KB doesn't cover. The description
    # is changed too - with the old VPN description the KB search still finds the VPN article.
    # Expected: LOW confidence -> HITL even though this is only P3.
    "ticket_number": "INC0001001", "short_description": "Cisco Webex not launching on MacBook M2 after Sonoma update",
    "description": "Cisco Webex not launching on MacBook M2 after Sonoma update.",
    "category": "Software", "priority": "P3", "sla_due": "2024-01-15 12:00:00"}

SAP_TICKET = {
    # P1 SAP outage - sla_due picked for CRITICAL (10 of 60 min = 16.7%), same as Lab C5.
    # Expected: HITL (P1_SLA).
    "ticket_number": "INC0001002", "short_description": "Cannot access ERP system - login error",
    "description": "Multiple Finance users unable to login to SAP. Error: DBCON_FAIL.",
    "category": "Application", "priority": "P1", "sla_due": "2024-01-15 10:40:00"}

ACCESS_GRANT_TICKET = {
    # Lab C7 Step 4. request_type matches REQ-1002 in data/requests.csv.
    # Expected: HITL (ACCESS_GRANT) regardless of priority.
    "ticket_number": "REQ-1002", "short_description": "VPN access for new contractor",
    "description": "Contractor needs VPN access. Email: contractor@client.com",
    "category": "Access", "priority": "P2", "sla_due": "2024-01-15 15:00:00",
    "request_type": "Access Grant"}


if __name__ == "__main__":
    app = build_graph()

    first = WEBEX_TICKET if "--webex" in sys.argv else VPN_TICKET
    test_tickets = [first, SAP_TICKET, ACCESS_GRANT_TICKET]

    all_results = []
    for ticket in test_tickets:
        final_state = app.invoke(ticket)
        all_results.append(final_state)

    print(f"\n\n{'=' * 60}")
    print("AUDIT LOG")
    print("=" * 60)
    for result in all_results:
        print(f"\n--- {result['ticket_number']} ({result['final_status']}) ---")
        for entry in result["audit_log"]:
            print(f"  [{entry['timestamp']}] {entry['agent']}: {entry['action']} — {entry['detail']}")
