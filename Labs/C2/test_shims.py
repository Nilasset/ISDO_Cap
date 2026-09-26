"""
ISDO Lab C2 — Automated check of both mock APIs (Steps 3-6 + CRUD loop).

Start both shims first, each in its own terminal (from the project root):
    python mcp_server/snow_shim.py
    python mcp_server/jira_shim.py
Then, in a third terminal:
    python Labs/C2/test_shims.py

Uses only the Python standard library. Any update it makes is put back
afterwards, so the shims are left exactly as they started.
"""

import json
import sys
import urllib.error
import urllib.request

SNOW = "http://localhost:5001"
JIRA = "http://localhost:5002"
results = []


def call(method, url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"{}")
        except ValueError:  # e.g. an HTML 500 page from a server crash
            print(f"  ! {method} {url} -> HTTP {e.code} (non-JSON response; check the shim's terminal)")
            return e.code, {}


def check(name, condition, detail=""):
    results.append(condition)
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}" + (f"  -> {detail}" if detail else ""))


def main():
    # Step 6 first: fail fast with a clear message if a shim isn't running
    print("\n--- Step 6: health checks ---")
    for name, base in [("ServiceNow", SNOW), ("Jira", JIRA)]:
        try:
            status, body = call("GET", f"{base}/health")
        except urllib.error.URLError:
            print(f"  [FAIL] {name} shim is not running on {base}. Start it and retry.")
            sys.exit(1)
        check(f"{name} /health", status == 200 and body.get("status") == "ok", json.dumps(body))

    print("\n--- Step 3: ServiceNow list all ---")
    status, body = call("GET", f"{SNOW}/api/now/table/incident")
    check("GET /api/now/table/incident returns 15", body.get("total") == 15, f"total={body.get('total')}")

    print("\n--- Step 4: ServiceNow filters ---")
    status, body = call("GET", f"{SNOW}/api/now/table/incident?priority=P1")
    p1 = [r["number"] for r in body.get("result", [])]
    check("?priority=P1 returns only P1", p1 and all(r["priority"] == "P1" for r in body["result"]),
          f"total={body.get('total')} {p1}")
    status, body = call("GET", f"{SNOW}/api/now/table/incident?category=Network")
    check("?category=Network works", body.get("total", 0) > 0, f"total={body.get('total')}")
    status, body = call("GET", f"{SNOW}/api/now/table/incident/INC0001001")
    check("GET /incident/INC0001001", status == 200 and body["result"]["number"] == "INC0001001",
          body.get("result", {}).get("short_description", ""))
    status, _ = call("GET", f"{SNOW}/api/now/table/incident/INC9999999")
    check("Unknown incident returns 404", status == 404)

    print("\n--- Step 5: Jira list and single issue ---")
    status, body = call("GET", f"{JIRA}/rest/agile/1.0/board/requests")
    check("GET /rest/agile/1.0/board/requests returns 10", body.get("total") == 10,
          f"total={body.get('total')}")
    status, body = call("GET", f"{JIRA}/rest/api/2/issue/REQ-1002")
    check("GET /rest/api/2/issue/REQ-1002 has nested 'fields'",
          status == 200 and "priority" in body.get("fields", {}),
          f"priority={body.get('fields', {}).get('priority')}")
    status, body = call("GET", f"{JIRA}/rest/api/2/issue?request_type=Access+Grant")
    check("?request_type=Access+Grant filter", body.get("total") == 2, f"total={body.get('total')}")

    print("\n--- CRUD loop used by later labs (update, read back, restore) ---")
    _, before = call("GET", f"{SNOW}/api/now/table/incident/INC0001002")
    old_state = before["result"]["state"]
    call("PATCH", f"{SNOW}/api/now/table/incident/INC0001002", {"state": "Escalated"})
    _, after = call("GET", f"{SNOW}/api/now/table/incident/INC0001002")
    check("PATCH state=Escalated and read back", after["result"]["state"] == "Escalated")
    call("PATCH", f"{SNOW}/api/now/table/incident/INC0001002", {"state": old_state})

    _, before = call("GET", f"{JIRA}/rest/api/2/issue/REQ-1008")
    old_status = before["fields"]["status"]["name"]
    call("PUT", f"{JIRA}/rest/api/2/issue/REQ-1008", {"fields": {"status": "In Progress"}})
    _, after = call("GET", f"{JIRA}/rest/api/2/issue/REQ-1008")
    check("PUT status=In Progress and read back", after["fields"]["status"]["name"] == "In Progress")
    call("PUT", f"{JIRA}/rest/api/2/issue/REQ-1008", {"fields": {"status": old_status}})

    passed = sum(results)
    print(f"\n{passed}/{len(results)} checks passed.")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
