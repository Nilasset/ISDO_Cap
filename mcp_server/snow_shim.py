"""
ISDO Lab C2 — Mock ServiceNow REST API (Flask Shim)
Mimics the ServiceNow Table API so the MCP server can make real HTTP calls
without touching a production system.

Endpoints:
  GET   /api/now/table/incident           — list all incidents
  GET   /api/now/table/incident?priority=P1 — filter (category, state, priority, assignment_group)
  GET   /api/now/table/incident/<number>  — get one incident
  PATCH /api/now/table/incident/<number>  — update fields in memory (e.g. state, work_notes)
  POST  /api/now/table/incident           — create an incident
  GET   /health                           — health check

Run from the project root:  python mcp_server/snow_shim.py   (port 5001)
"""

from flask import Flask, jsonify, request
import csv
import os

app = Flask(__name__)

DATA_FILE = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "incidents.csv"))


def load_incidents():
    incidents = {}
    try:
        with open(DATA_FILE, newline="", encoding="utf-8") as f:
            for line, row in enumerate(csv.DictReader(f), start=2):
                if None in row:  # more values than headers: an unquoted comma
                    print(f"Warning: skipped malformed row at line {line} of {DATA_FILE}")
                    continue
                incidents[row["number"]] = dict(row)
    except FileNotFoundError:
        print(f"Warning: {DATA_FILE} not found. Starting with empty dataset.")
    return incidents


# In-memory store (simulates the ServiceNow DB for the session)
INCIDENTS = load_incidents()


@app.route("/api/now/table/incident", methods=["GET"])
def list_incidents():
    """Return all incidents, optionally filtered by query params."""
    results = list(INCIDENTS.values())
    for key in ["category", "state", "priority", "assignment_group"]:
        val = request.args.get(key)
        if val:
            results = [r for r in results if r.get(key, "").lower() == val.lower()]
    return jsonify({"result": results, "total": len(results)})


@app.route("/api/now/table/incident/<number>", methods=["GET"])
def get_incident(number):
    incident = INCIDENTS.get(number)
    if not incident:
        return jsonify({"error": f"Incident {number} not found"}), 404
    return jsonify({"result": incident})


@app.route("/api/now/table/incident/<number>", methods=["PATCH"])
def update_incident(number):
    """Update fields on an incident (e.g. state, work_notes)."""
    if number not in INCIDENTS:
        return jsonify({"error": f"Incident {number} not found"}), 404
    updates = request.get_json(silent=True)
    if not isinstance(updates, dict) or not updates:
        return jsonify({"error": "Body must be a non-empty JSON object"}), 400
    updates.pop("number", None)  # the record's key can't be changed
    INCIDENTS[number].update(updates)
    print(f"[ServiceNow Mock] Updated {number}: {updates}")
    return jsonify({"result": INCIDENTS[number], "message": "Updated successfully"})


@app.route("/api/now/table/incident", methods=["POST"])
def create_incident():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or "number" not in data:
        return jsonify({"error": "Missing required field: number"}), 400
    if data["number"] in INCIDENTS:
        return jsonify({"error": f"Incident {data['number']} already exists"}), 409
    INCIDENTS[data["number"]] = data
    print(f"[ServiceNow Mock] Created incident: {data['number']}")
    return jsonify({"result": data, "message": "Incident created"}), 201


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "ServiceNow Mock", "incidents_loaded": len(INCIDENTS)})


@app.errorhandler(404)
@app.errorhandler(405)
def json_error(e):
    # Agents expect JSON, not Flask's HTML error pages
    return jsonify({"error": e.description}), e.code


if __name__ == "__main__":
    print("ServiceNow Mock API starting on http://localhost:5001")
    print(f"Loaded {len(INCIDENTS)} incidents from {DATA_FILE}")
    print("Endpoints: GET /api/now/table/incident  |  GET /health")
    app.run(port=5001, debug=True)
