"""
Flask Application Controller for Fake Website Detector Using Web Security Analysis.
TYCS Academic Project - Pair Programming Implementation.
"""

import os
import io
import csv
import json
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, jsonify, Response, send_file
)
import config
from database.db import (
    init_db, insert_scan, get_scan_by_id,
    get_recent_scans, get_all_scans, get_dashboard_stats,
    delete_scan, clear_all_scans
)
from analyzer.url_validator import validate_url
from analyzer.safe_fetcher import safe_fetch_url
from analyzer.feature_extractor import extract_url_features
from analyzer.risk_scorer import calculate_risk_score
from analyzer.reputation_checker import check_domain_reputation
from analyzer.ai_detector import predict_url_ai

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY

# Ensure database tables exist on startup
with app.app_context():
    init_db()


@app.route("/", methods=["GET"])
def index():
    """Home landing page with URL input, live features, and recent scan preview."""
    recent_scans = get_recent_scans(limit=4)
    return render_template("index.html", recent_scans=recent_scans)


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Handles website URL submission.
    Performs validation, SSRF defense, network inspection, feature extraction,
    heuristic risk scoring, and Machine Learning AI classification, then persists findings to SQLite.
    """
    raw_url = request.form.get("url", "").strip()

    if not raw_url:
        flash("Please enter a website URL before initiating analysis.", "warning")
        return redirect(url_for("index"))

    # Step 1: Syntactic, Protocol, and SSRF Validation
    val_result = validate_url(raw_url)
    if not val_result["is_valid"]:
        flash(f"Invalid URL: {val_result['error_message']}", "danger")
        return redirect(url_for("index"))

    normalized_url = val_result["normalized_url"]
    hostname = val_result["hostname"]

    # Step 2: Safe Network Probe (SSRF-Protected)
    fetch_result = safe_fetch_url(normalized_url)

    # Step 3: Optional Reputation & Threat Feed Check
    reputation_result = check_domain_reputation(hostname, normalized_url)

    # Step 4: Extract Lexical, Structural, and Live Indicators
    features = extract_url_features(normalized_url, fetch_result, val_result)

    # Step 5: Transparent Rule-Based Risk Scoring
    score_data = calculate_risk_score(features, reputation_result)

    # Step 6: Machine Learning AI Model Prediction (Random Forest)
    ai_prediction = predict_url_ai(normalized_url)

    # Prepare complete findings object for storage
    findings = {
        "validation": {
            "submitted_url": raw_url,
            "normalized_url": normalized_url,
            "hostname": hostname,
            "resolved_ip": val_result.get("resolved_ip"),
            "dns_message": val_result.get("dns_message")
        },
        "features": features,
        "scoring": score_data,
        "reputation": reputation_result,
        "ai_prediction": ai_prediction
    }

    scan_status = "completed" if fetch_result.get("success") else "completed_static_only"
    http_status = fetch_result.get("status_code")
    resolved_ip = val_result.get("resolved_ip")

    # Step 7: Insert into Database
    try:
        scan_id = insert_scan(
            submitted_url=raw_url,
            normalized_url=normalized_url,
            risk_score=score_data["final_score"],
            risk_category=score_data["risk_category"],
            risk_tier=score_data["risk_tier"],
            findings=findings,
            scan_status=scan_status,
            resolved_ip=resolved_ip,
            http_status=http_status
        )
        return redirect(url_for("results", scan_id=scan_id))
    except Exception as exc:
        flash(f"Database error while saving scan: {str(exc)}", "danger")
        return redirect(url_for("index"))


@app.route("/results/<int:scan_id>", methods=["GET"])
def results(scan_id):
    """Detailed Results page displaying risk meter, AI predictions, and positive/negative indicators."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        flash(f"Scan record #{scan_id} was not found.", "warning")
        return redirect(url_for("index"))

    findings = scan.get("findings", {})
    scoring = findings.get("scoring", {})
    features = findings.get("features", {})
    validation = findings.get("validation", {})
    reputation = findings.get("reputation", {})
    ai_prediction = findings.get("ai_prediction", {})

    return render_template(
        "results.html",
        scan=scan,
        scoring=scoring,
        features=features,
        validation=validation,
        reputation=reputation,
        ai_prediction=ai_prediction
    )


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Security Dashboard displaying metrics, recent scans, and live analytics."""
    stats = get_dashboard_stats()
    return render_template("dashboard.html", stats=stats)


@app.route("/api/stats", methods=["GET"])
def api_stats():
    """API endpoint providing real dashboard metrics for Chart.js visualization."""
    stats = get_dashboard_stats()
    return jsonify({
        "total_scans": stats["total_scans"],
        "low_risk": stats["low_risk_count"],
        "medium_risk": stats["medium_risk_count"],
        "high_risk": stats["high_risk_count"],
        "avg_risk_score": stats["avg_risk_score"]
    })


@app.route("/history", methods=["GET"])
def history():
    """Searchable, filterable, and sortable scan history table."""
    search_query = request.args.get("q", "").strip()
    category_filter = request.args.get("category", "").strip().lower()
    sort_order = request.args.get("sort", "desc").strip().lower()

    scans = get_all_scans(
        search=search_query,
        category=category_filter,
        sort_order=sort_order
    )

    return render_template(
        "history.html",
        scans=scans,
        search_query=search_query,
        category_filter=category_filter,
        sort_order=sort_order
    )


@app.route("/history/delete/<int:scan_id>", methods=["POST"])
def delete_history_item(scan_id):
    """Deletes an individual scan record from history."""
    success = delete_scan(scan_id)
    if success:
        flash(f"Scan record #{scan_id} was successfully deleted.", "info")
    else:
        flash(f"Failed to delete scan #{scan_id} (record not found).", "warning")
    return redirect(url_for("history"))


@app.route("/history/clear", methods=["POST"])
def clear_all_history():
    """Clears all scan history records after confirmation."""
    clear_all_scans()
    flash("All scan history records have been permanently cleared.", "info")
    return redirect(url_for("history"))


@app.route("/export/<int:scan_id>/<string:format_type>", methods=["GET"])
def export_report(scan_id, format_type):
    """
    Generates and downloads a scan report in TXT, CSV, or JSON format.
    Does not claim to be a certified security audit.
    """
    scan = get_scan_by_id(scan_id)
    if not scan:
        flash("Scan record not found for export.", "warning")
        return redirect(url_for("history"))

    findings = scan.get("findings", {})
    scoring = findings.get("scoring", {})
    hostname = findings.get("validation", {}).get("hostname", "unknown")
    fmt = format_type.lower()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host = "".join(c if c.isalnum() else "_" for c in hostname)

    if fmt == "txt":
        filename = f"Security_Report_{safe_host}_{timestamp}.txt"
        lines = [
            "==================================================================",
            "   ACADEMIC WEB SECURITY SCAN REPORT",
            "   Fake Website Detector Using Web Security Analysis (TYCS Project)",
            "==================================================================",
            "",
            "DISCLAIMER:",
            "This report is an automated preliminary risk assessment based on public",
            "URL and website heuristics. It is NOT a certified security audit and",
            "does not guarantee whether a website is authentic or fraudulent.",
            "",
            f"Report Generated At : {scan['scanned_at']}",
            f"Scan ID             : #{scan['id']}",
            f"Submitted URL       : {scan['submitted_url']}",
            f"Normalized URL      : {scan['normalized_url']}",
            f"Resolved IP Address : {scan.get('resolved_ip') or 'Not Resolved'}",
            f"HTTP Response Code  : {scan.get('http_status') or 'N/A'}",
            "",
            "------------------------------------------------------------------",
            "RISK ASSESSMENT SUMMARY",
            "------------------------------------------------------------------",
            f"Final Risk Score    : {scan['risk_score']} / 100",
            f"Risk Category       : {scan['risk_category']}",
            f"Overall Verdict     : {scoring.get('verdict_summary', 'N/A')}",
            "",
            "------------------------------------------------------------------",
            "DETECTED RISK INDICATORS (NEGATIVE FINDINGS)",
            "------------------------------------------------------------------",
        ]
        negative = scoring.get("negative_findings", [])
        if negative:
            for idx, item in enumerate(negative, 1):
                lines.append(f"{idx}. [{item.get('category')}] {item.get('indicator')} (+{item.get('points')} pts)")
                lines.append(f"   Explanation: {item.get('description')}")
        else:
            lines.append("No negative risk indicators were detected.")

        lines.extend([
            "",
            "------------------------------------------------------------------",
            "POSITIVE SECURITY ATTRIBUTES",
            "------------------------------------------------------------------",
        ])
        positive = scoring.get("positive_findings", [])
        if positive:
            for idx, item in enumerate(positive, 1):
                lines.append(f"{idx}. {item.get('indicator')}: {item.get('description')}")
        else:
            lines.append("No positive attributes recorded.")

        lines.extend([
            "",
            "------------------------------------------------------------------",
            "RECOMMENDED SAFETY ACTIONS",
            "------------------------------------------------------------------",
        ])
        recs = scoring.get("recommendations", [])
        for idx, rec in enumerate(recs, 1):
            lines.append(f"{idx}. {rec}")

        content = "\n".join(lines)
        return Response(
            content,
            mimetype="text/plain",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    elif fmt == "csv":
        filename = f"Security_Report_{safe_host}_{timestamp}.csv"
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Field", "Value"])
        writer.writerow(["Scan ID", scan["id"]])
        writer.writerow(["Scan Date", scan["scanned_at"]])
        writer.writerow(["Submitted URL", scan["submitted_url"]])
        writer.writerow(["Normalized URL", scan["normalized_url"]])
        writer.writerow(["Risk Score", scan["risk_score"]])
        writer.writerow(["Risk Category", scan["risk_category"]])
        writer.writerow(["Scan Status", scan["scan_status"]])
        writer.writerow(["Resolved IP", scan.get("resolved_ip") or "N/A"])
        writer.writerow(["HTTP Status", scan.get("http_status") or "N/A"])
        writer.writerow([])
        writer.writerow(["Indicator Type", "Category", "Indicator Name", "Points Added", "Description"])

        for item in scoring.get("negative_findings", []):
            writer.writerow([
                "Risk Indicator",
                item.get("category"),
                item.get("indicator"),
                item.get("points"),
                item.get("description")
            ])
        for item in scoring.get("positive_findings", []):
            writer.writerow([
                "Positive Attribute",
                "Good Practice",
                item.get("indicator"),
                0,
                item.get("description")
            ])

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    elif fmt == "json":
        filename = f"Security_Report_{safe_host}_{timestamp}.json"
        export_payload = {
            "metadata": {
                "project": "Fake Website Detector Using Web Security Analysis",
                "academic_level": "TYCS Final Year Project",
                "exported_at": datetime.now().isoformat(),
                "disclaimer": "Automated preliminary heuristic assessment; not a certified security audit."
            },
            "scan": scan
        }
        return Response(
            json.dumps(export_payload, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    flash("Unsupported export format requested.", "warning")
    return redirect(url_for("results", scan_id=scan_id))


@app.route("/about", methods=["GET"])
def about():
    """Academic project documentation, methodology, system scope, and limitations."""
    return render_template("about.html")


@app.errorhandler(404)
def page_not_found(e):
    return render_template("base.html", error_title="404 - Page Not Found", error_message="The requested page does not exist."), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template("base.html", error_title="500 - Internal Server Error", error_message="An unexpected server error occurred. Please try again."), 500


if __name__ == "__main__":
    print("=" * 60)
    print(" Fake Website Detector Using Web Security Analysis")
    print(" TYCS Final Year Project Server Running")
    print(" Local Access URL: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=config.DEBUG)
