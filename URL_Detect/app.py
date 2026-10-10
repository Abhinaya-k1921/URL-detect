from flask import Flask, render_template, request, jsonify, send_file
from detector import check_url
from history import (
    add_scan,
    get_history,
    clear_history,
    get_statistics
)
from report import generate_security_report
import os

app = Flask(__name__)


# ---------------------------------------------------------
# NO-CACHE HEADERS
# Prevent browser from showing old history/statistics data
# ---------------------------------------------------------

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ---------------------------------------------------------
# HOME
# ---------------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------------------------------------------------
# URL ANALYSIS
# ---------------------------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json(silent=True)

        if not data or "url" not in data:
            return jsonify({
                "success": False,
                "error": "URL is required"
            }), 400

        url = str(data["url"]).strip()

        if not url:
            return jsonify({
                "success": False,
                "error": "Please enter a URL"
            }), 400

        result = check_url(url)

        # Save valid scans to history
        if result.get("result") != "Invalid":
            saved_scan = add_scan(result)

            if not saved_scan:
                print("WARNING: Scan history could not be saved.")

        return jsonify(result)

    except Exception as error:
        print("Analyze error:", error)

        return jsonify({
            "success": False,
            "error": "Unable to analyze the URL",
            "details": str(error)
        }), 500


# ---------------------------------------------------------
# SCAN HISTORY
# ---------------------------------------------------------

@app.route("/history", methods=["GET"])
def history():
    try:
        limit = request.args.get("limit", "100")

        history_data = get_history(limit)

        return jsonify({
            "success": True,
            "history": history_data,
            "count": len(history_data)
        })

    except Exception as error:
        print("History error:", error)

        return jsonify({
            "success": False,
            "error": "Unable to load scan history",
            "details": str(error)
        }), 500


# ---------------------------------------------------------
# CLEAR HISTORY
# ---------------------------------------------------------

@app.route("/history", methods=["DELETE"])
def delete_history():
    try:
        success = clear_history()

        if not success:
            return jsonify({
                "success": False,
                "error": "Unable to clear scan history"
            }), 500

        return jsonify({
            "success": True,
            "message": "Scan history cleared successfully"
        })

    except Exception as error:
        print("Clear history error:", error)

        return jsonify({
            "success": False,
            "error": "Unable to clear scan history",
            "details": str(error)
        }), 500


# ---------------------------------------------------------
# STATISTICS
# ---------------------------------------------------------

@app.route("/statistics", methods=["GET"])
def statistics():
    try:
        stats = get_statistics()

        return jsonify({
            "success": True,
            "statistics": stats
        })

    except Exception as error:
        print("Statistics error:", error)

        return jsonify({
            "success": False,
            "error": "Unable to load statistics",
            "details": str(error)
        }), 500


# ---------------------------------------------------------
# GENERATE SECURITY REPORT
# ---------------------------------------------------------

@app.route("/report", methods=["POST"])
def create_report():
    try:
        data = request.get_json(silent=True)

        if not data:
            return jsonify({
                "success": False,
                "error": "Scan result is required"
            }), 400

        if not data.get("url"):
            return jsonify({
                "success": False,
                "error": "URL is required"
            }), 400

        report = generate_security_report(data)

        if not report:
            return jsonify({
                "success": False,
                "error": "Unable to generate report"
            }), 500

        return jsonify({
            "success": True,
            "filename": report["filename"],
            "message": "Security report generated successfully"
        })

    except Exception as error:
        print("Report generation error:", error)

        return jsonify({
            "success": False,
            "error": "Unable to generate security report",
            "details": str(error)
        }), 500


# ---------------------------------------------------------
# DOWNLOAD REPORT
# ---------------------------------------------------------

@app.route("/report/download/<filename>", methods=["GET"])
def download_report(filename):
    try:
        reports_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "reports"
        )

        filepath = os.path.join(reports_dir, filename)

        if not os.path.isfile(filepath):
            return jsonify({
                "success": False,
                "error": "Report not found"
            }), 404

        return send_file(
            filepath,
            as_attachment=True,
            download_name=filename,
            mimetype="text/html"
        )

    except Exception as error:
        print("Report download error:", error)

        return jsonify({
            "success": False,
            "error": "Unable to download report",
            "details": str(error)
        }), 500


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "SentinelURL",
        "version": "1.0"
    })


# ---------------------------------------------------------
# 404 ERROR
# ---------------------------------------------------------

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found"
    }), 404


# ---------------------------------------------------------
# 500 ERROR
# ---------------------------------------------------------

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500


# ---------------------------------------------------------
# START SERVER
# ---------------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("SentinelURL - Malicious URL Detection System")
    print("=" * 60)

    print("Server      : http://127.0.0.1:5000")
    print("Scanner     : POST /analyze")
    print("History     : GET /history")
    print("Statistics  : GET /statistics")
    print("Reports     : POST /report")
    print("Health      : GET /health")

    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )