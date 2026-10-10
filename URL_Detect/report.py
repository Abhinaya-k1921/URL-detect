# report.py

from datetime import datetime
import html
import os


REPORTS_DIR = os.path.join(
    os.path.dirname(__file__),
    "reports"
)


def ensure_reports_directory():
    os.makedirs(REPORTS_DIR, exist_ok=True)


def get_risk_class(result):
    result = str(result).lower()

    if result == "malicious":
        return "malicious"
    elif result == "suspicious":
        return "suspicious"
    elif result == "safe":
        return "safe"

    return "unknown"


def generate_security_report(scan):
    ensure_reports_directory()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_report_{timestamp}.html"
    filepath = os.path.join(REPORTS_DIR, filename)

    url = html.escape(str(scan.get("url", "")))
    result = html.escape(str(scan.get("result", "Unknown")))
    score = scan.get("score", 0)
    risk_level = html.escape(str(scan.get("risk_level", "Unknown")))
    site_name = html.escape(str(scan.get("site_name", "Unknown")))
    domain = html.escape(str(scan.get("domain", "")))
    site_type = html.escape(str(scan.get("site_type", "Unknown")))
    domain_status = html.escape(
        str(scan.get("domain_status", "Unknown"))
    )

    ml_prediction = html.escape(
        str(scan.get("ml_prediction", "Unavailable"))
    )
    ml_confidence = scan.get("ml_confidence", 0)
    rule_score = scan.get("rule_score", 0)
    ml_score = scan.get("ml_score", 0)

    reasons = scan.get("reasons", [])
    features = scan.get("features", {})
    detection_methods = scan.get("detection_methods", [])

    reasons_html = ""

    if reasons:
        for reason in reasons:
            reasons_html += (
                f"<li>{html.escape(str(reason))}</li>"
            )
    else:
        reasons_html = "<li>No specific suspicious indicators detected.</li>"

    methods_html = ""

    if detection_methods:
        for method in detection_methods:
            methods_html += (
                f"<li>{html.escape(str(method))}</li>"
            )
    else:
        methods_html = "<li>No detection methods recorded.</li>"

    features_html = ""

    if isinstance(features, dict) and features:
        for key, value in features.items():
            readable_key = str(key).replace("_", " ").title()

            features_html += f"""
            <tr>
                <td>{html.escape(readable_key)}</td>
                <td>{html.escape(str(value))}</td>
            </tr>
            """
    else:
        features_html = """
        <tr>
            <td colspan="2">No feature data available.</td>
        </tr>
        """

    risk_class = get_risk_class(scan.get("result", ""))

    generated_at = datetime.now().strftime(
        "%d %B %Y, %I:%M:%S %p"
    )

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>SentinelURL Security Report</title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 0;
            font-family: Arial, Helvetica, sans-serif;
            background: #0b1120;
            color: #e5e7eb;
        }}

        .container {{
            width: 92%;
            max-width: 1100px;
            margin: 40px auto;
        }}

        .header {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 25px;
        }}

        .header h1 {{
            margin: 0 0 8px;
            font-size: 32px;
            color: #38bdf8;
        }}

        .header p {{
            margin: 5px 0;
            color: #9ca3af;
        }}

        .risk-card {{
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 25px;
            border: 1px solid #1f2937;
            background: #111827;
        }}

        .risk-card.safe {{
            border-left: 6px solid #22c55e;
        }}

        .risk-card.suspicious {{
            border-left: 6px solid #f59e0b;
        }}

        .risk-card.malicious {{
            border-left: 6px solid #ef4444;
        }}

        .risk-card.unknown {{
            border-left: 6px solid #64748b;
        }}

        .risk-title {{
            font-size: 28px;
            font-weight: bold;
            margin-bottom: 12px;
        }}

        .score {{
            font-size: 42px;
            font-weight: bold;
            margin-top: 15px;
        }}

        .section {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 25px;
        }}

        .section h2 {{
            margin-top: 0;
            color: #38bdf8;
            font-size: 22px;
        }}

        .grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
        }}

        .item {{
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 10px;
            padding: 15px;
        }}

        .item strong {{
            display: block;
            color: #94a3b8;
            margin-bottom: 6px;
            font-size: 13px;
        }}

        .item span {{
            color: #f8fafc;
            word-break: break-word;
        }}

        ul {{
            margin: 0;
            padding-left: 22px;
        }}

        li {{
            margin-bottom: 10px;
            line-height: 1.5;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th,
        td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #1f2937;
        }}

        th {{
            color: #38bdf8;
            background: #0f172a;
        }}

        td {{
            color: #d1d5db;
        }}

        .footer {{
            text-align: center;
            color: #64748b;
            padding: 25px;
            font-size: 13px;
        }}

        .notice {{
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 15px;
            color: #94a3b8;
            line-height: 1.6;
        }}

        @media (max-width: 700px) {{
            .grid {{
                grid-template-columns: 1fr;
            }}

            .container {{
                width: 94%;
                margin: 20px auto;
            }}

            .header h1 {{
                font-size: 25px;
            }}

            .score {{
                font-size: 34px;
            }}

            table {{
                font-size: 13px;
            }}
        }}
    </style>
</head>

<body>

<div class="container">

    <div class="header">
        <h1>SentinelURL</h1>
        <p>Malicious URL Detection & Security Analysis Report</p>
        <p>Generated: {html.escape(generated_at)}</p>
    </div>

    <div class="risk-card {risk_class}">
        <div class="risk-title">
            {result}
        </div>

        <div>
            Risk Level:
            <strong>{risk_level}</strong>
        </div>

        <div class="score">
            Security Score: {html.escape(str(score))}/100
        </div>
    </div>

    <div class="section">
        <h2>URL Information</h2>

        <div class="grid">

            <div class="item">
                <strong>URL</strong>
                <span>{url}</span>
            </div>

            <div class="item">
                <strong>Site Name</strong>
                <span>{site_name}</span>
            </div>

            <div class="item">
                <strong>Domain</strong>
                <span>{domain}</span>
            </div>

            <div class="item">
                <strong>Site Type</strong>
                <span>{site_type}</span>
            </div>

            <div class="item">
                <strong>Domain Status</strong>
                <span>{domain_status}</span>
            </div>

            <div class="item">
                <strong>Known Domain</strong>
                <span>
                    {html.escape(str(scan.get("known_domain", False)))}
                </span>
            </div>

        </div>
    </div>

    <div class="section">
        <h2>Detection Analysis</h2>

        <div class="grid">

            <div class="item">
                <strong>ML Prediction</strong>
                <span>{ml_prediction}</span>
            </div>

            <div class="item">
                <strong>ML Confidence</strong>
                <span>{html.escape(str(ml_confidence))}%</span>
            </div>

            <div class="item">
                <strong>ML Risk Score</strong>
                <span>{html.escape(str(ml_score))}</span>
            </div>

            <div class="item">
                <strong>Rule-Based Score</strong>
                <span>{html.escape(str(rule_score))}</span>
            </div>

        </div>
    </div>

    <div class="section">
        <h2>Detection Methods</h2>

        <ul>
            {methods_html}
        </ul>
    </div>

    <div class="section">
        <h2>Security Findings</h2>

        <ul>
            {reasons_html}
        </ul>
    </div>

    <div class="section">
        <h2>URL Feature Analysis</h2>

        <table>
            <thead>
                <tr>
                    <th>Feature</th>
                    <th>Value</th>
                </tr>
            </thead>

            <tbody>
                {features_html}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Security Notice</h2>

        <div class="notice">
            This report is generated from automated machine-learning
            and rule-based URL analysis. Detection results are
            indicators and should not be treated as a guarantee
            that a URL is safe or malicious.
        </div>
    </div>

    <div class="footer">
        SentinelURL &copy; {datetime.now().year}
        <br>
        Automated URL Security Analysis System
    </div>

</div>

</body>
</html>
"""

    with open(filepath, "w", encoding="utf-8") as file:
        file.write(report_html)

    return {
        "filename": filename,
        "filepath": filepath,
        "generated_at": generated_at
    }