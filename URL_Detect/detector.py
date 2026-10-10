import re
import ipaddress
import os
import joblib
import pandas as pd

from urllib.parse import urlparse



# ============================================================
# KNOWN POPULAR DOMAINS
# ============================================================
# This file is generated from a public top-domain ranking.
# It is supporting evidence, NOT a security whitelist.
KNOWN_DOMAINS_PATH = os.path.join(
    os.path.dirname(__file__),
    "known_domains.txt"
)


def load_known_domains():
    domains = set()

    if not os.path.exists(KNOWN_DOMAINS_PATH):
        print("Warning: known_domains.txt not found. Run build_domain_list.py.")
        return domains

    try:
        with open(KNOWN_DOMAINS_PATH, "r", encoding="utf-8") as file:
            for line in file:
                domain = line.strip().lower().rstrip(".")
                if domain and not domain.startswith("#"):
                    domains.add(domain)

        print(f"Known popular domains loaded: {len(domains):,}")

    except Exception as e:
        print("Warning: Could not load known_domains.txt.")
        print("Reason:", e)

    return domains


KNOWN_DOMAINS = load_known_domains()


def is_known_domain(hostname):
    """Return True for an exact known domain or a subdomain of one."""
    hostname = (hostname or "").lower().rstrip(".")

    if not hostname or not KNOWN_DOMAINS:
        return False

    parts = hostname.split(".")

    for index in range(len(parts) - 1):
        candidate = ".".join(parts[index:])
        if candidate in KNOWN_DOMAINS:
            return True

    return hostname in KNOWN_DOMAINS


# ============================================================
# SITE / DOMAIN INFORMATION
# ============================================================

# Common official domains used to display a friendly site name.
# This is presentation metadata only; it does NOT affect the risk score.
KNOWN_SITE_NAMES = {
    "google.com": "Google",
    "youtube.com": "YouTube",
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "whatsapp.com": "WhatsApp",
    "x.com": "X",
    "twitter.com": "X",
    "github.com": "GitHub",
    "linkedin.com": "LinkedIn",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "amazon.com": "Amazon",
    "amazon.in": "Amazon India",
    "flipkart.com": "Flipkart",
    "wikipedia.org": "Wikipedia",
    "reddit.com": "Reddit",
    "discord.com": "Discord",
    "telegram.org": "Telegram",
    "openai.com": "OpenAI",
    "chatgpt.com": "ChatGPT",
    "netflix.com": "Netflix",
    "spotify.com": "Spotify",
    "paypal.com": "PayPal",
    "cloudflare.com": "Cloudflare",
    "stackoverflow.com": "Stack Overflow",
    "medium.com": "Medium",
    "canva.com": "Canva",
    "zoom.us": "Zoom",
    "adobe.com": "Adobe",
    "oracle.com": "Oracle",
    "ibm.com": "IBM",
    "nvidia.com": "NVIDIA",
    "intel.com": "Intel",
}

def get_base_domain(hostname):
    """Return a simple registrable-domain approximation without external dependencies."""
    hostname = (hostname or "").lower().rstrip(".")
    if not hostname:
        return ""

    if is_ip_address(hostname):
        return hostname

    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname

    # Handle common multi-part public suffixes.
    common_two_part_suffixes = {
        "co.in", "co.uk", "co.jp", "com.au", "com.br",
        "com.cn", "com.sg", "net.in", "org.in", "gov.in",
        "ac.in", "edu.in"
    }

    suffix = ".".join(parts[-2:])
    if suffix in common_two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def get_site_name(hostname):
    """Return a friendly site name when confidently known; otherwise a safe fallback."""
    hostname = (hostname or "").lower().rstrip(".")
    base_domain = get_base_domain(hostname)

    if not base_domain:
        return "Unknown"

    if is_ip_address(hostname):
        return "IP Address"

    if base_domain in KNOWN_SITE_NAMES:
        return KNOWN_SITE_NAMES[base_domain]

    # Generic fallback: use the domain label, but never claim it is an
    # official brand name.
    label = base_domain.split(".")[0]
    label = re.sub(r"[-_]+", " ", label).strip()

    if not label:
        return "Unknown Site"

    return label.title()


def get_domain_display(hostname):
    """Return the domain shown to the user."""
    return (hostname or "").lower().rstrip(".") or "Unknown"


# ============================================================
# SUSPICIOUS URL DATABASES
# ============================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "confirm",
    "password",
    "credential",
    "wallet",
    "bank",
    "payment",
    "billing",
    "invoice",
    "free",
    "winner",
    "prize",
    "bonus",
    "gift",
    "claim",
    "reward",
    "urgent",
    "alert"
]


SUSPICIOUS_TLDS = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".xyz",
    ".click",
    ".zip",
    ".mov",
    ".work",
    ".buzz"
]


URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at"
]


DANGEROUS_EXTENSIONS = [
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".msi",
    ".apk",
    ".dll",
    ".jar"
]


# ============================================================
# LOAD RANDOM FOREST MODEL
# ============================================================

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "model.pkl"
)

MODEL = None
MODEL_FEATURES = None


try:

    if os.path.exists(MODEL_PATH):

        model_data = joblib.load(MODEL_PATH)

        MODEL = model_data["model"]
        MODEL_FEATURES = model_data["features"]

        print("Random Forest model loaded successfully.")

    else:

        print("Warning: model.pkl not found.")

except Exception as e:

    print("Warning: Could not load Random Forest model.")
    print("Reason:", e)


# ============================================================
# CHECK IP ADDRESS
# ============================================================

def is_ip_address(hostname):

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def extract_features(url):

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    features = {

        "url_length":
            len(url),

        "hostname_length":
            len(hostname),

        "path_length":
            len(path),

        "query_length":
            len(query),

        "num_dots":
            url.count("."),

        "num_hyphens":
            url.count("-"),

        "num_underscores":
            url.count("_"),

        "num_slashes":
            url.count("/"),

        "num_question_marks":
            url.count("?"),

        "num_equals":
            url.count("="),

        "num_ampersands":
            url.count("&"),

        "num_percent":
            url.count("%"),

        "num_digits":
            sum(c.isdigit() for c in url),

        "num_special_chars":
            len(re.findall(r"[^a-zA-Z0-9]", url)),

        "has_https":
            int(parsed.scheme.lower() == "https"),

        "has_ip":
            int(is_ip_address(hostname)),

        "has_at_symbol":
            int("@" in url),

        "num_subdomains":
            max(
                0,
                len(hostname.split(".")) - 2
            ),

        "has_suspicious_keyword":
            int(
                any(
                    word in url.lower()
                    for word in SUSPICIOUS_KEYWORDS
                )
            ),

        "has_suspicious_tld":
            int(
                any(
                    hostname.lower().endswith(tld)
                    for tld in SUSPICIOUS_TLDS
                )
            ),

        "is_shortened":
            int(
                any(
                    shortener in hostname.lower()
                    for shortener in URL_SHORTENERS
                )
            ),

        "has_dangerous_extension":
            int(
                any(
                    path.lower().endswith(ext)
                    for ext in DANGEROUS_EXTENSIONS
                )
            ),

        "has_double_slash":
            int("//" in path)
    }

    return features


# ============================================================
# RULE-BASED DETECTION
# ============================================================

def calculate_rule_score(url, parsed, hostname):

    score = 0
    reasons = []

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    if parsed.scheme.lower() != "https":

        score += 10

        reasons.append(
            "The URL does not use HTTPS."
        )

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    if is_ip_address(hostname):

        score += 25

        reasons.append(
            "The URL uses an IP address instead of a normal domain."
        )

    # --------------------------------------------------------
    # URL LENGTH
    # --------------------------------------------------------

    if len(url) > 75:

        score += 10

        reasons.append(
            "The URL is unusually long."
        )

    if len(url) > 150:

        score += 10

        reasons.append(
            "The URL is extremely long."
        )

    # --------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------------

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url.lower():

            found_keywords.append(keyword)

    if found_keywords:

        keyword_score = min(
            30,
            len(found_keywords) * 10
        )

        score += keyword_score

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_keywords[:6])
        )

    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    if "@" in url:

        score += 20

        reasons.append(
            "The URL contains '@', which can hide the actual destination."
        )

    # --------------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------------

    subdomain_count = max(
        0,
        len(hostname.split(".")) - 2
    )

    if subdomain_count >= 3:

        score += 15

        reasons.append(
            "The URL contains an unusually high number of subdomains."
        )

    # --------------------------------------------------------
    # SUSPICIOUS TLD
    # --------------------------------------------------------

    hostname_lower = hostname.lower()

    if any(
        hostname_lower.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    ):

        score += 15

        reasons.append(
            "The domain uses a suspicious TLD."
        )

    # --------------------------------------------------------
    # URL SHORTENER
    # --------------------------------------------------------

    if any(
        shortener in hostname_lower
        for shortener in URL_SHORTENERS
    ):

        score += 15

        reasons.append(
            "A URL-shortening service is being used."
        )

    # --------------------------------------------------------
    # DANGEROUS FILE
    # --------------------------------------------------------

    path_lower = parsed.path.lower()

    if any(
        path_lower.endswith(ext)
        for ext in DANGEROUS_EXTENSIONS
    ):

        score += 20

        reasons.append(
            "The URL points to a potentially dangerous file."
        )

    # --------------------------------------------------------
    # SPECIAL CHARACTERS
    # --------------------------------------------------------

    special_chars = len(
        re.findall(
            r"[^a-zA-Z0-9]",
            url
        )
    )

    if special_chars > 20:

        score += 10

        reasons.append(
            "The URL contains many special characters."
        )

    # --------------------------------------------------------
    # MANY HYPHENS
    # --------------------------------------------------------

    if url.count("-") >= 4:

        score += 10

        reasons.append(
            "The URL contains many hyphens."
        )

    # --------------------------------------------------------
    # MANY PARAMETERS
    # --------------------------------------------------------

    if url.count("=") >= 4:

        score += 10

        reasons.append(
            "The URL contains many query parameters."
        )

    return min(score, 100), reasons


# ============================================================
# MAIN URL CHECK
# ============================================================

def check_url(url):

    url = url.strip()

    # --------------------------------------------------------
    # EMPTY URL
    # --------------------------------------------------------

    if not url:

        return {
            "result": "Invalid",
            "score": 0,
            "risk_level": "Unknown",
            "site_name": "Unknown",
            "domain": "",
            "site_type": "Invalid URL",
            "summary": "Please enter a valid URL for analysis.",
            "domain_status": "Not Checked",
            "detection_methods": [],
            "ml_prediction": "Unknown",
            "ml_confidence": 0,
            "rule_score": 0,
            "ml_score": 0,
            "reasons": [
                "Please enter a URL."
            ]
        }

    # --------------------------------------------------------
    # ADD HTTP IF SCHEME IS MISSING
    # --------------------------------------------------------

    test_url = url

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        test_url
    ):

        test_url = "http://" + test_url

    # --------------------------------------------------------
    # PARSE URL
    # --------------------------------------------------------

    parsed = urlparse(test_url)

    hostname = parsed.hostname or ""

    if not hostname:

        return {
            "result": "Invalid",
            "score": 0,
            "risk_level": "Unknown",
            "site_name": "Unknown",
            "domain": "",
            "site_type": "Invalid URL",
            "summary": "Please enter a valid URL for analysis.",
            "domain_status": "Not Checked",
            "detection_methods": [],
            "ml_prediction": "Unknown",
            "ml_confidence": 0,
            "rule_score": 0,
            "ml_score": 0,
            "reasons": [
                "The entered value is not a valid URL."
            ]
        }

    # ========================================================
    # RULE ENGINE
    # ========================================================

    rule_score, reasons = calculate_rule_score(
        test_url,
        parsed,
        hostname
    )

    # ========================================================
    # MACHINE LEARNING
    # ========================================================

    ml_prediction = "Unavailable"
    ml_confidence = 0
    ml_score = 0

    features = extract_features(test_url)

    if MODEL is not None and MODEL_FEATURES is not None:

        try:

            feature_df = pd.DataFrame(
                [features]
            )

            # Ensure exact same feature order
            feature_df = feature_df[
                MODEL_FEATURES
            ]

            prediction = MODEL.predict(
                feature_df
            )[0]

            probabilities = MODEL.predict_proba(
                feature_df
            )[0]

            # Class 1 = malicious
            malicious_probability = probabilities[1]

            ml_confidence = round(
                malicious_probability * 100,
                2
            )

            if prediction == 1:

                ml_prediction = "Malicious"

            else:

                ml_prediction = "Safe"

            ml_score = malicious_probability * 100

        except Exception as e:

            print(
                "ML prediction error:",
                e
            )

    # ========================================================
    # KNOWN DOMAIN CHECK
    # ========================================================

    known_domain = is_known_domain(hostname)

    # ========================================================
    # DOMAIN STATUS
    # ========================================================
    # This is display information for the frontend.
    # It does not directly change the risk score.

    if is_ip_address(hostname):
        domain_status = "IP Address"
    elif known_domain:
        domain_status = "Known Popular Domain"
    else:
        domain_status = "Unknown Domain"

    # Do not blindly whitelist popular domains.
    # Only reduce ML false positives when rule-based risk is low.
    adjusted_ml_score = ml_score

    if known_domain and rule_score == 0 and MODEL is not None:
        adjusted_ml_score = min(ml_score, 15)

        reasons.append(
            "Domain appears in the known popular-domain list; "
            "the ML contribution was reduced to help prevent false positives."
        )

    # ========================================================
    # DISPLAYED ML ASSESSMENT
    # ========================================================
    # The raw model prediction can be a false positive on a very
    # popular domain. The adjusted score is the ML contribution
    # actually used by SentinelURL for the final risk decision.
    raw_ml_prediction = ml_prediction
    raw_ml_confidence = ml_confidence

    if known_domain and rule_score == 0 and MODEL is not None:
        if adjusted_ml_score < 50:
            ml_prediction = "Safe"
            ml_confidence = round(100 - adjusted_ml_score, 2)
        else:
            ml_prediction = "Malicious"
            ml_confidence = round(adjusted_ml_score, 2)

    # ========================================================
    # COMBINE RULE SCORE + ML SCORE
    # ========================================================

    if MODEL is not None:

        final_score = (
            rule_score * 0.45
            +
            adjusted_ml_score * 0.55
        )

    else:

        final_score = rule_score

    final_score = round(
        min(100, final_score)
    )

    # ========================================================
    # FINAL CLASSIFICATION
    # ========================================================

    if final_score >= 60:

        result = "Malicious"
        risk_level = "High"

    elif final_score >= 30:

        result = "Suspicious"
        risk_level = "Medium"

    else:

        result = "Safe"
        risk_level = "Low"

    # ========================================================
    # ML EXPLANATION
    # ========================================================

    if MODEL is not None:

        if ml_prediction == "Malicious" and not (
            known_domain and rule_score == 0
        ):

            reasons.append(
                "Machine learning model detected "
                f"malicious characteristics with "
                f"{ml_confidence:.1f}% malicious probability."
            )

    # ========================================================
    # DEFAULT REASON
    # ========================================================

    if not reasons:

        reasons.append(
            "No major suspicious URL characteristics detected."
        )

    # ========================================================
    # SITE / DOMAIN SUMMARY
    # ========================================================

    site_name = get_site_name(hostname)
    domain_display = get_domain_display(hostname)

    if is_ip_address(hostname):
        site_type = "IP Address"
    elif known_domain:
        site_type = "Known Popular Domain"
    else:
        site_type = "Unknown Domain"

    if final_score >= 60:
        summary = (
            f"{site_name} ({domain_display}) shows multiple "
            "characteristics associated with potentially malicious activity. "
            "Do not open the URL unless you trust its source."
        )
    elif final_score >= 30:
        summary = (
            f"{site_name} ({domain_display}) contains some suspicious "
            "characteristics. Verify the destination and source before opening."
        )
    elif known_domain:
        summary = (
            f"{site_name} ({domain_display}) is present in the known popular-domain "
            "list, and no major suspicious URL characteristics were detected."
        )
    else:
        summary = (
            f"{site_name} ({domain_display}) did not show major suspicious "
            "URL characteristics in the checks performed."
        )

    detection_methods = [
        "Machine Learning",
        "Rule-Based Analysis",
        "Domain Reputation"
    ]

    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    return {

        "url": url,

        "result": result,

        "score": final_score,

        "risk_level": risk_level,

        "site_name": site_name,

        "domain": domain_display,

        "site_type": site_type,

        "summary": summary,

        "domain_status": domain_status,

        "detection_methods": detection_methods,

        "ml_prediction": ml_prediction,

        "ml_confidence": ml_confidence,

        "raw_ml_prediction": raw_ml_prediction,

        "raw_ml_confidence": raw_ml_confidence,

        "rule_score": rule_score,

        "ml_score": round(
            adjusted_ml_score,
            2
        ),

        "raw_ml_score": round(
            ml_score,
            2
        ),

        "known_domain": known_domain,

        "reasons": reasons,

        "features": features
    }