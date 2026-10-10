import json
import os
from datetime import datetime


HISTORY_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "scan_history.json"
)

MAX_HISTORY = 100


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

        return []

    except (
        json.JSONDecodeError,
        OSError
    ):
        return []


def save_history(history):

    try:

        with open(
            HISTORY_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                history,
                file,
                indent=4,
                ensure_ascii=False
            )

        return True

    except OSError as error:

        print(
            "History save error:",
            error
        )

        return False


def add_scan(result):

    history = load_history()

    now = datetime.now()

    scan = {

        "id":
            now.strftime(
                "%Y%m%d%H%M%S%f"
            ),

        "timestamp":
            now.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "url":
            result.get(
                "url",
                ""
            ),

        "result":
            result.get(
                "result",
                "Unknown"
            ),

        "score":
            result.get(
                "score",
                0
            ),

        "risk_level":
            result.get(
                "risk_level",
                "Unknown"
            ),

        "site_name":
            result.get(
                "site_name",
                "Unknown"
            ),

        "domain":
            result.get(
                "domain",
                ""
            ),

        "site_type":
            result.get(
                "site_type",
                "Unknown"
            ),

        "domain_status":
            result.get(
                "domain_status",
                "Unknown"
            ),

        "known_domain":
            result.get(
                "known_domain",
                False
            ),

        "ml_prediction":
            result.get(
                "ml_prediction",
                "Unavailable"
            ),

        "ml_confidence":
            result.get(
                "ml_confidence",
                0
            ),

        "rule_score":
            result.get(
                "rule_score",
                0
            ),

        "ml_score":
            result.get(
                "ml_score",
                0
            ),

        "raw_ml_score":
            result.get(
                "raw_ml_score",
                0
            ),

        "reasons":
            result.get(
                "reasons",
                []
            ),

        "detection_methods":
            result.get(
                "detection_methods",
                []
            ),

        "features":
            result.get(
                "features",
                {}
            )
    }


    history.insert(
        0,
        scan
    )


    history = history[
        :MAX_HISTORY
    ]


    saved = save_history(
        history
    )


    if not saved:
        print(
            "WARNING: Scan was not saved."
        )


    return scan


def get_history(
    limit=50
):

    history = load_history()

    try:

        limit = int(limit)

    except (
        TypeError,
        ValueError
    ):

        limit = 50


    limit = max(
        1,
        min(
            limit,
            MAX_HISTORY
        )
    )


    return history[
        :limit
    ]


def clear_history():

    try:

        if os.path.exists(
            HISTORY_FILE
        ):

            os.remove(
                HISTORY_FILE
            )

        return True

    except OSError as error:

        print(
            "History clear error:",
            error
        )

        return False


def get_statistics():

    history = load_history()

    total = len(history)

    safe = 0

    suspicious = 0

    malicious = 0


    for scan in history:

        result = str(
            scan.get(
                "result",
                ""
            )
        ).lower().strip()


        if result == "safe":

            safe += 1

        elif result == "suspicious":

            suspicious += 1

        elif result == "malicious":

            malicious += 1


    return {

        "total_scans":
            total,

        "safe":
            safe,

        "suspicious":
            suspicious,

        "malicious":
            malicious

    }