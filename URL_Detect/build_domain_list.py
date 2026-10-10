import csv
import io
import urllib.request
import zipfile
from pathlib import Path


TRANC0_URL = "https://tranco-list.eu/top-1m.csv.zip"
OUTPUT_FILE = Path(__file__).with_name("known_domains.txt")
LIMIT = 10000


def main():
    print("Downloading latest Tranco top-domain list...")

    request = urllib.request.Request(
        TRANC0_URL,
        headers={"User-Agent": "SentinelURL-DomainList/1.0"}
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read()

    print(f"Downloaded {len(data) / 1024 / 1024:.1f} MB.")

    with zipfile.ZipFile(io.BytesIO(data)) as archive:

        csv_names = [
            name for name in archive.namelist()
            if name.lower().endswith(".csv")
        ]

        if not csv_names:
            raise RuntimeError("No CSV file found inside the downloaded ZIP.")

        csv_name = csv_names[0]

        with archive.open(csv_name) as raw_file:
            text_file = io.TextIOWrapper(
                raw_file,
                encoding="utf-8",
                errors="replace"
            )

            reader = csv.reader(text_file)

            domains = []

            for row in reader:

                if len(row) < 2:
                    continue

                # Tranco format: rank,domain
                domain = row[1].strip().lower().rstrip(".")

                if domain:
                    domains.append(domain)

                if len(domains) >= LIMIT:
                    break

    # Remove duplicates while preserving order.
    domains = list(dict.fromkeys(domains))

    if len(domains) < LIMIT:
        raise RuntimeError(
            f"Only {len(domains)} domains were found. "
            f"Expected at least {LIMIT}."
        )

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:

        file.write(
            "# SentinelURL known popular domains\n"
        )

        file.write(
            "# Source: Tranco top-domain ranking\n"
        )

        file.write(
            "# These domains are supporting evidence, NOT a security whitelist.\n"
        )

        for domain in domains:
            file.write(domain + "\n")

    print()
    print(f"Created: {OUTPUT_FILE}")
    print(f"Domains saved: {len(domains):,}")
    print()
    print("You can now run: python app.py")


if __name__ == "__main__":
    main()
