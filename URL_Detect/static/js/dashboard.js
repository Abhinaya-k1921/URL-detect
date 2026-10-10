// static/js/dashboard.js

document.addEventListener("DOMContentLoaded", () => {
    loadDashboard();
    loadHistory();

    const refreshStatsButton = document.getElementById("refreshStats");
    const refreshHistoryButton = document.getElementById("refreshHistory");
    const clearHistoryButton = document.getElementById("clearHistory");

    if (refreshStatsButton) {
        refreshStatsButton.addEventListener("click", loadDashboard);
    }

    if (refreshHistoryButton) {
        refreshHistoryButton.addEventListener("click", loadHistory);
    }

    if (clearHistoryButton) {
        clearHistoryButton.addEventListener("click", clearScanHistory);
    }
});


async function loadDashboard() {
    try {
        const response = await fetch("/statistics");

        if (!response.ok) {
            throw new Error("Failed to load statistics");
        }

        const data = await response.json();

        updateElement("totalScans", data.total_scans || 0);
        updateElement("safeScans", data.safe || 0);
        updateElement("suspiciousScans", data.suspicious || 0);
        updateElement("maliciousScans", data.malicious || 0);

        updateCharts(data);
    } catch (error) {
        console.error("Dashboard error:", error);
    }
}


function updateElement(id, value) {
    const element = document.getElementById(id);

    if (element) {
        element.textContent = value;
    }
}


function updateCharts(data) {
    const total = Number(data.total_scans || 0);
    const safe = Number(data.safe || 0);
    const suspicious = Number(data.suspicious || 0);
    const malicious = Number(data.malicious || 0);

    updateBarChart(
        "safeBar",
        "safeBarValue",
        safe,
        total
    );

    updateBarChart(
        "suspiciousBar",
        "suspiciousBarValue",
        suspicious,
        total
    );

    updateBarChart(
        "maliciousBar",
        "maliciousBarValue",
        malicious,
        total
    );

    updateThreatChart(
        safe,
        suspicious,
        malicious,
        total
    );
}


function updateBarChart(barId, valueId, value, total) {
    const bar = document.getElementById(barId);
    const valueElement = document.getElementById(valueId);

    const percentage = total > 0
        ? Math.round((value / total) * 100)
        : 0;

    if (bar) {
        bar.style.width = `${percentage}%`;
    }

    if (valueElement) {
        valueElement.textContent = `${value} (${percentage}%)`;
    }
}


function updateThreatChart(safe, suspicious, malicious, total) {
    const chart = document.getElementById("threatChart");

    if (!chart) {
        return;
    }

    if (total === 0) {
        chart.style.background =
            "conic-gradient(#202936 0deg 360deg)";
        return;
    }

    const safeDegrees = (safe / total) * 360;
    const suspiciousDegrees = (suspicious / total) * 360;
    const maliciousDegrees = (malicious / total) * 360;

    const safeEnd = safeDegrees;
    const suspiciousEnd = safeDegrees + suspiciousDegrees;
    const maliciousEnd =
        safeDegrees +
        suspiciousDegrees +
        maliciousDegrees;

    chart.style.background = `
        conic-gradient(
            #22c55e 0deg ${safeEnd}deg,
            #f59e0b ${safeEnd}deg ${suspiciousEnd}deg,
            #ef4444 ${suspiciousEnd}deg ${maliciousEnd}deg
        )
    `;
}


async function loadHistory() {
    const tableBody = document.getElementById("historyBody");
    const emptyHistory = document.getElementById("emptyHistory");

    if (!tableBody) {
        return;
    }

    try {
        const response = await fetch("/history?limit=50");

        if (!response.ok) {
            throw new Error("Failed to load scan history");
        }

        const history = await response.json();

        tableBody.innerHTML = "";

        if (!Array.isArray(history) || history.length === 0) {
            if (emptyHistory) {
                emptyHistory.style.display = "block";
            }
            return;
        }

        if (emptyHistory) {
            emptyHistory.style.display = "none";
        }

        history.forEach((scan) => {
            const row = document.createElement("tr");

            const result = String(scan.result || "Unknown");
            const resultClass = result.toLowerCase();

            row.innerHTML = `
                <td>${escapeHtml(scan.timestamp || "-")}</td>

                <td class="history-url"
                    title="${escapeHtml(scan.url || "")}">
                    ${escapeHtml(shortenUrl(scan.url || "-"))}
                </td>

                <td>
                    ${escapeHtml(scan.site_name || "Unknown")}
                </td>

                <td>
                    <span class="history-badge ${resultClass}">
                        ${escapeHtml(result)}
                    </span>
                </td>

                <td>
                    ${escapeHtml(String(scan.score ?? 0))}
                </td>

                <td>
                    ${escapeHtml(scan.risk_level || "Unknown")}
                </td>
            `;

            tableBody.appendChild(row);
        });
    } catch (error) {
        console.error("History error:", error);

        tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="history-error">
                    Unable to load scan history.
                </td>
            </tr>
        `;
    }
}


function shortenUrl(url, maxLength = 65) {
    if (!url) {
        return "-";
    }

    if (url.length <= maxLength) {
        return url;
    }

    return url.substring(0, maxLength) + "...";
}


async function clearScanHistory() {
    const confirmed = window.confirm(
        "Are you sure you want to delete all scan history?"
    );

    if (!confirmed) {
        return;
    }

    try {
        const response = await fetch("/history", {
            method: "DELETE"
        });

        if (!response.ok) {
            throw new Error("Failed to clear history");
        }

        await loadDashboard();
        await loadHistory();

        showMessage(
            "Scan history cleared successfully.",
            "success"
        );
    } catch (error) {
        console.error("Clear history error:", error);

        showMessage(
            "Unable to clear scan history.",
            "error"
        );
    }
}


function showMessage(message, type = "success") {
    let container = document.getElementById("dashboardMessage");

    if (!container) {
        container = document.createElement("div");
        container.id = "dashboardMessage";

        document.body.appendChild(container);
    }

    container.textContent = message;
    container.className = `dashboard-message ${type}`;
    container.style.display = "block";

    setTimeout(() => {
        container.style.display = "none";
    }, 3000);
}


function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


window.loadDashboard = loadDashboard;
window.loadHistory = loadHistory;