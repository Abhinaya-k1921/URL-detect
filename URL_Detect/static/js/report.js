document.addEventListener("DOMContentLoaded", () => {
    setupReportButton();
});


function setupReportButton() {
    const button = document.getElementById("generateReport");

    if (!button) {
        return;
    }

    button.addEventListener("click", async () => {
        if (!window.lastScanResult) {
            showReportMessage(
                "Please scan a URL first.",
                "error"
            );
            return;
        }

        button.disabled = true;
        button.textContent = "Generating...";

        try {
            const response = await fetch("/report", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(
                    window.lastScanResult
                )
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    data.error || "Report generation failed"
                );
            }

            const downloadUrl =
                `/report/download/${encodeURIComponent(
                    data.filename
                )}`;

            const link = document.createElement("a");
            link.href = downloadUrl;
            link.download = data.filename;
            document.body.appendChild(link);
            link.click();
            link.remove();

            showReportMessage(
                "Security report generated successfully.",
                "success"
            );

        } catch (error) {
            console.error(
                "Report generation error:",
                error
            );

            showReportMessage(
                error.message ||
                "Unable to generate security report.",
                "error"
            );
        } finally {
            button.disabled = false;
            button.textContent = "Generate Security Report";
        }
    });
}


function showReportMessage(message, type) {
    let element =
        document.getElementById("reportMessage");

    if (!element) {
        element = document.createElement("div");
        element.id = "reportMessage";

        const button =
            document.getElementById("generateReport");

        if (button && button.parentElement) {
            button.parentElement.appendChild(element);
        } else {
            document.body.appendChild(element);
        }
    }

    element.textContent = message;
    element.className =
        `report-message ${type}`;

    element.style.display = "block";

    setTimeout(() => {
        element.style.display = "none";
    }, 4000);
}


window.setLastScanResult = function(result) {
    window.lastScanResult = result;
};