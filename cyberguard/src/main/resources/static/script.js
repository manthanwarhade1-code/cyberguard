
const API = "/api";

function showPage(page) {
    document.querySelectorAll(".page").forEach(section => {
        section.classList.add("hidden");
    });

    document.getElementById(page).classList.remove("hidden");

    document.querySelectorAll(".nav").forEach(button => {
        button.classList.toggle(
            "active",
            button.dataset.page === page
        );
    });

    const titles = {
        dashboard: "Security Dashboard",
        url: "Malicious URL Scanner",
        file: "File Security Scanner",
        network: "Network Monitor",
        history: "Scan History"
    };

    document.getElementById("page-title").textContent =
        titles[page];

    if (page === "history") loadHistory();
    if (page === "dashboard") loadDashboard();
}

document.querySelectorAll(".nav").forEach(button => {
    button.addEventListener("click", () => {
        showPage(button.dataset.page);
    });
});

function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
    })[char]);
}

function showResult(id, result) {
    const box = document.getElementById(id);

    box.classList.remove("hidden");

    box.innerHTML = `
        <h3>Analysis Result</h3>
        <p><strong>Type:</strong> ${escapeHTML(result.type)}</p>
        <p><strong>Target:</strong> ${escapeHTML(result.target)}</p>
        <p><strong>Status:</strong>
            <span class="risk">${escapeHTML(result.status)}</span>
        </p>
        <p><strong>Details:</strong> ${escapeHTML(result.details)}</p>
        <p><strong>Time:</strong> ${escapeHTML(result.time)}</p>
    `;

    loadDashboard();
}

async function scanURL() {
    const url = document.getElementById("urlInput").value.trim();

    if (!url) {
        alert("Please enter a URL");
        return;
    }

    try {
        const response = await fetch(API + "/scan/url", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url })
        });

        const result = await response.json();

        if (!response.ok) throw new Error(result.message || "URL scan failed");

        showResult("urlResult", result);

    } catch (error) {
        alert(error.message);
    }
}

async function scanFile() {
    const input = document.getElementById("fileInput");

    if (!input.files.length) {
        alert("Please select a file");
        return;
    }

    const formData = new FormData();
    formData.append("file", input.files[0]);

    try {
        const response = await fetch(API + "/scan/file", {
            method: "POST",
            body: formData
        });

        const result = await response.json();

        if (!response.ok) throw new Error(result.message || "File scan failed");

        showResult("fileResult", result);

    } catch (error) {
        alert(error.message);
    }
}

async function scanNetwork() {
    const logs = document.getElementById("networkInput").value;

    if (!logs.trim()) {
        alert("Please enter network logs");
        return;
    }

    try {
        const response = await fetch(API + "/scan/network", {
            method: "POST",
            headers: {
                "Content-Type": "text/plain"
            },
            body: logs
        });

        const result = await response.json();

        if (!response.ok) throw new Error(result.message || "Network scan failed");

        showResult("networkResult", result);

    } catch (error) {
        alert(error.message);
    }
}

async function loadHistory() {
    try {
        const response = await fetch(API + "/history");

        if (!response.ok) throw new Error("History unavailable");

        const records = await response.json();
        const container = document.getElementById("historyList");

        if (!records.length) {
            container.textContent = "No records found.";
            return;
        }

        container.innerHTML = records.map(item => `
            <div class="record">
                <strong>${escapeHTML(item.type)}</strong>
                <p>Target: ${escapeHTML(item.target)}</p>
                <p>Status: ${escapeHTML(item.status)}</p>
                <p>Details: ${escapeHTML(item.details)}</p>
                <small>${escapeHTML(item.time)}</small>
            </div>
        `).join("");

    } catch (error) {
        document.getElementById("historyList").textContent =
            error.message;
    }
}

async function loadDashboard() {
    try {
        const response = await fetch(API + "/history");

        if (!response.ok) return;

        const records = await response.json();

        const threats = records.filter(
            item => item.status !== "NO OBVIOUS THREAT"
        ).length;

        document.getElementById("total").textContent =
            records.length;

        document.getElementById("threats").textContent =
            threats;

        document.getElementById("safe").textContent =
            records.length - threats;

        const recent = document.getElementById("recent");

        if (!records.length) {
            recent.textContent = "No scan activity available.";
        } else {
            recent.innerHTML = records.slice(0, 5).map(item => `
                <div class="record">
                    <strong>${escapeHTML(item.type)}</strong> -
                    ${escapeHTML(item.status)}
                    <p>${escapeHTML(item.target)}</p>
                </div>
            `).join("");
        }

    } catch (error) {
        console.error(error);
    }
}

async function clearHistory() {
    if (!confirm("Clear all scan history?")) return;

    try {
        const response = await fetch(API + "/history", {
            method: "DELETE"
        });

        if (!response.ok) throw new Error("Could not clear history");

        loadHistory();
        loadDashboard();

    } catch (error) {
        alert(error.message);
    }
}

loadDashboard();
