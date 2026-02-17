const stats = window.dashboardStats || { total: 0, Phishing: 0, Suspicious: 0, Safe: 0 };
const logs  = window.dashboardLogs  || [];

// Now init charts automatically when DOM is ready
document.addEventListener("DOMContentLoaded", function () {
    // Initialize charts using the injected data
    initCharts(stats, logs);

    // ===================================================================
    // 1. Real-time Email Scanning (Dashboard + Scan Page)
    // ===================================================================
    const checkBtn = document.getElementById("checkBtn");
    const emailInput = document.getElementById("emailInput");
    const resultBox = document.getElementById("resultBox");

    if (checkBtn && emailInput && resultBox) {
        checkBtn.addEventListener("click", async function () {
            const emailText = emailInput.value.trim();

            if (!emailText) {
                showResult("Please paste an email first!", "warning");
                return;
            }

            if (emailText.length > 100000) {
                showResult("Email too large. Max 100,000 characters.", "warning");
                return;
            }

            showResult("Scanning email...", "safe");

            try {
                const response = await fetch("/scan_api", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email_text: emailText })
                });

                const data = await response.json();

                if (response.ok) {
                    const confidence = data.confidence !== undefined 
                        ? (data.confidence * 100).toFixed(1) + "%" 
                        : "N/A";

                    const message = `
                        <strong style="font-size: 28px; display: block; margin-bottom: 10px;">
                            ${data.label}
                        </strong>
                        <strong>Confidence:</strong> ${confidence}<br>
                        <strong>Reason:</strong> ${data.reason || "No specific reason"}
                        ${data.quarantined ? "<br><br>Email has been <strong>QUARANTINED</strong>" : ""}
                    `;

                    showResult(message, 
                        data.label === "Phishing" ? "phishing" :
                        data.label === "Suspicious" ? "warning" : "safe"
                    );

                    // Auto-refresh dashboard after scan
                    if (window.location.pathname === "/") {
                        setTimeout(() => location.reload(), 2500);
                    }
                } else {
                    showResult(data.error || "Scan failed", "warning");
                }
            } catch (err) {
                console.error("Scan error:", err);
                showResult("Network error. Please try again.", "warning");
            }
        });
    }

    function showResult(html, type) {
        resultBox.innerHTML = html;
        resultBox.className = "result";
        resultBox.classList.add(type);
        resultBox.classList.remove("hidden");
    }
});


// ===================================================================
// 3. Chart Initialization Function
// ===================================================================
function initCharts(stats, logs) {
    // --- Pie/Doughnut Chart: Threat Distribution ---
    const pieCtx = document.getElementById("pieChart");
    if (pieCtx) {
        new Chart(pieCtx, {
            type: "doughnut",
            data: {
                labels: ["Phishing", "Suspicious", "Safe"],
                datasets: [{
                    data: [
                        stats.Phishing || 0,
                        stats.Suspicious || 0,
                        stats.Safe || 0
                    ],
                    backgroundColor: ["#e74c3c", "#f39c12", "#27ae60"],
                    borderColor: "#0b132b",
                    borderWidth: 3,
                    hoverOffset: 15
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: "#e6e6e6", font: { size: 14 } }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 
                                    ? ((context.parsed / total) * 100).toFixed(1) + "%"
                                    : "0%";
                                return `${context.label}: ${context.parsed} (${percentage})`;
                            }
                        }
                    }
                }
            }
        });
    }

    // --- Line Chart: Phishing Detections Over Time (Last 12 entries) ---
    const lineCtx = document.getElementById("lineChart");
    if (lineCtx && logs.length > 0) {
        const recentLogs = logs.slice(0, 12).reverse();

        const labels = recentLogs.map(log => 
            new Date(log.timestamp).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit"
            })
        );

        const phishingCount = recentLogs.map(log => log.label === "Phishing" ? 1 : 0);
        const cumulative = phishingCount.reduce((acc, val, i) => {
            acc.push((acc[i - 1] || 0) + val);
            return acc;
        }, []);

        new Chart(lineCtx, {
            type: "line",
            data: {
                labels: labels,
                datasets: [{
                    label: "Cumulative Phishing Detections",
                    data: cumulative,
                    borderColor: "#e74c3c",
                    backgroundColor: "rgba(231, 76, 60, 0.1)",
                    borderWidth: 3,
                    pointBackgroundColor: "#e74c3c",
                    pointRadius: 5,
                    pointHoverRadius: 8,
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            title: function(context) {
                                return "Time: " + context[0].label;
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { stepSize: 1, color: "#a0b5cc" },
                        grid: { color: "rgba(255,255,255,0.05)" }
                    },
                    x: {
                        ticks: { color: "#a0b5cc" },
                        grid: { color: "rgba(255,255,255,0.05)" }
                    }
                }
            }
        });
    }
}



// ... Rest of file unchanged ...

// NEW: Toggle for SHAP meta plot
function toggleExpand(button) {
    const content = button.nextElementSibling;
    if (content.style.display === "none" || content.style.display === "") {
        content.style.display = "block";
        button.textContent = "▲";
    } else {
        content.style.display = "none";
        button.textContent = "▼";
    }
}


async function showMetaChart(logId, button) {
    const content = button.nextElementSibling;
    if (content.style.display === "block") {
        content.style.display = "none";
        button.textContent = "▼";
        return;
    }

    // Fetch data
    const res = await fetch(`/shap/${logId}`);
    const data = await res.json();

    // Render meta chart
    const ctx = document.getElementById(`metaChart${logId}`).getContext('2d');
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.meta.labels,
            datasets: [{
                label: 'SHAP Contribution',
                data: data.meta.values,
                backgroundColor: '#5bc0be',
                borderColor: '#5bc0be',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            scales: { y: { beginAtZero: true } },
            plugins: { legend: { display: false } }
        }
    });

    content.style.display = "block";
    button.textContent = "▲";
}

window.addEventListener('load', async () => {
    console.log('[DETAIL DEBUG] Page fully loaded');
    console.log('[DETAIL DEBUG] Current URL path:', window.location.pathname);

    if (!window.location.pathname.startsWith('/detail/')) {
        console.log('[DETAIL DEBUG] Not a detail page → skipping');
        return;
    }

    const logId = window.location.pathname.split('/').pop();
    console.log('[DETAIL DEBUG] Extracted log ID:', logId);

    const grid = document.querySelector('.plot-grid');
    if (!grid) {
        console.error('[DETAIL DEBUG] .plot-grid container not found in DOM');
        return;
    }
    console.log('[DETAIL DEBUG] Found .plot-grid element');

    try {
        console.log('[DETAIL DEBUG] Fetching /shap/' + logId);
        const response = await fetch(`/shap/${logId}`);
        console.log('[DETAIL DEBUG] Fetch response status:', response.status);

        if (!response.ok) {
            throw new Error(`Fetch failed with status ${response.status}`);
        }

        const data = await response.json();
        console.log('[DETAIL DEBUG] Raw SHAP data:', data);

        // Check each section exists
        console.log('[DETAIL DEBUG] meta exists?', !!data.meta);
        console.log('[DETAIL DEBUG] word exists?', !!data.word);
        console.log('[DETAIL DEBUG] char exists?', !!data.char);
        console.log('[DETAIL DEBUG] count exists?', !!data.count);
        console.log('[DETAIL DEBUG] stats exists?', !!data.stats);

        function drawChart(canvasId, sectionKey, title) {
            const canvas = document.getElementById(canvasId);
            if (!canvas) {
                console.error(`[DETAIL DEBUG] Canvas #${canvasId} not found`);
                return;
            }
            console.log(`[DETAIL DEBUG] Drawing chart for ${title} on #${canvasId}`);

            const section = data[sectionKey] || {};
            const labels = section.labels || [];
            const values = section.values || [];

            new Chart(canvas, {
                type: 'bar',
                data: {
                    labels: labels.length ? labels : ['No data'],
                    datasets: [{
                        label: 'SHAP value',
                        data: values.length ? values : [0],
                        backgroundColor: '#5bc0be',
                        borderColor: '#0b132b',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { title: { display: true, text: title } },
                    scales: { y: { beginAtZero: false } }
                }
            });
        }

        drawChart('metaChart',  'meta',  'Meta Model');
        drawChart('wordChart',  'word',  'Word Model');
        drawChart('charChart',  'char',  'Char Model');
        drawChart('countChart', 'count', 'Count Model');
        drawChart('statsChart', 'stats', 'Stats Model');

    } catch (err) {
        console.error('[DETAIL DEBUG] Critical error:', err);
        grid.innerHTML += `<div style="color:#e74c3c; padding:20px; text-align:center;">
            Failed to load SHAP explanations: ${err.message}<br>
            (Check browser console for more details)
        </div>`;
    }
});




// Force-run detail charts as soon as possible
function tryInitDetailCharts() {
    if (!window.location.pathname.includes('/detail/')) return;

    console.log('[DETAIL FORCE] Running on path:', window.location.pathname);

    const logId = window.location.pathname.split('/').pop();
    console.log('[DETAIL FORCE] Log ID:', logId);

    fetch(`/shap/${logId}`)
        .then(r => {
            console.log('[DETAIL FORCE] Fetch status:', r.status);
            return r.json();
        })
        .then(data => {
            console.log('[DETAIL FORCE] Data:', data);

            const draw = (canvasId, sectionKey, title) => {
                const c = document.getElementById(canvasId);
                if (!c) {
                    console.warn('[DETAIL FORCE] No canvas:', canvasId);
                    return;
                }
                console.log('[DETAIL FORCE] Drawing:', title);

                new Chart(c.getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: (data[sectionKey]?.labels || ['No data']),
                        datasets: [{
                            label: 'SHAP',
                            data: (data[sectionKey]?.values || [0]),
                            backgroundColor: '#5bc0be'
                        }]
                    },
                    options: { responsive: true }
                });
            };

            draw('metaChart', 'meta', 'Meta');
            draw('wordChart', 'word', 'Word');
            draw('charChart', 'char', 'Char');
            draw('countChart', 'count', 'Count');
            draw('statsChart', 'stats', 'Stats');
        })
        .catch(e => console.error('[DETAIL FORCE] Error:', e));
}

// Try immediately, after small delay, and on load
setTimeout(tryInitDetailCharts, 100);
setTimeout(tryInitDetailCharts, 500);
window.addEventListener('load', tryInitDetailCharts);