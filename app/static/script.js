// document.getElementById("checkBtn").addEventListener("click", async () => {
//     const text = document.getElementById("emailInput").value.trim();
//     const box = document.getElementById("resultBox");
//     if (!text) return;

//     box.className = "result";
//     box.textContent = "Scanning...";
//     box.classList.remove("hidden");

//     const res = await fetch("/scan", {
//         method: "POST",
//         headers: { "Content-Type": "application/json" },
//         body: JSON.stringify({ email_text: text })
//     });

//     const data = await res.json();
//     box.innerHTML = `<strong>${data.label}</strong><br>${data.reason || ''}`;
//     box.classList.add(
//         data.label === "Phishing" ? "phishing" :
//         data.label === "Suspicious" ? "warning" : "safe"
//     );

//     setTimeout(() => location.reload(), 2000); // Auto refresh
// });

// function initCharts(stats, logs) {
//     const labels = ["Phishing", "Suspicious", "Safe"];
//     const data = [stats.Phishing||0, stats.Suspicious||0, stats.Safe||0];
//     const bg = ["#e74c3c", "#f39c12", "#27ae61"];

//     new Chart(document.getElementById("pieChart"), {
//         type: "doughnut",
//         data: { labels, datasets: [{ data, backgroundColor: bg }] },
//         options: { responsive: true }
//     });

//     // Simple trend (last 10 logs)
//     const recent = logs.slice(0, 10).reverse();
//     const times = recent.map(l => new Date(l.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}));
//     const phishing = recent.map(l => l.label === "Phishing" ? 1 : 0);

//     new Chart(document.getElementById("lineChart"), {
//         type: "line",
//         data: { labels: times, datasets: [{ label: "Phishing Detections", data: phishing.reduce((a,[_,v])=>[...a, (a[a.length-1]||0)+v],[],[]), borderColor: "#e74c3c", tension: 0.3 }] },
//         options: { scales: { y: { beginAtZero: true, max: 1 } } }
//     });
// }



// app/static/script.js - Complete & Professional Dashboard JavaScript


// document.addEventListener("DOMContentLoaded", function () {
//     // ===================================================================
//     // 1. Real-time Email Scanning (Dashboard + Scan Page)
//     // ===================================================================
//     const checkBtn = document.getElementById("checkBtn");
//     const emailInput = document.getElementById("emailInput");
//     const resultBox = document.getElementById("resultBox");

//     if (checkBtn && emailInput && resultBox) {
//         checkBtn.addEventListener("click", async function () {
//             const emailText = emailInput.value.trim();

//             if (!emailText) {
//                 showResult("Please paste an email first!", "warning");
//                 return;
//             }

//             if (emailText.length > 100000) {
//                 showResult("Email too large. Max 100,000 characters.", "warning");
//                 return;
//             }

//             showResult("Scanning email...", "safe");

//             try {
//                 const response = await fetch("/scan", {
//                     method: "POST",
//                     headers: {
//                         "Content-Type": "application/json"
//                     },
//                     body: JSON.stringify({ email_text: emailText })
//                 });

//                 const data = await response.json();

//                 if (response.ok) {
//                     const confidence = data.confidence !== undefined 
//                         ? (data.confidence * 100).toFixed(1) + "%" 
//                         : "N/A";

//                     const message = `
//                         <strong style="font-size: 28px; display: block; margin-bottom: 10px;">
//                             ${data.label}
//                         </strong>
//                         <strong>Confidence:</strong> ${confidence}<br>
//                         <strong>Reason:</strong> ${data.reason || "No specific reason"}
//                         ${data.quarantined ? "<br><br>Email has been <strong>QUARANTINED</strong>" : ""}
//                     `;

//                     showResult(message, 
//                         data.label === "Phishing" ? "phishing" :
//                         data.label === "Suspicious" ? "warning" : "safe"
//                     );

//                     // Auto-refresh dashboard after scan (only on index page)
//                     if (window.location.pathname === "/") {
//                         setTimeout(() => location.reload(), 2500);
//                     }
//                 } else {
//                     showResult(data.error || "Scan failed", "warning");
//                 }
//             } catch (err) {
//                 console.error("Scan error:", err);
//                 showResult("Network error. Please try again.", "warning");
//             }
//         });
//     }

//     // Helper: Show result with proper styling
//     function showResult(html, type) {
//         resultBox.innerHTML = html;
//         resultBox.className = "result"; // Reset classes
//         resultBox.classList.add(type);
//         resultBox.classList.remove("hidden");
//     }

//     // ===================================================================
//     // 2. Initialize Charts (Only on Dashboard)
//     // ===================================================================
//     if (typeof stats !== "undefined" && typeof logs !== "undefined") {
//         initCharts(stats, logs);
//     }
// });











// app/static/script.js - FINAL FIXED VERSION

// Data is injected from Flask in index.html → use global variables
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