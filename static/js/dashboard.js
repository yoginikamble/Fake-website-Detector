/**
 * Security Dashboard Chart.js Integration
 * Fake Website Detector Using Web Security Analysis (TYCS Project)
 */

document.addEventListener("DOMContentLoaded", function () {
  const chartCanvas = document.getElementById("riskDistributionChart");
  if (!chartCanvas) return;

  // Retrieve metrics from canvas data attributes
  const lowCount = parseInt(chartCanvas.getAttribute("data-low") || "0", 10);
  const medCount = parseInt(chartCanvas.getAttribute("data-medium") || "0", 10);
  const highCount = parseInt(chartCanvas.getAttribute("data-high") || "0", 10);
  const totalCount = lowCount + medCount + highCount;

  const emptyPlaceholder = document.getElementById("emptyChartPlaceholder");

  if (totalCount === 0) {
    chartCanvas.style.display = "none";
    if (emptyPlaceholder) emptyPlaceholder.style.display = "block";
    return;
  }

  const ctx = chartCanvas.getContext("2d");

  // Create Modern Cybersecurity Doughnut Chart
  new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: [
        `Low Risk (${lowCount})`,
        `Medium Risk (${medCount})`,
        `High Risk (${highCount})`
      ],
      datasets: [
        {
          data: [lowCount, medCount, highCount],
          backgroundColor: [
            "rgba(16, 185, 129, 0.85)",  // Emerald Low
            "rgba(245, 158, 11, 0.85)",  // Amber Medium
            "rgba(239, 68, 68, 0.85)"    // Crimson High
          ],
          borderColor: [
            "#10b981",
            "#f59e0b",
            "#ef4444"
          ],
          borderWidth: 2,
          hoverOffset: 6
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: "#94a3b8",
            font: {
              family: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
              size: 12
            },
            padding: 16
          }
        },
        tooltip: {
          backgroundColor: "rgba(15, 23, 42, 0.95)",
          titleColor: "#ffffff",
          bodyColor: "#00e5ff",
          borderColor: "#1e2f55",
          borderWidth: 1,
          padding: 12,
          boxPadding: 6,
          callbacks: {
            label: function (context) {
              const val = context.raw || 0;
              const pct = totalCount > 0 ? Math.round((val / totalCount) * 100) : 0;
              return ` ${context.label}: ${val} scans (${pct}%)`;
            }
          }
        }
      },
      cutout: "68%"
    }
  });
});
