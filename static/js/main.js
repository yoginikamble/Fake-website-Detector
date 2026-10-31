/**
 * Main Frontend Interactivity Script
 * Fake Website Detector Using Web Security Analysis (TYCS Project)
 */

document.addEventListener("DOMContentLoaded", function () {
  // 1. Quick Example Pill Population
  const samplePills = document.querySelectorAll(".pill-cyber");
  const scanInput = document.getElementById("urlInput");

  if (samplePills.length > 0 && scanInput) {
    samplePills.forEach(function (pill) {
      pill.addEventListener("click", function (e) {
        e.preventDefault();
        const urlToUse = this.getAttribute("data-url");
        if (urlToUse) {
          scanInput.value = urlToUse;
          scanInput.focus();
        }
      });
    });
  }

  // 2. Loading Overlay on Scan Submission
  const scanForm = document.getElementById("scanForm");
  const loadingOverlay = document.getElementById("loadingOverlay");
  const loadingSubtext = document.getElementById("loadingSubtext");

  if (scanForm && loadingOverlay) {
    scanForm.addEventListener("submit", function (e) {
      const urlVal = scanInput ? scanInput.value.trim() : "";
      if (!urlVal) {
        return; // Let standard HTML5 validation handle empty
      }

      // Display radar spinner overlay
      loadingOverlay.style.display = "flex";

      // Animated security scanning steps
      const steps = [
        "Verifying URL syntax & protocol schemes...",
        "Evaluating SSRF defenses & public DNS resolution...",
        "Executing safe HTTP probe & SSL handshake...",
        "Extracting lexical, structural, and TLD indicators...",
        "Computing transparent weighted risk score..."
      ];

      let stepIndex = 0;
      const interval = setInterval(function () {
        stepIndex++;
        if (stepIndex < steps.length && loadingSubtext) {
          loadingSubtext.textContent = steps[stepIndex];
        } else {
          clearInterval(interval);
        }
      }, 700);
    });
  }

  // 3. Auto-dismiss Alert Banners after 6 seconds
  const flashAlerts = document.querySelectorAll(".alert-dismissible");
  flashAlerts.forEach(function (alert) {
    setTimeout(function () {
      try {
        const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
        if (bsAlert) {
          bsAlert.close();
        }
      } catch (err) {
        // Fallback fade out
        alert.style.opacity = "0";
        setTimeout(() => alert.remove(), 400);
      }
    }, 6000);
  });
});
