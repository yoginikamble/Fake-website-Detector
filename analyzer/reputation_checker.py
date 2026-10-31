"""
Reputation Checker Module.

Provides an optional threat intelligence hook.
- Operates safely offline using local heuristics when external API keys are not provided.
- If configured with an optional threat API (e.g. Google Safe Browsing / VirusTotal via environment variables),
  queries the service with strict timeouts and error isolation.
- Distinguishes clearly between 'Checked', 'Not Configured', and 'Unavailable'.
"""

import requests
from typing import Dict, Any
import config


def check_domain_reputation(hostname: str, full_url: str) -> Dict[str, Any]:
    """
    Evaluates reputation for the domain/URL.
    
    Returns structured dictionary with:
    - is_configured: bool
    - provider: str
    - status: 'checked' | 'not_configured' | 'error'
    - is_malicious: bool or None
    - message: str
    """
    result: Dict[str, Any] = {
        "is_configured": False,
        "provider": config.THREAT_API_PROVIDER or "None",
        "status": "not_configured",
        "is_malicious": None,
        "details": "",
        "checked": False
    }

    api_key = config.THREAT_API_KEY
    provider = (config.THREAT_API_PROVIDER or "").lower()

    if not api_key or provider in ("none", "", "disabled"):
        result["status"] = "not_configured"
        result["details"] = (
            "Optional external threat-intelligence API is not configured. "
            "Analysis relies entirely on transparent, local rule-based security heuristics."
        )
        return result

    result["is_configured"] = True

    # Google Safe Browsing API v4 lookup (if configured)
    if provider == "google_safebrowsing":
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {
                "clientId": "fake-website-detector-tycs",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": full_url}]
            }
        }
        try:
            resp = requests.post(endpoint, json=payload, timeout=3.0)
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                result["checked"] = True
                result["status"] = "checked"
                if matches:
                    result["is_malicious"] = True
                    threat_types = [m.get("threatType") for m in matches]
                    result["details"] = f"Flagged by Google Safe Browsing: {', '.join(threat_types)}"
                else:
                    result["is_malicious"] = False
                    result["details"] = "No threats registered in Google Safe Browsing database."
                return result
            elif resp.status_code == 429:
                result["status"] = "error"
                result["details"] = "Threat intelligence API rate limit exceeded. Falling back to local heuristics."
                return result
            else:
                result["status"] = "error"
                result["details"] = f"Threat intelligence API returned HTTP {resp.status_code}."
                return result
        except Exception as exc:
            result["status"] = "error"
            result["details"] = f"Threat intelligence query failed: {str(exc)}"
            return result

    # Generic or unsupported provider configured
    result["status"] = "not_configured"
    result["details"] = f"Configured provider '{config.THREAT_API_PROVIDER}' is not recognized."
    return result
