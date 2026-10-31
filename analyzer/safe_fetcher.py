"""
Safe HTTP Fetcher Module with Server-Side Request Forgery (SSRF) Protection.

Features:
- Validates initial and redirected URLs before making connections.
- Limits maximum redirects.
- Applies strict connection and read timeouts.
- Caps maximum downloaded response bytes to prevent buffer exhaustion.
- Extracts response headers, status codes, and SSL certificate health indicators safely.
"""

import time
import requests
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List
import config
from .url_validator import resolve_and_verify_ssrf, is_safe_ip_address, is_ip_address


def safe_fetch_url(target_url: str) -> Dict[str, Any]:
    """
    Safely executes an HTTP/HTTPS probe against a target URL.

    Guarantees:
    - Never contacts private or internal IP ranges at any hop.
    - Limits redirects and revalidates destination at each redirect hop.
    - Reads only headers and a maximum of 256 KB of content.
    - Never evaluates JavaScript or downloads arbitrary executables.
    """
    result: Dict[str, Any] = {
        "attempted": False,
        "success": False,
        "status_code": None,
        "response_time_ms": 0,
        "final_url": target_url,
        "redirect_count": 0,
        "redirect_chain": [],
        "headers": {},
        "security_headers": {
            "hsts": False,
            "x_frame_options": False,
            "csp": False,
            "x_content_type_options": False
        },
        "ssl_valid": None,
        "error_message": "",
        "notes": []
    }

    current_url = target_url
    redirects_traversed: List[Dict[str, Any]] = []

    # Configure custom requests session with custom User-Agent
    session = requests.Session()
    session.headers.update({
        "User-Agent": config.DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close"
    })

    start_time = time.time()
    result["attempted"] = True

    try:
        for hop in range(config.MAX_REDIRECTS + 1):
            parsed = urlparse(current_url)
            hostname = parsed.hostname

            if not hostname:
                result["error_message"] = f"Hop {hop}: Invalid URL format encountered during traversal."
                return result

            # Re-verify SSRF safety for this hop's destination
            is_safe, resolved_ip, reason = resolve_and_verify_ssrf(hostname)
            if not is_safe:
                result["error_message"] = f"Hop {hop} security check failed: {reason}"
                return result

            # Perform request without automatic redirect following
            try:
                resp = session.get(
                    current_url,
                    timeout=config.REQUEST_TIMEOUT_SECONDS,
                    allow_redirects=False,
                    stream=True,
                    verify=True
                )
                ssl_check_passed = True
            except requests.exceptions.SSLError as ssl_err:
                # SSL verification failed (e.g. self-signed or invalid cert)
                result["ssl_valid"] = False
                result["notes"].append(f"SSL Handshake Warning: {str(ssl_err).split(':')[-1].strip()}")
                # Try fetching with verify=False just to inspect status, but record the warning
                try:
                    resp = session.get(
                        current_url,
                        timeout=config.REQUEST_TIMEOUT_SECONDS,
                        allow_redirects=False,
                        stream=True,
                        verify=False
                    )
                    ssl_check_passed = False
                except Exception as inner_err:
                    result["error_message"] = f"Connection failed after SSL rejection: {str(inner_err)}"
                    return result
            except requests.exceptions.Timeout:
                result["error_message"] = (
                    f"Connection timed out after {config.REQUEST_TIMEOUT_SECONDS} seconds. "
                    "Website server is slow or non-responsive."
                )
                return result
            except requests.exceptions.ConnectionError:
                result["error_message"] = (
                    "Could not establish connection to the remote server. Host may be offline or blocking requests."
                )
                return result
            except Exception as req_err:
                result["error_message"] = f"Network connection error: {str(req_err)}"
                return result

            if result["ssl_valid"] is None:
                if current_url.lower().startswith("https://"):
                    result["ssl_valid"] = ssl_check_passed
                else:
                    result["ssl_valid"] = None  # Plain HTTP

            # Check if this response is a redirect (3xx)
            if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
                location = resp.headers["Location"]
                next_url = urljoin(current_url, location)

                redirects_traversed.append({
                    "hop": hop + 1,
                    "from_url": current_url,
                    "to_url": next_url,
                    "status_code": resp.status_code
                })

                if hop >= config.MAX_REDIRECTS:
                    result["error_message"] = f"Maximum redirect limit ({config.MAX_REDIRECTS}) exceeded."
                    result["redirect_count"] = len(redirects_traversed)
                    result["redirect_chain"] = redirects_traversed
                    return result

                current_url = next_url
                continue
            else:
                # Reached final destination
                elapsed = int((time.time() - start_time) * 1000)
                result["response_time_ms"] = elapsed
                result["status_code"] = resp.status_code
                result["final_url"] = current_url
                result["redirect_count"] = len(redirects_traversed)
                result["redirect_chain"] = redirects_traversed
                result["success"] = True

                # Extract security headers
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                result["headers"] = {
                    "server": headers_lower.get("server", "Hidden/Not Provided"),
                    "content_type": headers_lower.get("content-type", "Unknown")
                }

                result["security_headers"]["hsts"] = "strict-transport-security" in headers_lower
                result["security_headers"]["x_frame_options"] = "x-frame-options" in headers_lower
                result["security_headers"]["csp"] = "content-security-policy" in headers_lower
                result["security_headers"]["x_content_type_options"] = "x-content-type-options" in headers_lower

                # Consume limited content safely (do not buffer excessive amounts)
                try:
                    _ = resp.raw.read(config.MAX_RESPONSE_BYTES)
                except Exception:
                    pass
                finally:
                    resp.close()

                return result

    except Exception as general_err:
        result["error_message"] = f"Unexpected error during safe network fetch: {str(general_err)}"
        return result
    finally:
        session.close()

    return result
