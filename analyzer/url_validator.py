"""
URL Validation and SSRF Protection Module.

Validates URL syntax, protocol schemes, hostnames, and verifies that the destination
does not target local, private, or reserved internal network addresses (SSRF Protection).
"""

import re
import socket
import ipaddress
from urllib.parse import urlparse, urlunparse
from typing import Tuple, Optional, Dict, Any


# Standard allowed schemes
ALLOWED_SCHEMES = {"http", "https"}

# Regex for basic domain label validation (RFC 1035 / RFC 1123)
DOMAIN_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")


def normalize_url(raw_url: str) -> str:
    """
    Cleans and standardizes the user-provided URL.
    - Trims whitespace.
    - If scheme is missing, prepends 'https://' for safe default analysis.
    - Converts host to lowercase.
    """
    if not raw_url:
        return ""
    
    url = raw_url.strip()
    
    # If the user typed something like "example.com" or "www.example.com/login"
    # without a scheme, assume https:// for user convenience
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*:", url) or re.match(r"^[a-zA-Z0-9.\-]+:[0-9]+(/|$)", url):
            url = "https://" + url
        
    try:
        parsed = urlparse(url)
        # Normalize hostname to lowercase
        hostname = (parsed.hostname or "").lower()
        try:
            port_num = parsed.port
            port = f":{port_num}" if port_num and port_num not in (80, 443) else ""
        except ValueError:
            port = ""
    except Exception:
        return url
    
    netloc = f"{hostname}{port}"
    if parsed.username or parsed.password:
        auth = parsed.username or ""
        if parsed.password:
            auth += f":{parsed.password}"
        netloc = f"{auth}@{netloc}"
        
    normalized = urlunparse((
        parsed.scheme.lower(),
        netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        parsed.fragment
    ))
    return normalized


def is_ip_address(host: str) -> bool:
    """Checks whether the given string is a valid IPv4 or IPv6 address."""
    if not host:
        return False
    # Strip brackets from IPv6 hostnames like [::1]
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def is_safe_ip_address(ip_str: str) -> Tuple[bool, str]:
    """
    Evaluates whether an IP address is safe to query over the public Internet.
    Blocks private networks, localhost, link-local, multicast, and reserved ranges to prevent SSRF.
    """
    try:
        clean_ip = ip_str.strip("[]")
        ip = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False, f"Invalid IP address format: '{ip_str}'"

    # Block Loopback (127.0.0.0/8, ::1)
    if ip.is_loopback:
        return False, "Destination is a loopback address (SSRF blocked: localhost)"

    # Block Link-local (169.254.0.0/16, fe80::/10) - Check before is_private
    if ip.is_link_local:
        return False, "Destination is a link-local address (SSRF blocked: APIPA/Cloud Metadata)"

    # Block Private RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    if ip.is_private:
        return False, "Destination is a private internal network address (SSRF blocked: RFC1918)"

    # Block Multicast (224.0.0.0/4, ff00::/8)
    if ip.is_multicast:
        return False, "Destination is a multicast IP address (SSRF blocked)"

    # Block Reserved (240.0.0.0/4, etc.)
    if ip.is_reserved:
        return False, "Destination is in a reserved IP block (SSRF blocked)"

    # Block Unspecified (0.0.0.0, ::)
    if ip.is_unspecified:
        return False, "Destination is an unspecified IP address (SSRF blocked: 0.0.0.0)"

    # Additional Carrier Grade NAT (100.64.0.0/10) check for IPv4
    if isinstance(ip, ipaddress.IPv4Address):
        cgnat = ipaddress.IPv4Network("100.64.0.0/10")
        if ip in cgnat:
            return False, "Destination is within Carrier Grade NAT address space (SSRF blocked)"

    return True, "Safe public IP address"


def resolve_and_verify_ssrf(hostname: str) -> Tuple[bool, Optional[str], str]:
    """
    Performs DNS resolution on a domain name and verifies that all resolved IP addresses
    belong to public address space. Prevents DNS rebinding and internal network scanning.

    Returns:
        (is_safe, resolved_primary_ip, explanation_message)
    """
    if not hostname:
        return False, None, "Hostname is empty or undefined"

    # Known internal keywords
    lower_host = hostname.lower()
    if lower_host in {"localhost", "localhost.localdomain", "broadcasthost", "ip6-localhost"}:
        return False, None, "Localhost names are prohibited for security reasons (SSRF Protection)"

    if lower_host.endswith((".local", ".internal", ".lan", ".home", ".corp", ".test")):
        return False, None, "Internal top-level domain names are prohibited (SSRF Protection)"

    # If the host is already an IP address
    if is_ip_address(hostname):
        safe, reason = is_safe_ip_address(hostname)
        return safe, hostname, reason

    # Perform DNS lookup
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return True, None, "DNS resolution yielded no address records"

        resolved_ips = []
        for item in addr_info:
            ip = item[4][0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)

        # Check every resolved IP for SSRF safety
        for ip in resolved_ips:
            safe, reason = is_safe_ip_address(ip)
            if not safe:
                return False, ip, f"Resolved IP {ip} rejected: {reason}"

        primary_ip = resolved_ips[0] if resolved_ips else None
        return True, primary_ip, f"Domain resolved successfully to public IP: {primary_ip}"

    except socket.gaierror:
        # Domain cannot be resolved in DNS (could be non-existent or DNS server down)
        # We allow static analysis to continue, but mark live checks as unavailable
        return True, None, "Domain name could not be resolved via DNS (Host not found or offline)"
    except Exception as exc:
        return True, None, f"DNS verification warning: {str(exc)}"


def validate_url(raw_url: str) -> Dict[str, Any]:
    """
    Comprehensive URL validation function.

    Checks:
    1. Non-empty string.
    2. Length sanity (<= 2048 chars).
    3. Proper URL syntax and scheme (only http and https permitted).
    4. Valid hostname.
    5. SSRF validation on resolved IPs.

    Returns dictionary with validation status and structured details.
    """
    result = {
        "is_valid": False,
        "is_safe_ssrf": False,
        "error_message": "",
        "raw_url": raw_url,
        "normalized_url": "",
        "scheme": "",
        "hostname": "",
        "port": None,
        "path": "",
        "query": "",
        "resolved_ip": None,
        "dns_message": ""
    }

    if not raw_url or not raw_url.strip():
        result["error_message"] = "URL input cannot be empty. Please enter a valid website address."
        return result

    raw_clean = raw_url.strip()

    if len(raw_clean) > 2048:
        result["error_message"] = "URL exceeds the maximum permissible length of 2048 characters."
        return result

    # Check for unsupported schemes like ftp://, file://, javascript:, data:
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+\-.]*):", raw_clean)
    if scheme_match:
        found_scheme = scheme_match.group(1).lower()
        if found_scheme not in ALLOWED_SCHEMES and not re.match(r"^[a-zA-Z0-9.\-]+:[0-9]+(/|$)", raw_clean):
            result["scheme"] = found_scheme
            result["error_message"] = (
                f"Unsupported URL scheme '{found_scheme}://'. "
                f"Only standard web protocols ('http://' and 'https://') are permitted."
            )
            return result

    normalized = normalize_url(raw_clean)
    result["normalized_url"] = normalized

    try:
        parsed = urlparse(normalized)
    except Exception as exc:
        result["error_message"] = f"Malformed URL syntax: {str(exc)}"
        return result

    # Validate scheme
    scheme = parsed.scheme.lower()
    result["scheme"] = scheme
    if scheme not in ALLOWED_SCHEMES:
        result["error_message"] = (
            f"Unsupported URL scheme '{scheme}://'. "
            f"Only standard web protocols ('http://' and 'https://') are permitted."
        )
        return result

    # Validate hostname existence
    hostname = parsed.hostname
    if not hostname:
        result["error_message"] = "Invalid URL: Missing hostname or domain name."
        return result

    result["hostname"] = hostname.lower()
    result["port"] = parsed.port
    result["path"] = parsed.path or "/"
    result["query"] = parsed.query

    # Validate hostname syntax
    if is_ip_address(hostname):
        safe_ip, ip_reason = is_safe_ip_address(hostname)
        if not safe_ip:
            result["error_message"] = f"Security Violation: {ip_reason}"
            return result
        result["is_safe_ssrf"] = True
        result["resolved_ip"] = hostname
        result["dns_message"] = "Direct public IP address supplied"
    else:
        # Validate domain label lengths and characters
        labels = hostname.split(".")
        if len(labels) < 2 and hostname != "localhost":
            result["error_message"] = (
                f"Invalid domain format '{hostname}'. A top-level domain (e.g., .com, .org) is required."
            )
            return result

        # Check total domain length
        if len(hostname) > 253:
            result["error_message"] = "Domain name exceeds maximum permitted length of 253 characters."
            return result

        for label in labels:
            if not label:
                result["error_message"] = "Invalid domain name: Contains consecutive or trailing dots."
                return result
            if len(label) > 63:
                result["error_message"] = f"Domain label '{label}' exceeds maximum permitted length of 63 characters."
                return result
            # Punycode labels start with xn--
            if not DOMAIN_LABEL_REGEX.match(label):
                result["error_message"] = f"Domain label '{label}' contains illegal characters."
                return result

        # SSRF and DNS check
        is_safe, resolved_ip, dns_msg = resolve_and_verify_ssrf(hostname)
        result["resolved_ip"] = resolved_ip
        result["dns_message"] = dns_msg

        if not is_safe:
            result["error_message"] = f"Security Alert: {dns_msg}"
            return result

        result["is_safe_ssrf"] = True

    result["is_valid"] = True
    return result
