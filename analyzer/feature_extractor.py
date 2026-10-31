"""
Feature Extractor Module.

Extracts lexical, structural, protocol, typosquatting, brand impersonation,
and network features from a validated URL.
Distinguishes between checked indicators, indicators that could not be checked,
and not-applicable checks.
"""

from urllib.parse import urlparse
import re
from typing import Dict, Any, List
import config
from .url_validator import is_ip_address


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes the Levenshtein edit distance between two strings."""
    if s1 == s2:
        return 0
    if len(s1) == 0:
        return len(s2)
    if len(s2) == 0:
        return len(s1)

    v0 = list(range(len(s2) + 1))
    v1 = [0] * (len(s2) + 1)

    for i in range(len(s1)):
        v1[0] = i + 1
        for j in range(len(s2)):
            cost = 0 if s1[i] == s2[j] else 1
            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
        v0 = list(v1)

    return v0[len(s2)]


def check_typosquatting(hostname: str) -> Dict[str, Any]:
    """
    Evaluates whether the hostname is a lookalike / typosquatting impersonation
    of a major trusted brand using character substitution (leetspeak), edit distance,
    or combosquatting.
    """
    clean_host = hostname.lower()
    if clean_host.startswith("www."):
        clean_host = clean_host[4:]

    # Split into domain labels, discarding top-level domains like .com, .org, .xyz
    labels = [p for p in clean_host.split(".") if p]
    if len(labels) >= 2:
        domain_labels = labels[:-1]  # Check SLD and subdomains
    else:
        domain_labels = labels

    for label in domain_labels:
        # 1. Leetspeak substitution check (e.g., 'go0gle' -> 'google', 'paypa1' -> 'paypal')
        deleet = "".join(config.LEET_CHAR_MAP.get(c, c) for c in label)
        has_digits_substituted = any(c in config.LEET_CHAR_MAP for c in label)

        if has_digits_substituted and deleet in config.POPULAR_BRANDS and label not in config.POPULAR_BRANDS:
            return {
                "is_detected": True,
                "target_brand": deleet,
                "technique": "Leetspeak Homoglyph Substitution",
                "label_analyzed": label,
                "description": f"Domain label '{label}' mimics legitimate brand '{deleet}' using number/character substitutions ('{label}' -> '{deleet}')."
            }

        # 2. Levenshtein edit distance check (1 or 2 edits away from popular brand)
        for brand in config.POPULAR_BRANDS:
            # Skip if this label IS the actual authentic brand
            if label == brand:
                continue

            dist = levenshtein_distance(label, brand)
            dist_deleet = levenshtein_distance(deleet, brand)
            min_dist = min(dist, dist_deleet)

            # High confidence: 1 character difference on brands of length >= 4
            if min_dist == 1 and len(brand) >= 4:
                return {
                    "is_detected": True,
                    "target_brand": brand,
                    "technique": "Typosquatting Edit Distance (1 character difference)",
                    "label_analyzed": label,
                    "description": f"Domain label '{label}' is a deceptive 1-character typosquatting lookalike of legitimate brand '{brand}'."
                }

            # Moderate confidence: 2 character difference on brands of length >= 6
            if min_dist == 2 and len(brand) >= 6 and (has_digits_substituted or "-" in label):
                return {
                    "is_detected": True,
                    "target_brand": brand,
                    "technique": "Typosquatting Edit Distance (2 character difference)",
                    "label_analyzed": label,
                    "description": f"Domain label '{label}' is visually similar to brand '{brand}'."
                }

            # 3. Combosquatting: brand combined with sensitive keywords (e.g., 'google-security', 'paypal-login')
            if brand in label and label != brand:
                sensitive_affixes = ["login", "verify", "security", "update", "account", "support", "auth", "secure", "signin"]
                if any(aff in label for aff in sensitive_affixes):
                    return {
                        "is_detected": True,
                        "target_brand": brand,
                        "technique": "Combosquatting (Brand + Action Keyword)",
                        "label_analyzed": label,
                        "description": f"Domain label '{label}' illicitly pairs legitimate brand '{brand}' with security action keywords."
                    }

    return {
        "is_detected": False,
        "target_brand": None,
        "technique": None,
        "label_analyzed": None,
        "description": "Standard domain naming without brand impersonation homoglyphs."
    }


def extract_url_features(normalized_url: str, fetch_result: Dict[str, Any] = None, val_result: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Extracts security indicator features from the given normalized URL and network probe result.
    """
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = normalized_url

    features: Dict[str, Any] = {}

    # 1. URL Length Analysis
    url_len = len(full_url)
    features["url_length"] = {
        "value": url_len,
        "is_excessive": url_len > 75,
        "is_medium": 54 <= url_len <= 75,
        "is_short": url_len < 54,
        "description": f"URL length is {url_len} characters."
    }

    # 2. Direct IP Address Hostname
    is_ip = is_ip_address(hostname)
    features["ip_address_host"] = {
        "is_detected": is_ip,
        "value": hostname if is_ip else None,
        "description": "Direct IP address used instead of a domain name." if is_ip else "Domain name used (not a raw IP address)."
    }

    # 3. Suspicious URL Characters
    has_at = "@" in full_url
    has_double_slash_path = "//" in path
    hyphen_count = hostname.count("-")
    percent_count = full_url.count("%")

    features["suspicious_characters"] = {
        "has_at_symbol": has_at,
        "has_double_slash_path": has_double_slash_path,
        "hyphen_count": hyphen_count,
        "excessive_hyphens": hyphen_count >= 2,
        "percent_count": percent_count,
        "excessive_percents": percent_count >= 3,
        "description": (
            "Detected obfuscation characters in URL structure."
            if (has_at or has_double_slash_path or hyphen_count >= 2 or percent_count >= 3)
            else "Clean character distribution with no suspicious obfuscation symbols."
        )
    }

    # 4. Subdomain Count Analysis
    clean_host = hostname
    if clean_host.startswith("www."):
        clean_host = clean_host[4:]
    
    domain_parts = [p for p in clean_host.split(".") if p]
    subdomain_count = max(0, len(domain_parts) - 2)
    features["subdomains"] = {
        "count": subdomain_count,
        "total_labels": len(domain_parts),
        "is_excessive": subdomain_count >= 2,
        "description": (
            f"Detected {subdomain_count} subdomain level(s). High subdomain count often indicates host masking."
            if subdomain_count >= 2
            else f"Normal subdomain depth ({subdomain_count} subdomain(s))."
        )
    }

    # 5. Punycode / IDN Homograph Indicator
    is_punycode = "xn--" in hostname
    features["punycode"] = {
        "is_detected": is_punycode,
        "description": (
            "Punycode (xn--) detected. May represent an Internationalized Domain Name (IDN) homograph attack."
            if is_punycode
            else "Standard ASCII character domain (no punycode detected)."
        )
    }

    # 6. Brand Impersonation & Typosquatting (e.g. go0gle.com, paypa1.com, amaz0n.com)
    typo_check = check_typosquatting(hostname)
    features["typosquatting"] = typo_check

    # 7. URL Shortener Service Identification
    is_shortener = hostname in config.SHORTENER_DOMAINS or any(hostname.endswith("." + d) for d in config.SHORTENER_DOMAINS)
    features["url_shortener"] = {
        "is_detected": is_shortener,
        "description": (
            f"URL utilizes a known shortener service ({hostname}), hiding the true destination."
            if is_shortener
            else "URL does not belong to known public URL shortener services."
        )
    }

    # 8. Sensitive Keywords in Domain or Path
    url_lower = full_url.lower()
    matched_keywords = [kw for kw in config.SUSPICIOUS_KEYWORDS if kw in url_lower]
    features["sensitive_keywords"] = {
        "is_detected": len(matched_keywords) > 0,
        "matched": matched_keywords,
        "description": (
            f"Security-sensitive keywords found in URL: {', '.join(matched_keywords[:4])}."
            if matched_keywords
            else "No suspicious security-sensitive keywords observed in URL path."
        )
    }

    # 9. Protocol & Port Analysis
    is_https = parsed.scheme.lower() == "https"
    port = parsed.port
    is_standard_port = port is None or (is_https and port == 443) or (not is_https and port == 80)
    features["protocol_and_port"] = {
        "is_https": is_https,
        "port": port or (443 if is_https else 80),
        "is_standard_port": is_standard_port,
        "description": (
            "Encrypted HTTPS protocol on standard port."
            if (is_https and is_standard_port)
            else (
                "Unencrypted HTTP protocol in use."
                if not is_https
                else f"Non-standard port ({port}) specified in URL."
            )
        )
    }

    # 10. Top-Level Domain (TLD) Analysis
    tld = "." + hostname.split(".")[-1] if "." in hostname else ""
    is_suspicious_tld = tld in config.SUSPICIOUS_TLDS
    features["tld_analysis"] = {
        "tld": tld,
        "is_suspicious": is_suspicious_tld,
        "description": (
            f"Top-level domain '{tld}' is in the high-abuse / high-risk TLD list."
            if is_suspicious_tld
            else f"Top-level domain '{tld}' has standard operational reputation."
        )
    }

    # 11. DNS Reachability & Resolution Analysis
    dns_failed = False
    if val_result and val_result.get("resolved_ip") is None and "could not be resolved" in val_result.get("dns_message", "").lower():
        dns_failed = True
    elif fetch_result:
        err_msg = fetch_result.get("error_message", "").lower()
        if (
            "could not be resolved" in err_msg
            or "host not found" in err_msg
            or "name or service not known" in err_msg
            or "host may be offline" in err_msg
            or (fetch_result.get("attempted") and not fetch_result.get("success") and fetch_result.get("status_code") is None)
        ):
            dns_failed = True

    features["dns_reachability"] = {
        "dns_failed": dns_failed,
        "description": (
            "Domain could not be resolved via public DNS records (Host not found / unregistered ghost domain)."
            if dns_failed
            else "Domain passed public DNS resolution."
        )
    }

    # 12. Live Network Probe Features (if fetch was executed)
    if fetch_result and fetch_result.get("attempted"):
        features["live_fetch"] = {
            "completed": fetch_result.get("success", False),
            "status_code": fetch_result.get("status_code"),
            "response_time_ms": fetch_result.get("response_time_ms", 0),
            "redirect_count": fetch_result.get("redirect_count", 0),
            "final_url": fetch_result.get("final_url", normalized_url),
            "ssl_valid": fetch_result.get("ssl_valid"),
            "security_headers": fetch_result.get("security_headers", {}),
            "notes": fetch_result.get("notes", []),
            "error_message": fetch_result.get("error_message", "")
        }

        # Check redirect divergence (if final domain is different from initial domain)
        initial_host = hostname
        final_parsed = urlparse(fetch_result.get("final_url", normalized_url))
        final_host = (final_parsed.hostname or "").lower()
        diverged = (initial_host != final_host) and (not final_host.endswith("." + initial_host)) and (not initial_host.endswith("." + final_host))

        features["redirect_analysis"] = {
            "redirect_count": fetch_result.get("redirect_count", 0),
            "has_diverged_domain": diverged,
            "final_hostname": final_host,
            "description": (
                f"Redirected to a different external domain: {final_host}."
                if diverged
                else f"Redirect chain stayed within target host ({fetch_result.get('redirect_count', 0)} hop(s))."
            )
        }
    else:
        features["live_fetch"] = {
            "completed": False,
            "status_code": None,
            "error_message": "Live network checks could not be completed or were skipped."
        }
        features["redirect_analysis"] = {
            "redirect_count": 0,
            "has_diverged_domain": False,
            "final_hostname": hostname,
            "description": "Live redirect verification unavailable."
        }

    return features
