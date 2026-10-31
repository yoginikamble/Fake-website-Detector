"""
Risk Scoring System Module.

Calculates an explainable risk score (0-100) based on detected security indicators.
Categorizes scores:
  - 0-29: Low Risk Indicators
  - 30-59: Medium Risk Indicators
  - 60-100: High Risk Indicators

Generates detailed positive and negative findings, uncompleted checks, and actionable advice.
"""

from typing import Dict, Any, List
import config


def calculate_risk_score(features: Dict[str, Any], reputation: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Computes a transparent, weighted risk score and produces an itemized breakdown.
    """
    points = 0
    negative_findings: List[Dict[str, Any]] = []
    positive_findings: List[Dict[str, Any]] = []
    checks_uncompleted: List[Dict[str, Any]] = []
    recommendations: List[str] = []

    # 1. Direct IP Address Hostname
    ip_feat = features.get("ip_address_host", {})
    if ip_feat.get("is_detected"):
        w = config.WEIGHTS.get("ip_address_host", 25)
        points += w
        negative_findings.append({
            "indicator": "Direct IP Address in Hostname",
            "points": w,
            "severity": "high",
            "category": "Host Architecture",
            "description": f"Target uses raw IP address '{ip_feat.get('value')}' instead of a verified domain name."
        })
        recommendations.append("Legitimate organizations rarely use raw IP addresses for public user services. Exercise caution.")
    else:
        positive_findings.append({
            "indicator": "Domain Name Employed",
            "description": "Target uses a named host rather than a raw IP address."
        })

    # 2. Punycode / IDN Homograph
    puny_feat = features.get("punycode", {})
    if puny_feat.get("is_detected"):
        w = config.WEIGHTS.get("punycode_domain", 22)
        points += w
        negative_findings.append({
            "indicator": "Punycode (xn--) Domain Detected",
            "points": w,
            "severity": "high",
            "category": "Domain Authenticity",
            "description": "Host contains internationalized punycode ('xn--'), which can mimic authentic brand spellings."
        })
        recommendations.append("Verify the exact Unicode characters in the domain name to guard against homograph visual deception.")
    else:
        positive_findings.append({
            "indicator": "Standard Character Set",
            "description": "Domain name uses standard ASCII characters with no punycode prefix."
        })

    # 3. Brand Impersonation & Typosquatting (e.g. go0gle, paypa1, amaz0n)
    typo_feat = features.get("typosquatting", {})
    if typo_feat.get("is_detected"):
        w = config.WEIGHTS.get("brand_typosquatting", 45)
        points += w
        target = typo_feat.get("target_brand", "popular brand")
        negative_findings.append({
            "indicator": f"Brand Typosquatting (Mimics '{target}')",
            "points": w,
            "severity": "high",
            "category": "Brand Impersonation",
            "description": typo_feat.get("description")
        })
        recommendations.append(f"CRITICAL WARNING: This URL mimics legitimate brand '{target}'. Do not enter passwords or credentials. Navigate directly to the official '{target}.com' website.")
    else:
        positive_findings.append({
            "indicator": "No Brand Typosquatting Detected",
            "description": "Domain does not mimic popular trusted brand names using character substitutions."
        })

    # 4. DNS Reachability & Existence
    dns_feat = features.get("dns_reachability", {})
    if dns_feat.get("dns_failed"):
        w = config.WEIGHTS.get("dns_resolution_failed", 25)
        points += w
        negative_findings.append({
            "indicator": "Unresolvable Host / NXDOMAIN",
            "points": w,
            "severity": "medium",
            "category": "DNS Verification",
            "description": dns_feat.get("description")
        })
        recommendations.append("Domain cannot be contacted or resolved via DNS records. Verify domain spelling before proceeding.")
    else:
        positive_findings.append({
            "indicator": "Active Public DNS Resolution",
            "description": "Domain successfully resolved to active public network infrastructure."
        })

    # 3. URL Shortener Service
    short_feat = features.get("url_shortener", {})
    if short_feat.get("is_detected"):
        w = config.WEIGHTS.get("url_shortener", 16)
        points += w
        negative_findings.append({
            "indicator": "Known URL Shortener Service",
            "points": w,
            "severity": "medium",
            "category": "Destination Concealment",
            "description": "URL employs a public link shortener that masks the real destination website."
        })
        recommendations.append("Expand and inspect shortened links using an unshortener before entering credentials.")
    else:
        positive_findings.append({
            "indicator": "Direct Destination URL",
            "description": "Destination is not obscured by common public link shortening services."
        })

    # 4. Suspicious Characters in URL
    char_feat = features.get("suspicious_characters", {})
    if char_feat.get("has_at_symbol"):
        w = config.WEIGHTS.get("at_symbol", 25)
        points += w
        negative_findings.append({
            "indicator": "'@' Character in URL",
            "points": w,
            "severity": "high",
            "category": "URL Obfuscation",
            "description": "The '@' character instructs browsers to ignore preceding text as authentication, misleading users."
        })
        recommendations.append("Inspect the actual destination server following the '@' sign.")

    if char_feat.get("has_double_slash_path"):
        w = config.WEIGHTS.get("double_slash_path", 15)
        points += w
        negative_findings.append({
            "indicator": "Double Slash in Path ('//')",
            "points": w,
            "severity": "medium",
            "category": "URL Path Obfuscation",
            "description": "Double slash in path can be used for open redirection or path traversal evasion."
        })

    if char_feat.get("excessive_hyphens"):
        w = config.WEIGHTS.get("excessive_hyphens", 16)
        points += w
        negative_findings.append({
            "indicator": f"Excessive Hyphens in Domain ({char_feat.get('hyphen_count')} hyphens)",
            "points": w,
            "severity": "medium",
            "category": "Domain Syntax",
            "description": "Attackers frequently chain brand names with multiple hyphens (e.g. 'paypal-update-account.com')."
        })
        recommendations.append("Confirm the official website name of the entity being contacted.")

    # 5. Subdomain Count
    sub_feat = features.get("subdomains", {})
    if sub_feat.get("is_excessive"):
        w = config.WEIGHTS.get("excessive_subdomains", 18)
        points += w
        negative_findings.append({
            "indicator": f"High Subdomain Hierarchy ({sub_feat.get('count')} subdomains)",
            "points": w,
            "severity": "medium",
            "category": "DNS Hierarchy",
            "description": "Multiple subdomains are frequently used to embed authentic brand names on third-party hosting."
        })
        recommendations.append("Examine the root domain name (the last two parts before the TLD) rather than initial subdomains.")
    else:
        positive_findings.append({
            "indicator": "Normal Subdomain Depth",
            "description": f"Domain exhibits a normal, clean subdomain hierarchy ({sub_feat.get('count', 0)} subdomain level)."
        })

    # 6. Sensitive Keywords in URL
    kw_feat = features.get("sensitive_keywords", {})
    if kw_feat.get("is_detected"):
        w = config.WEIGHTS.get("sensitive_keywords", 18)
        points += w
        negative_findings.append({
            "indicator": "Security-Sensitive Keywords Present",
            "points": w,
            "severity": "medium",
            "category": "Lexical Pattern",
            "description": f"Contains security-sensitive terminology: {', '.join(kw_feat.get('matched', [])[:4])}."
        })
        recommendations.append("If this page asks for passwords or payment details, verify the domain through an independent bookmark.")

    # 7. URL Length
    len_feat = features.get("url_length", {})
    if len_feat.get("is_excessive"):
        w = config.WEIGHTS.get("excessive_url_length", 15)
        points += w
        negative_findings.append({
            "indicator": f"Excessive URL Length ({len_feat.get('value')} chars)",
            "points": w,
            "severity": "low",
            "category": "URL Structure",
            "description": "Exceptionally long URLs (>75 chars) are often used to conceal target parameters or payloads."
        })
    elif len_feat.get("is_medium"):
        w = config.WEIGHTS.get("medium_url_length", 8)
        points += w
        negative_findings.append({
            "indicator": f"Moderate URL Length ({len_feat.get('value')} chars)",
            "points": w,
            "severity": "low",
            "category": "URL Structure",
            "description": "URL length is slightly elevated (54-75 characters)."
        })
    else:
        positive_findings.append({
            "indicator": "Concise URL Length",
            "description": f"URL length is compact ({len_feat.get('value', 0)} characters), reducing obfuscation risk."
        })

    # 8. Protocol & Port
    proto_feat = features.get("protocol_and_port", {})
    if not proto_feat.get("is_https"):
        w = config.WEIGHTS.get("insecure_http", 15)
        points += w
        negative_findings.append({
            "indicator": "Unencrypted HTTP Protocol",
            "points": w,
            "severity": "medium",
            "category": "Transport Security",
            "description": "The URL uses plain 'http://'. Network traffic is unencrypted and vulnerable to interception."
        })
        recommendations.append("Never submit passwords, personal data, or credit card numbers on unencrypted HTTP pages.")
    else:
        if not dns_feat.get("dns_failed"):
            positive_findings.append({
                "indicator": "HTTPS Transport Protocol",
                "description": "The URL specifies encrypted HTTPS communication."
            })
        else:
            checks_uncompleted.append({
                "check": "Live SSL/TLS Handshake Verification",
                "reason": "Host could not be contacted via DNS to verify SSL certificate."
            })

    if not proto_feat.get("is_standard_port"):
        w = config.WEIGHTS.get("non_standard_port", 18)
        points += w
        negative_findings.append({
            "indicator": f"Non-Standard Port ({proto_feat.get('port')})",
            "points": w,
            "severity": "medium",
            "category": "Network Port",
            "description": f"Service runs on unusual port {proto_feat.get('port')} instead of standard 80 or 443."
        })

    # 9. TLD Risk
    tld_feat = features.get("tld_analysis", {})
    if tld_feat.get("is_suspicious"):
        w = config.WEIGHTS.get("suspicious_tld", 16)
        points += w
        negative_findings.append({
            "indicator": f"High-Abuse Top Level Domain ({tld_feat.get('tld')})",
            "points": w,
            "severity": "medium",
            "category": "Domain Extension",
            "description": f"Top level domain '{tld_feat.get('tld')}' is frequently associated with disposable phishing sites."
        })
    else:
        positive_findings.append({
            "indicator": "Standard Top Level Domain",
            "description": f"Domain uses a reputable extension ({tld_feat.get('tld') or '.standard'})."
        })

    # 10. Live Network Probe Findings
    live_feat = features.get("live_fetch", {})
    if live_feat.get("completed"):
        # SSL Check
        if live_feat.get("ssl_valid") is False:
            w = config.WEIGHTS.get("ssl_error", 22)
            points += w
            negative_findings.append({
                "indicator": "SSL Certificate Validation Failed",
                "points": w,
                "severity": "high",
                "category": "Certificate Security",
                "description": "SSL handshake failed or certificate is self-signed/expired/invalid."
            })
            recommendations.append("Do not bypass browser SSL/TLS certificate warnings.")
        elif live_feat.get("ssl_valid") is True:
            positive_findings.append({
                "indicator": "Valid SSL Certificate",
                "description": "SSL/TLS handshake succeeded with valid trusted certificate."
            })

        # Redirect Divergence
        red_feat = features.get("redirect_analysis", {})
        if red_feat.get("has_diverged_domain"):
            w = config.WEIGHTS.get("redirect_divergence", 18)
            points += w
            negative_findings.append({
                "indicator": "Redirect to Different External Domain",
                "points": w,
                "severity": "medium",
                "category": "Redirection Behavior",
                "description": f"Redirects away from original host to external domain: '{red_feat.get('final_hostname')}'."
            })
            recommendations.append("Check whether the final redirected domain is the intended official organization.")

        # Security Headers
        sec_headers = live_feat.get("security_headers", {})
        missing_count = sum(1 for k, v in sec_headers.items() if not v)
        if missing_count >= 3:
            w = config.WEIGHTS.get("missing_security_headers", 6)
            points += w
            negative_findings.append({
                "indicator": f"Defensive Headers Missing ({missing_count} absent)",
                "points": w,
                "severity": "low",
                "category": "Web Defense Headers",
                "description": "Website lacks modern browser defense headers (HSTS, CSP, or X-Frame-Options)."
            })
        else:
            positive_findings.append({
                "indicator": "Defensive Security Headers Present",
                "description": "Target employs standard defensive headers (HSTS, X-Frame-Options, or CSP)."
            })
    else:
        checks_uncompleted.append({
            "check": "Live HTTP Response & Security Headers",
            "reason": live_feat.get("error_message") or "Network probe timed out or destination was unreachable."
        })

    # 11. Optional Reputation Check
    if reputation and reputation.get("is_configured"):
        if reputation.get("is_malicious") is True:
            w = config.WEIGHTS.get("reputation_flagged", 35)
            points += w
            negative_findings.append({
                "indicator": "Threat Intelligence Blacklist Match",
                "points": w,
                "severity": "high",
                "category": "Threat Feed",
                "description": reputation.get("details", "Target flagged by configured threat intelligence source.")
            })
            recommendations.append("Known security feeds flag this URL as dangerous. Avoid visiting.")
        elif reputation.get("is_malicious") is False:
            positive_findings.append({
                "indicator": "Clean Reputation Feed Record",
                "description": reputation.get("details", "No malicious flags in configured threat feed.")
            })
    else:
        checks_uncompleted.append({
            "check": "External Threat Intelligence Blacklist",
            "reason": "Not configured (optional). Analysis relies on local heuristics."
        })

    # 12. WHOIS Information
    checks_uncompleted.append({
        "check": "WHOIS Domain Creation Date & Registrar Details",
        "reason": "Requires external registry WHOIS lookup service (disabled to avoid rate limits or paid dependencies)."
    })

    # Bound score strictly between 0 and 100
    final_score = min(100, max(0, points))

    # Determine risk category according to project specification
    if final_score < 30:
        risk_category = config.RISK_LEVEL_LOW
        risk_tier = "low"
        risk_badge_class = "success"
        verdict_summary = (
            "Few or no suspicious security indicators were detected. "
            "The URL appears consistent with typical legitimate site structures based on the checks performed."
        )
    elif final_score < 60:
        risk_category = config.RISK_LEVEL_MEDIUM
        risk_tier = "medium"
        risk_badge_class = "warning"
        verdict_summary = (
            "Potentially suspicious indicators were detected. "
            "Further verification is recommended before entering sensitive credentials or personal details."
        )
    else:
        risk_category = config.RISK_LEVEL_HIGH
        risk_tier = "high"
        risk_badge_class = "danger"
        verdict_summary = (
            "Multiple high-risk indicators were detected. "
            "The URL exhibits characteristics commonly observed in phishing attacks or deceptive web destinations."
        )

    # Default fallback recommendation if none triggered
    if not recommendations:
        recommendations.append("Continue standard cyber hygiene: verify URL address bar and ensure valid lock icon before logging in.")

    return {
        "final_score": final_score,
        "risk_category": risk_category,
        "risk_tier": risk_tier,
        "risk_badge_class": risk_badge_class,
        "verdict_summary": verdict_summary,
        "total_indicators_flagged": len(negative_findings),
        "negative_findings": negative_findings,
        "positive_findings": positive_findings,
        "checks_uncompleted": checks_uncompleted,
        "recommendations": recommendations
    }
