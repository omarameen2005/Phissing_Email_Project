# engine/extractor_url.py
"""
Advanced URL Feature Extractor for Phishing Detection
Extracts 10 powerful phishing indicators from raw email text.
Used by URLHandler in the Chain of Responsibility.
"""
import re
from urllib.parse import urlparse, unquote
from typing import List, Tuple

# High-precision phishing indicators (constantly updated)
SUSPICIOUS_TLDS = {
    "ru", "cn", "tk", "top", "xyz", "zip", "biz", "pw", "info", "ga", "gq", "ml",
    "cf", "sbs", "pub", "cfd", "so", "icu", "re", "ua", "online", "link", "ly",
    "site", "click", "work", "club", "loan", "win", "stream", "review", "cam",
    "date", "party", "gdn", "racing", "accountant"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "cli.re", "bl.ink", "short.link", "rebrand.ly", "shrtco.de", "cut.ly"
}

SUSPICIOUS_KEYWORDS = {
    "login", "update", "verify", "secure", "banking", "account", "password",
    "confirm", "payment", "billing", "suspend", "deactivate", "security",
    "alert", "urgent", "immediate", "support", "helpdesk", "ebay", "paypal",
    "amazon", "apple", "microsoft", "netflix", "crypto", "wallet", "recovery"
}

# Regex for IP address domains
IP_DOMAIN_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def extract_urls(text: str) -> List[str]:
    """
    Extract and decode all URLs from text.
    Handles http, https, www., and obfuscated URLs.
    """
    if not text:
        return []
    
    pattern = r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+)'
    raw_urls = re.findall(pattern, text, re.IGNORECASE)
    return [unquote(url.strip()) for url in raw_urls]


def url_features(text: str) -> Tuple[int, int, int, int, int, int, int, int, int, int]:
    """
    Extract 10 powerful phishing URL features from email text.
    Returns tuple in fixed order for URLHandler.
    
    Returns:
        (length, dots, at_symbol, no_https, keywords, ip_domain,
         bad_tld, shortener, special_chars, has_uppercase)
    """
    urls = extract_urls(text)
    if not urls:
        return (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    max_length = max_dots = max_specials = 0
    has_at = has_no_https = has_keyword = has_ip = has_bad_tld = is_shortener = has_upper = 0

    for url in urls:
        try:
            # Normalize URL
            if not url.startswith(("http://", "https://")):
                url_norm = "http://" + url
            else:
                url_norm = url

            parsed = urlparse(url_norm)
            domain = parsed.netloc.lower()
            path_query = (parsed.path + parsed.query).lower()
            full_url = url.lower()

            # 1. Length
            max_length = max(max_length, len(url))

            # 2. Number of dots
            max_dots = max(max_dots, url.count('.'))

            # 3. Contains @ symbol (obfuscation)
            has_at = has_at or ('@' in url)

            # 4. Not using HTTPS
            has_no_https = has_no_https or not url.startswith("https://")

            # 5. Suspicious keywords in URL
            has_keyword = has_keyword or any(k in full_url for k in SUSPICIOUS_KEYWORDS)

            # 6. IP address instead of domain
            clean_domain = domain.split(':')[0]  # remove port
            has_ip = has_ip or bool(IP_DOMAIN_REGEX.match(clean_domain))

            # 7. Suspicious TLD
            tld = clean_domain.split('.')[-1] if '.' in clean_domain else ''
            has_bad_tld = has_bad_tld or (tld in SUSPICIOUS_TLDS)

            # 8. Known URL shortener
            is_shortener = is_shortener or any(short in domain for short in SHORTENER_DOMAINS)

            # 9. Special characters count
            special_count = len(re.findall(r'[%\-_+/=?#&]', url))
            max_specials = max(max_specials, special_count)

            # 10. Contains uppercase letters (rare in real URLs)
            has_upper = has_upper or any(c.isupper() for c in url if c.isalpha())

        except Exception:
            continue  # Never crash on bad URL

    return (
        max_length,
        max_dots,
        int(has_at),
        int(has_no_https),
        int(has_keyword),
        int(has_ip),
        int(has_bad_tld),
        int(is_shortener),
        max_specials,
        int(has_upper)
    )