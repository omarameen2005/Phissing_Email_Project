import re
from urllib.parse import urlparse, unquote
from typing import List
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin


SUSPICIOUS_TLDS = {
    "ru", "cn", "tk", "top", "xyz", "zip", "biz", "pw", "info", "ga", "gq", "ml",
    "cf", "sbs", "pub", "cfd", "so", "icu", "re", "ua", "online", "link", "ly",
    "site", "click", "work", "club", "loan", "win", "stream", "cam", "date", "party"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "cli.re", "bl.ink", "short.link", "rebrand.ly", "shrtco.de", "cut.ly"
}

SUSPICIOUS_KEYWORDS = {
    "login", "update", "verify", "secure", "bank", "account", "password",
    "confirm", "payment", "billing", "suspend", "urgent", "alert", "support",
    "ebay", "paypal", "amazon", "apple", "microsoft", "netflix", "crypto"
}


def extract_urls(text: str) -> List[str]:

    if not text:
        return []
    pattern = r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+)'
    urls = re.findall(pattern, text, re.IGNORECASE)
    return [unquote(u.strip().lower()) for u in urls]


def url_features(text: str) -> list:

    urls = extract_urls(text)
    if not urls:
        return [0] * 10

    features_per_url = []
    for url in urls:
        try:
        
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path_query = (parsed.path + parsed.query).lower()

          
            features_per_url.append([
                len(url),                                    
                url.count('.'),                        
                int('@' in url),                        
                int(not url.startswith("https://")),       
                int(any(k in url for k in SUSPICIOUS_KEYWORDS)),  
                int(bool(re.match(r"\d+\.\d+\.\d+\.\d+", domain))),  
                int(domain.split(".")[-1] in SUSPICIOUS_TLDS),       
                int(any(s in domain for s in SHORTENER_DOMAINS)),    
                len(re.findall(r'[-_?=&%+/]', url)),         
                int(any(c.isupper() for c in url if c.isalpha()))   
            ])
        except Exception:
            features_per_url.append([0] * 10)


    return list(map(max, zip(*features_per_url)))



class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self
    def transform(self, X):
        return np.array([url_features(text) for text in X])