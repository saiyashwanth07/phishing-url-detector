import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "secure", "account", "verify", "update",
    "bank", "confirm", "signin", "payment"
]

def url_risk_score(url):
    score = 0
    domain = (urlparse(url).netloc or urlparse(url).path).lower()

    # Length
    if len(domain) > 30:
        score += 15

    # Hyphens
    score += domain.count("-") * 10

    # Digits
    score += sum(c.isdigit() for c in domain) * 5

    # Suspicious words
    for word in SUSPICIOUS_WORDS:
        if word in domain:
            score += 20

    # IP address usage
    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 40

    return min(score, 100)
