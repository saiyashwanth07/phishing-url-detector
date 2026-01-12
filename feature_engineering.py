import pandas as pd
import re
import math
import os
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "malicious_phish.csv")

print("Loading dataset from:", DATASET_PATH)

df = pd.read_csv(DATASET_PATH).dropna()
df["url"] = df["url"].astype(str)

SUSPICIOUS_WORDS = ["login","secure","account","verify","update","bank","confirm","signin","payment"]
SUSPICIOUS_TLDS = [".tk",".ml",".ga",".cf",".gq",".work",".top"]

def entropy(url):
    prob = [url.count(c)/len(url) for c in set(url)]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def approx_domain_age(url):
    url = url.lower()
    if any(url.endswith(tld) for tld in SUSPICIOUS_TLDS):
        return 5     # very new domains
    if any(word in url for word in SUSPICIOUS_WORDS):
        return 30
    return 365      # assume old domain

rows = []

for _, row in df.iterrows():
    url = row["url"]
    label = row["type"]
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    rows.append({
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_digits": sum(c.isdigit() for c in url),
        "num_hyphens": url.count("-"),
        "num_subdomains": len(domain.split(".")) - 2 if "." in domain else 0,
        "has_ip": 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        "has_https": 1 if url.startswith("https") else 0,
        "has_at": 1 if "@" in url else 0,
        "query_length": len(parsed.query),
        "suspicious_words": sum(word in url.lower() for word in SUSPICIOUS_WORDS),
        "suspicious_tld": 1 if any(url.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0,
        "approx_domain_age": approx_domain_age(url),
        "entropy": entropy(url),
        "label": label
    })

feature_df = pd.DataFrame(rows)

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "phishing_features.csv")
feature_df.to_csv(OUTPUT_PATH, index=False)

print("Feature dataset created:", feature_df.shape)
print("Saved to:", OUTPUT_PATH)
