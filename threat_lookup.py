import pandas as pd

# Load phishing dataset once
db = pd.read_csv("dataset/malicious_phish.csv")

# Keep only phishing URLs
phishing_urls = set(db[db["type"] == "phishing"]["url"].str.lower())

def check_threat(url):
    return url.lower() in phishing_urls
