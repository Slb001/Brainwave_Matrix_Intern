
import re
import requests
from urllib.parse import urlparse

# Common phishing keywords and suspicious TLDs
PHISHING_KEYWORDS = ['login', 'verify', 'update', 'secure', 'banking', 'account', 'confirm', 'webscr']
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq']

def is_suspicious_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    score = 0
    reasons = []

    # Check for IP-based URL
    if re.match(r'\d{1,3}(\.\d{1,3}){3}', domain):
        score += 2
        reasons.append("Uses IP address instead of domain")

    # Check for phishing keywords
    for keyword in PHISHING_KEYWORDS:
        if keyword in path or keyword in domain:
            score += 1
            reasons.append(f"Contains suspicious keyword: '{keyword}'")

    # Check for strange TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 2
            reasons.append(f"Suspicious TLD: '{tld}'")

    # Check for hyphens or subdomains
    if domain.count('.') > 2 or '-' in domain:
        score += 1
        reasons.append("Unusual number of subdomains or use of hyphens")

    return score, reasons

def main():
    url = input("Enter a URL to scan: ").strip()

    if not url.startswith('http'):
        url = 'http://' + url  # Fix incomplete URLs

    try:
        response = requests.head(url, timeout=5)
        print(f"URL is reachable. Status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Warning: URL may be offline or fake. Error: {e}")

    score, reasons = is_suspicious_url(url)

    print("\n--- Analysis ---")
    for reason in reasons:
        print(f"- {reason}")

    if score >= 0:
        print("🔴 This URL is likely **Malicious**")
    elif score >= 2:
        print("🟠 This URL is **Suspicious**")
    else:
        print("🟢 This URL appears **Safe**")

if __name__ == "__main__":
    main()
