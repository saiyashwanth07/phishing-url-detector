import whois
import datetime
import tldextract
import socket

socket.setdefaulttimeout(2)   # prevent long hangs

def get_domain(url):
    ext = tldextract.extract(url)
    return ext.domain + "." + ext.suffix

def get_domain_age(url):
    try:
        domain = get_domain(url)
        w = whois.whois(domain)
        created = w.creation_date

        if isinstance(created, list):
            created = created[0]

        if created is None:
            return -1

        return (datetime.datetime.now() - created).days

    except Exception:
        return -1   # fail-safe
