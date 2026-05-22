import requests
import time

_cache = {}

def lookup(ip):
    if ip in _cache:
        return _cache[ip]

    private_prefixes = ("10.", "192.168.", "127.", "172.")
    if any(ip.startswith(p) for p in private_prefixes):
        result = {"country": "Private", "city": "Local", "lat": 0, "lon": 0, "isp": "Local Network"}
        _cache[ip] = result
        return result

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,lat,lon,isp,status", timeout=3)
        data = r.json()
        if data.get("status") == "success":
            result = {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "isp": data.get("isp", "Unknown"),
            }
        else:
            result = {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0, "isp": "Unknown"}
        _cache[ip] = result
        time.sleep(0.1)
        return result
    except Exception:
        return {"country": "Error", "city": "Error", "lat": 0, "lon": 0, "isp": "Error"}


def bulk_lookup(ips):
    return {ip: lookup(ip) for ip in ips}
