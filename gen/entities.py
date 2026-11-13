"""Safe fake entity pools and validators.

ALL network/indicator values here are intentionally non-routable / reserved so
the dataset is safe to ship: external IPs come only from RFC5737 TEST-NET
ranges, internal IPs from RFC1918, domains only under .example/.test/.invalid
(RFC2606/RFC6761), hashes are random hex, and no real malware family names or
working payloads are ever emitted.
"""
import ipaddress
import re

# --- RFC5737 TEST-NET external ranges (safe to publish) ---
EXT_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
# --- RFC1918 internal ranges ---
INT_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
ALLOWED_DOMAIN_TLDS = (".example", ".test", ".invalid")
# RFC2606 reserved second-level names are also allowed (example.com/.org/.net)
ALLOWED_DOMAIN_SUFFIXES = ALLOWED_DOMAIN_TLDS + (
    "example.com", "example.org", "example.net",
)

# Real offensive-tool / malware family names that must never appear verbatim.
FORBIDDEN_NAMES = [
    "mimikatz", "cobaltstrike", "cobalt strike", "metasploit", "meterpreter",
    "emotet", "trickbot", "qakbot", "qbot", "lockbit", "conti", "ryuk",
    "wannacry", "notpetya", "bloodhound", "sharphound", "rubeus", "psexec.py",
    "impacket", "empire", "sliver", "brute ratel", "nanodump", "lazagne",
]


class Entities:
    """Deterministic pools keyed off a shared seeded Random."""

    def __init__(self, rng):
        self.rng = rng
        self._ext_cache = {}
        self._int_cache = {}

    # ---- IPs ----
    def ext_ip(self, key=None):
        """Stable external (RFC5737) IP, optionally memoised by key."""
        if key is not None and key in self._ext_cache:
            return self._ext_cache[key]
        net = self.rng.choice(EXT_NETS)
        host = self.rng.randint(1, 254)
        ip = str(net.network_address + host)
        if key is not None:
            self._ext_cache[key] = ip
        return ip

    def int_ip(self, subnet="10.20.0.0/16", key=None):
        if key is not None and key in self._int_cache:
            return self._int_cache[key]
        net = ipaddress.ip_network(subnet)
        host = self.rng.randint(1, min(65000, net.num_addresses - 2))
        ip = str(net.network_address + host)
        if key is not None:
            self._int_cache[key] = ip
        return ip

    # ---- domains / urls ----
    def ext_domain(self, label=None):
        label = label or self.rng.choice(
            ["update-check", "cdn-sync", "telemetry-node", "api-gw",
             "login-portal", "cloud-share", "pkg-mirror", "ns-report"]
        )
        tld = self.rng.choice([".test", ".invalid", ".example"])
        return f"{label}{self.rng.randint(1,99)}{tld}"

    def int_domain(self, host):
        return f"{host.lower()}.corp.example"

    def url(self, domain=None, path=None):
        d = domain or self.ext_domain()
        p = path or self.rng.choice(
            ["/api/v2/beacon", "/wp-content/up.php", "/j/collect",
             "/updates/pkg.bin", "/share/download", "/cdn/asset.js"]
        )
        scheme = self.rng.choice(["http", "https"])
        return f"{scheme}://{d}{p}"

    # ---- hashes ----
    def _hex(self, n):
        return "".join(self.rng.choice("0123456789abcdef") for _ in range(n))

    def md5(self):
        return self._hex(32)

    def sha1(self):
        return self._hex(40)

    def sha256(self):
        return self._hex(64)

    # ---- misc indicators ----
    def mutex(self):
        return "Global\\" + self._hex(16)

    def reg_run_key(self, value_name=None):
        hive = self.rng.choice([
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ])
        vn = value_name or self.rng.choice(
            ["OneDriveSync", "WinUpdateSvc", "AdobeARMsvc", "SecurityHealth"]
        )
        return hive + "\\" + vn

    def user_agent(self):
        return self.rng.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
            "python-requests/2.31.0",
            "curl/8.4.0",
            "Microsoft BITS/7.8",
            "WinHTTP/1.6",
            "Go-http-client/1.1",
        ])


# ---------------- validators (used by validator.py) ----------------

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


# Reserved/non-routable addresses that may legitimately appear in logs
# (loopback for local logons, unspecified/broadcast, link-local).
_RESERVED_SAFE = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "0.0.0.0/32", "255.255.255.255/32", "169.254.0.0/16")]


def ip_is_safe(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in EXT_NETS + INT_NETS + _RESERVED_SAFE:
        if addr in net:
            return True
    return False


def domain_is_safe(domain):
    d = domain.lower().rstrip(".")
    return any(d == s or d.endswith("." + s) or d.endswith(s)
               for s in ALLOWED_DOMAIN_SUFFIXES) or any(
        d.endswith(t) for t in ALLOWED_DOMAIN_TLDS)


def hash_is_safe(value, kind):
    lengths = {"md5": 32, "sha1": 40, "sha256": 64}
    if kind not in lengths:
        return False
    return len(value) == lengths[kind] and bool(_HEX_RE.match(value))


def text_has_forbidden(text):
    low = text.lower()
    return [n for n in FORBIDDEN_NAMES if n in low]
