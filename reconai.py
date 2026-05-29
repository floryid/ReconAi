from __future__ import annotations

import argparse
import json
import math
import re
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Iterable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit, parse_qsl, quote_plus
from urllib.request import Request, urlopen

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

console = Console()

BANNER = """
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ █████╗ ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██║██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝
""".strip("\n")

BANNER_ASCII = r"""
 ____                        ___    ___
|  _ \ ___  ___ ___  _ __   / _ \  |_ _|
| |_) / _ \/ __/ _ \| '_ \ | | | |  | |
|  _ <  __/ (_| (_) | | | || |_| |  | |
|_| \_\___|\___\___/|_| |_| \___/  |___|
""".strip("\n")


@dataclass(frozen=True)
class HttpResult:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: int


@dataclass(frozen=True)
class Endpoint:
    url: str
    source: str


@dataclass(frozen=True)
class Finding:
    title: str
    category: str
    severity: str
    score: int
    evidence: str = ""
    url: str = ""
    explanation: str = ""


@dataclass
class ReconState:
    base_url: str
    html_urls: set[str] = field(default_factory=set)
    js_urls: set[str] = field(default_factory=set)
    discovered_urls: set[str] = field(default_factory=set)
    endpoints_from_js: set[str] = field(default_factory=set)
    subdomains: set[str] = field(default_factory=set)
    live_subdomains: dict[str, int] = field(default_factory=dict)
    secrets: list[Finding] = field(default_factory=list)
    param_findings: list[Finding] = field(default_factory=list)
    surface_findings: list[Finding] = field(default_factory=list)
    graphql_findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[str] = []
        self.inline_scripts: list[str] = []
        self._in_script = False
        self._script_buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attrs_map = dict(attrs)
        if tag == "a":
            href = attrs_map.get("href")
            if href:
                self.links.append(href)
        if tag == "script":
            src = attrs_map.get("src")
            if src:
                self.scripts.append(src)
            self._in_script = True
            self._script_buf = []
        if tag == "form":
            action = attrs_map.get("action")
            if action:
                self.forms.append(action)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            text = "".join(self._script_buf).strip()
            if text:
                self.inline_scripts.append(text)
            self._in_script = False
            self._script_buf = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_buf.append(data)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent


def severity_from_score(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


def severity_style(sev: str) -> str:
    sev = (sev or "").upper()
    if sev == "CRITICAL":
        return "bold white on red"
    if sev == "HIGH":
        return "bold red"
    if sev == "MEDIUM":
        return "bold yellow"
    if sev == "LOW":
        return "bold green"
    return "bold cyan"


def supports_unicode_box() -> bool:
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "┌┐└┘─│".encode(enc)
        return True
    except Exception:
        return False


USE_ASCII_BOX = not supports_unicode_box()
BOX_STYLE = box.ASCII if USE_ASCII_BOX else box.ROUNDED


def supports_unicode_banner() -> bool:
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "████".encode(enc)
        return True
    except Exception:
        return False


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("target kosong")
    if "://" not in target:
        return f"https://{target}"
    return target


def normalize_domain_only(domain_or_url: str) -> str:
    raw = (domain_or_url or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        return urlparse(raw).netloc.split("@")[-1].split(":")[0].lower()
    return raw.split("@")[-1].split(":")[0].lower()


def make_ssl_context(insecure: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(
    url: str,
    *,
    method: str = "GET",
    data: Optional[bytes] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: float = 12.0,
    insecure: bool = False,
    max_bytes: int = 2_000_000,
) -> Optional[HttpResult]:
    t0 = time.time()
    hdrs = {
        "User-Agent": "ReconAI/1.0 (+triage)",
        "Accept": "*/*",
        "Connection": "close",
    }
    if headers:
        hdrs.update(headers)
    req = Request(url=url, method=method, data=data, headers=hdrs)
    try:
        with urlopen(req, timeout=timeout, context=make_ssl_context(insecure)) as resp:
            body = resp.read(max_bytes)
            elapsed = int((time.time() - t0) * 1000)
            return HttpResult(
                url=resp.geturl(),
                status=int(getattr(resp, "status", 0) or 0),
                headers={k.lower(): v for k, v in resp.headers.items()},
                body=body,
                elapsed_ms=elapsed,
            )
    except HTTPError as e:
        try:
            body = e.read(max_bytes)
        except Exception:
            body = b""
        elapsed = int((time.time() - t0) * 1000)
        return HttpResult(
            url=getattr(e, "url", url) or url,
            status=int(getattr(e, "code", 0) or 0),
            headers={k.lower(): v for k, v in getattr(e, "headers", {}).items()},
            body=body,
            elapsed_ms=elapsed,
        )
    except URLError:
        return None
    except Exception:
        return None


def crtsh_subdomains(domain: str, *, timeout: float, insecure: bool) -> set[str]:
    domain = (domain or "").strip(".").lower()
    if not domain:
        return set()
    url = f"https://crt.sh/?q={quote_plus('%25.' + domain)}&output=json"
    res = fetch(
        url,
        timeout=timeout,
        insecure=insecure,
        max_bytes=4_000_000,
        headers={"Accept": "application/json", "User-Agent": "ReconAI/1.0 (+triage)"},
    )
    if not res or res.status != 200 or not res.body:
        return set()
    text = decode_bytes(res.body)
    out: set[str] = set()
    data = None
    try:
        data = json.loads(text)
    except Exception:
        data = None
    if isinstance(data, list):
        for row in data:
            if not isinstance(row, dict):
                continue
            name_value = row.get("name_value")
            if not isinstance(name_value, str):
                continue
            for host in name_value.splitlines():
                h = host.strip().lower()
                if not h:
                    continue
                if h.startswith("*."):
                    h = h[2:]
                if h == domain or h.endswith("." + domain):
                    out.add(h)
        return out

    for m in re.finditer(r'"name_value"\s*:\s*"([^"]+)"', text):
        blob = m.group(1)
        blob = blob.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
        for host in blob.splitlines():
            h = host.strip().lower()
            if not h:
                continue
            if h.startswith("*."):
                h = h[2:]
            if h == domain or h.endswith("." + domain):
                out.add(h)
    return out


def certspotter_subdomains(domain: str, *, timeout: float, insecure: bool) -> set[str]:
    domain = (domain or "").strip(".").lower()
    if not domain:
        return set()
    url = f"https://api.certspotter.com/v1/issuances?domain={quote_plus(domain)}&include_subdomains=true&expand=dns_names"
    res = fetch(
        url,
        timeout=timeout,
        insecure=insecure,
        max_bytes=3_000_000,
        headers={"Accept": "application/json", "User-Agent": "ReconAI/1.0 (+triage)"},
    )
    if not res or res.status != 200 or not res.body:
        return set()
    text = decode_bytes(res.body)
    try:
        data = json.loads(text)
    except Exception:
        return set()
    out: set[str] = set()
    if not isinstance(data, list):
        return out
    for row in data:
        if not isinstance(row, dict):
            continue
        dns_names = row.get("dns_names")
        if not isinstance(dns_names, list):
            continue
        for host in dns_names:
            if not isinstance(host, str):
                continue
            h = host.strip().lower()
            if h.startswith("*."):
                h = h[2:]
            if h == domain or h.endswith("." + domain):
                out.add(h)
    return out


def bufferover_subdomains(domain: str, *, timeout: float, insecure: bool) -> set[str]:
    domain = (domain or "").strip(".").lower()
    if not domain:
        return set()
    url = f"https://dns.bufferover.run/dns?q={quote_plus('.' + domain)}"
    res = fetch(
        url,
        timeout=timeout,
        insecure=insecure,
        max_bytes=2_000_000,
        headers={"Accept": "application/json", "User-Agent": "ReconAI/1.0 (+triage)"},
    )
    if not res or res.status != 200 or not res.body:
        return set()
    text = decode_bytes(res.body)
    try:
        doc = json.loads(text)
    except Exception:
        return set()
    out: set[str] = set()
    if not isinstance(doc, dict):
        return out
    for key in ("FDNS_A", "RDNS"):
        arr = doc.get(key)
        if not isinstance(arr, list):
            continue
        for item in arr:
            if not isinstance(item, str):
                continue
            parts = item.split(",")
            host = parts[-1].strip().lower()
            if host.startswith("*."):
                host = host[2:]
            if host == domain or host.endswith("." + domain):
                out.add(host)
    return out


def rapiddns_subdomains(domain: str, *, timeout: float, insecure: bool) -> set[str]:
    domain = (domain or "").strip(".").lower()
    if not domain:
        return set()
    url = f"https://rapiddns.io/subdomain/{quote_plus(domain)}?full=1"
    res = fetch(
        url,
        timeout=timeout,
        insecure=insecure,
        max_bytes=2_000_000,
        headers={"Accept": "text/html", "User-Agent": "ReconAI/1.0 (+triage)"},
    )
    if not res or res.status != 200 or not res.body:
        return set()
    html = decode_bytes(res.body)
    out: set[str] = set()
    escaped = re.escape(domain)
    for m in re.finditer(rf"(?i)>([a-z0-9][a-z0-9\-.]{{0,190}}\.{escaped})<", html):
        host = m.group(1).strip(".").lower()
        if host.startswith("*."):
            host = host[2:]
        if host != domain and host.endswith("." + domain):
            out.add(host)
    return out


def doh_rr_exists(name: str, rr_type: str, *, timeout: float, insecure: bool) -> bool:
    name = (name or "").strip().lower()
    if not name:
        return False
    url = f"https://cloudflare-dns.com/dns-query?name={quote_plus(name)}&type={quote_plus(rr_type)}"
    res = fetch(
        url,
        timeout=timeout,
        insecure=insecure,
        max_bytes=220_000,
        headers={"Accept": "application/dns-json", "User-Agent": "ReconAI/1.0 (+triage)"},
    )
    if not res or res.status != 200 or not res.body:
        return False
    text = decode_bytes(res.body)
    try:
        doc = json.loads(text)
    except Exception:
        return False
    if not isinstance(doc, dict):
        return False
    status = doc.get("Status")
    if status != 0:
        return False
    ans = doc.get("Answer")
    if not isinstance(ans, list):
        return False
    for a in ans:
        if isinstance(a, dict) and a.get("type") in {1, 28, 5}:
            return True
    return False


def doh_name_exists(name: str, *, timeout: float, insecure: bool) -> bool:
    if doh_rr_exists(name, "A", timeout=timeout, insecure=insecure):
        return True
    return doh_rr_exists(name, "AAAA", timeout=timeout, insecure=insecure)


def bruteforce_subdomains(domain: str, *, timeout: float, insecure: bool, max_hits: int = 80) -> set[str]:
    domain = (domain or "").strip(".").lower()
    if not domain:
        return set()
    words = [
        "www",
        "api",
        "admin",
        "portal",
        "app",
        "apps",
        "dashboard",
        "dev",
        "test",
        "staging",
        "uat",
        "beta",
        "demo",
        "internal",
        "intranet",
        "vpn",
        "mail",
        "smtp",
        "imap",
        "pop",
        "webmail",
        "autodiscover",
        "ns1",
        "ns2",
        "dns",
        "cdn",
        "static",
        "assets",
        "img",
        "images",
        "files",
        "download",
        "uploads",
        "status",
        "monitor",
        "grafana",
        "prometheus",
        "kibana",
        "logs",
        "sso",
        "auth",
        "oauth",
        "login",
        "id",
        "accounts",
        "billing",
        "pay",
        "payment",
        "crm",
        "erp",
        "hr",
        "help",
        "support",
        "docs",
        "swagger",
        "openapi",
        "graphql",
        "git",
        "gitlab",
        "jenkins",
        "ci",
        "registry",
        "docker",
        "k8s",
    ]
    out: set[str] = set()
    with ThreadPoolExecutor(max_workers=18) as ex:
        futs = {}
        for w in words:
            host = f"{w}.{domain}"
            futs[ex.submit(doh_name_exists, host, timeout=timeout, insecure=insecure)] = host
        for fut in as_completed(futs):
            host = futs[fut]
            ok = False
            try:
                ok = bool(fut.result())
            except Exception:
                ok = False
            if ok:
                out.add(host)
                if len(out) >= max_hits:
                    break
    return out


def extract_subdomains_from_urls(root_domain: str, urls: Iterable[str]) -> set[str]:
    root_domain = (root_domain or "").strip(".").lower()
    if not root_domain:
        return set()
    out: set[str] = set()
    for u in urls:
        if not u:
            continue
        try:
            host = urlparse(u).netloc.split("@")[-1].split(":")[0].lower()
        except Exception:
            continue
        if not host:
            continue
        if host == root_domain:
            continue
        if host.endswith("." + root_domain):
            out.add(host)
    return out


def extract_subdomains_from_text(root_domain: str, text: str) -> set[str]:
    root_domain = (root_domain or "").strip(".").lower()
    if not root_domain or not text:
        return set()
    escaped = re.escape(root_domain)
    pat = re.compile(rf"(?i)\b([a-z0-9][a-z0-9\-\.]{{0,190}})\.{escaped}\b")
    out: set[str] = set()
    for m in pat.finditer(text):
        left = (m.group(1) or "").strip(".").lower()
        if not left:
            continue
        host = f"{left}.{root_domain}"
        if host != root_domain and host.endswith("." + root_domain):
            out.add(host)
    return out


def probe_live_hosts(hosts: Iterable[str], *, timeout: float, insecure: bool, max_hosts: int = 40) -> dict[str, int]:
    unique: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        hh = (h or "").strip().lower()
        if not hh or hh in seen:
            continue
        seen.add(hh)
        unique.append(hh)
        if len(unique) >= max_hosts:
            break

    def check_one(host: str) -> tuple[str, int]:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            res = fetch(url, timeout=timeout, insecure=insecure, max_bytes=180_000)
            if res and res.status:
                return host, res.status
        return host, 0

    out: dict[str, int] = {}
    if not unique:
        return out
    with ThreadPoolExecutor(max_workers=12) as ex:
        futs = {ex.submit(check_one, h): h for h in unique}
        for fut in as_completed(futs):
            host, status = ("", 0)
            try:
                host, status = fut.result()
            except Exception:
                host, status = (futs[fut], 0)
            if status:
                out[host] = status
    return out


def subdomain_findings(subdomains: set[str], live: dict[str, int]) -> list[Finding]:
    findings: list[Finding] = []
    base_score = 20
    for host in sorted(subdomains):
        status = live.get(host, 0)
        score = base_score + (10 if status in {200, 301, 302, 401, 403} else 0)
        key_bonus = 0
        if re.search(r"(?i)\b(admin|internal|intranet|vpn|sso|auth|oauth|grafana|kibana|jenkins|gitlab|ci|staging|uat|dev)\b", host):
            key_bonus = 25
        score = min(100, score + key_bonus)
        sev = severity_from_score(score)
        evidence = f"host={host}"
        if status:
            evidence = f"status={status} host={host}"
        findings.append(
            Finding(
                title="Subdomain ditemukan",
                category="Subdomain",
                severity=sev,
                score=score,
                evidence=evidence,
                url=f"https://{host}/" if status else "",
                explanation="Subdomain menambah attack surface. Prioritaskan yang mengandung kata admin/auth/dev/staging atau yang memberi response 200/30x/401/403.",
            )
        )
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings[:30]


def score_subdomain(host: str, status: int) -> tuple[int, str]:
    score = 20 + (10 if status in {200, 301, 302, 401, 403} else 0)
    if re.search(r"(?i)\b(admin|internal|intranet|vpn|sso|auth|oauth|grafana|kibana|jenkins|gitlab|ci|staging|uat|dev)\b", host):
        score += 25
    return min(100, score), severity_from_score(score)


def pick_working_base_url(candidate: str, *, timeout: float, insecure: bool) -> str:
    parsed = urlparse(candidate)
    if parsed.scheme in {"http", "https"}:
        res = fetch(candidate, timeout=timeout, insecure=insecure, max_bytes=300_000)
        if res:
            return candidate.rstrip("/")
        if parsed.scheme == "https":
            alt = urlunsplit(("http", parsed.netloc, parsed.path, parsed.query, parsed.fragment))
            res2 = fetch(alt, timeout=timeout, insecure=insecure, max_bytes=300_000)
            if res2:
                return alt.rstrip("/")
        return candidate.rstrip("/")
    https = f"https://{candidate}"
    res3 = fetch(https, timeout=timeout, insecure=insecure, max_bytes=300_000)
    if res3:
        return https.rstrip("/")
    http = f"http://{candidate}"
    res4 = fetch(http, timeout=timeout, insecure=insecure, max_bytes=300_000)
    if res4:
        return http.rstrip("/")
    return https.rstrip("/")


def is_same_site(base_url: str, other_url: str) -> bool:
    b = urlparse(base_url)
    o = urlparse(other_url)
    if not o.netloc:
        return True
    return o.netloc.lower() == b.netloc.lower()


COMMON_2LEVEL_TLDS = {
    "co.id",
    "ac.id",
    "go.id",
    "or.id",
    "sch.id",
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
}


def registrable_domain(host: str) -> str:
    host = (host or "").strip(".").lower()
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    tail2 = ".".join(parts[-2:])
    if tail2 in COMMON_2LEVEL_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail2


def is_related_host(base_host: str, other_host: str) -> bool:
    b = registrable_domain(base_host)
    o = (other_host or "").lower()
    return o == base_host.lower() or o.endswith("." + b) or o == b


def clean_url(u: str) -> str:
    u = u.strip()
    if not u:
        return ""
    if u.startswith(("javascript:", "mailto:", "tel:", "#")):
        return ""
    return u


def parse_html_for_assets(base_url: str, html: str) -> tuple[set[str], set[str], set[str], list[str]]:
    parser = LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        return set(), set(), set(), []
    links: set[str] = set()
    scripts: set[str] = set()
    forms: set[str] = set()
    for raw in parser.links:
        raw = clean_url(raw)
        if raw:
            links.add(urljoin(base_url + "/", raw))
    for raw in parser.scripts:
        raw = clean_url(raw)
        if raw:
            scripts.add(urljoin(base_url + "/", raw))
    for raw in parser.forms:
        raw = clean_url(raw)
        if raw:
            forms.add(urljoin(base_url + "/", raw))
    return links, scripts, forms, parser.inline_scripts


def extract_urls_from_text(base_url: str, text: str) -> set[str]:
    found: set[str] = set()
    for m in re.finditer(r"https?://[^\s'\"<>]+", text):
        found.add(m.group(0).rstrip(").,;"))
    for m in re.finditer(r"(?<![a-zA-Z0-9_])/(?:api|graphql|admin|v\d+|auth|oauth|internal)[^\s'\"<>]*", text):
        found.add(urljoin(base_url + "/", m.group(0).rstrip(").,;")))
    return {u for u in found if clean_url(u)}


def decode_bytes(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def looks_like_json(text: str) -> bool:
    t = (text or "").lstrip()
    return t.startswith("{") or t.startswith("[")


def is_html_content_type(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return "text/html" in ct or "application/xhtml+xml" in ct


def crawl_html(
    base_url: str,
    seeds: Iterable[str],
    *,
    timeout: float,
    insecure: bool,
    max_depth: int,
    max_pages: int,
) -> tuple[set[str], set[str], list[str], set[str]]:
    base_host = urlparse(base_url).netloc.lower()
    visited: set[str] = set()
    html_urls: set[str] = set()
    js_urls: set[str] = set()
    inline_scripts: list[str] = []
    extracted_urls: set[str] = set()

    queue: list[tuple[str, int]] = []
    for s in seeds:
        if not s:
            continue
        queue.append((s, 0))

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        res = fetch(url, timeout=timeout, insecure=insecure, max_bytes=1_200_000)
        if not res or not res.body:
            continue
        ct = res.headers.get("content-type", "")
        if not is_html_content_type(ct):
            continue
        html_urls.add(res.url)

        text = decode_bytes(res.body)
        links, scripts, forms, inline = parse_html_for_assets(base_url, text)
        inline_scripts.extend(inline)
        extracted_urls |= extract_urls_from_text(base_url, text)
        for blob in inline:
            extracted_urls |= extract_urls_from_text(base_url, blob)

        for s in scripts:
            try:
                host = urlparse(s).netloc.lower()
            except Exception:
                host = ""
            if not host or is_related_host(base_host, host):
                js_urls.add(s)

        if depth >= max_depth:
            continue
        for nxt in links.union(forms):
            if not is_same_site(base_url, nxt):
                continue
            if nxt not in visited:
                queue.append((nxt, depth + 1))

    return html_urls, js_urls, inline_scripts, extracted_urls


def openapi_candidate_urls(base_url: str) -> list[str]:
    paths = [
        "/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/swagger.json",
        "/swagger.yaml",
        "/swagger.yml",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api-docs",
        "/swagger/v1/swagger.json",
        "/swagger/v1/swagger.yaml",
        "/swagger/v1/swagger.yml",
    ]
    return [urljoin(base_url + "/", p.lstrip("/")) for p in paths]


def extract_openapi_urls_from_html(base_url: str, html: str) -> set[str]:
    urls: set[str] = set()
    for m in re.finditer(r"""(?i)\burl\s*:\s*['"]([^'"]+)['"]""", html):
        u = clean_url(m.group(1))
        if u:
            urls.add(urljoin(base_url + "/", u))
    for m in re.finditer(r"""(?i)\burls\s*:\s*\[\s*\{[^}]*\burl\s*:\s*['"]([^'"]+)['"]""", html):
        u = clean_url(m.group(1))
        if u:
            urls.add(urljoin(base_url + "/", u))
    for m in re.finditer(r"""(?i)\b(spec|swaggerDoc|openapi)\s*[:=]\s*['"]([^'"]+)['"]""", html):
        u = clean_url(m.group(2))
        if u:
            urls.add(urljoin(base_url + "/", u))
    return urls


def parse_openapi_spec(spec_text: str) -> tuple[set[str], list[tuple[str, str, str]], set[str]]:
    endpoints: set[str] = set()
    params: list[tuple[str, str, str]] = []
    auth: set[str] = set()
    if not spec_text:
        return endpoints, params, auth
    if looks_like_json(spec_text):
        try:
            doc = json.loads(spec_text)
        except Exception:
            return endpoints, params, auth
    else:
        return parse_openapi_yaml_fallback(spec_text)

    paths = doc.get("paths") if isinstance(doc, dict) else None
    if isinstance(paths, dict):
        for pth, methods in paths.items():
            if not isinstance(pth, str):
                continue
            endpoints.add(pth)
            if isinstance(methods, dict):
                for _, op in methods.items():
                    if not isinstance(op, dict):
                        continue
                    op_params = op.get("parameters")
                    if isinstance(op_params, list):
                        for pr in op_params:
                            if not isinstance(pr, dict):
                                continue
                            name = pr.get("name")
                            loc = pr.get("in", "")
                            if isinstance(name, str) and name:
                                params.append((pth, name, str(loc)))
            if isinstance(methods, dict):
                common_params = methods.get("parameters")
                if isinstance(common_params, list):
                    for pr in common_params:
                        if not isinstance(pr, dict):
                            continue
                        name = pr.get("name")
                        loc = pr.get("in", "")
                        if isinstance(name, str) and name:
                            params.append((pth, name, str(loc)))

    comps = doc.get("components") if isinstance(doc, dict) else None
    if isinstance(comps, dict):
        sec = comps.get("securitySchemes")
        if isinstance(sec, dict):
            for name, scheme in sec.items():
                if not isinstance(scheme, dict):
                    continue
                typ = str(scheme.get("type", "")).lower()
                if typ:
                    auth.add(typ)
                if str(scheme.get("scheme", "")).lower():
                    auth.add(str(scheme.get("scheme", "")).lower())
                if str(name):
                    auth.add(str(name).lower())
    return endpoints, params, auth


def parse_openapi_yaml_fallback(spec_text: str) -> tuple[set[str], list[tuple[str, str, str]], set[str]]:
    text = spec_text or ""
    if "paths:" not in text:
        return set(), [], set()
    endpoints: set[str] = set()
    params: list[tuple[str, str, str]] = []
    auth: set[str] = set()

    current_path = ""
    current_name = ""
    current_in = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        m_path = re.match(r"^\s{0,6}(/[^:\s]+)\s*:\s*$", line)
        if m_path:
            current_path = m_path.group(1)
            endpoints.add(current_path)
            continue
        m_name = re.match(r"^\s*name\s*:\s*([A-Za-z0-9_\-\.]+)\s*$", line)
        if m_name:
            current_name = m_name.group(1)
            continue
        m_in = re.match(r"^\s*in\s*:\s*([A-Za-z0-9_\-]+)\s*$", line)
        if m_in:
            current_in = m_in.group(1)
            if current_path and current_name:
                params.append((current_path, current_name, current_in))
                current_name = ""
                current_in = ""
            continue
        if re.search(r"(?i)\bsecuritySchemes\b", line):
            auth.add("securityschemes")
        m_type = re.match(r"^\s*type\s*:\s*([A-Za-z0-9_\-]+)\s*$", line)
        if m_type and "security" in text.lower():
            auth.add(m_type.group(1).lower())
        m_scheme = re.match(r"^\s*scheme\s*:\s*([A-Za-z0-9_\-]+)\s*$", line)
        if m_scheme:
            auth.add(m_scheme.group(1).lower())

    return endpoints, params, auth


def score_openapi_presence(spec_url: str, endpoints_count: int) -> Finding:
    score = 55
    if endpoints_count >= 80:
        score = 70
    if endpoints_count >= 200:
        score = 80
    return Finding(
        title="OpenAPI/Swagger spec terdeteksi",
        category="ApiSpec",
        severity=severity_from_score(score),
        score=score,
        evidence=f"paths={endpoints_count}",
        url=spec_url,
        explanation="Spec API yang terbuka mempercepat mapping endpoint/parameter dan biasanya jadi sumber terbaik untuk triage cepat.",
    )


def rank_parameters_from_refs(base_url: str, refs: list[tuple[str, str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for path, name, loc in refs:
        key = (path, name)
        if key in seen:
            continue
        seen.add(key)
        idor, ssrf, redir = score_param(name, "")
        score = max(idor, ssrf, redir)
        if score < 20:
            continue
        label = "Parameter menarik"
        if idor >= ssrf and idor >= redir and idor >= 40:
            label = "Parameter rawan IDOR"
        elif ssrf >= idor and ssrf >= redir and ssrf >= 40:
            label = "Parameter rawan SSRF"
        elif redir >= 40:
            label = "Parameter rawan Open Redirect"
        sev = severity_from_score(score)
        findings.append(
            Finding(
                title=f"{label}: {name}",
                category="SmartParameterRanking",
                severity=sev,
                score=score,
                evidence=f"from_openapi in={loc} IDOR={idor} SSRF={ssrf} Redirect={redir}",
                url=urljoin(base_url + "/", path.lstrip("/")),
                explanation=explain_param(name, idor, ssrf, redir),
            )
        )
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings[:60]


def detect_internal_indicators(text: str) -> set[str]:
    indicators: set[str] = set()
    for m in re.finditer(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b", text):
        indicators.add(m.group(0))
    for m in re.finditer(r"\b[a-zA-Z0-9.-]+\.(?:local|internal|corp|lan)\b", text):
        indicators.add(m.group(0))
    return indicators


SECRET_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 95),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), 85),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), 90),
    ("JWT", re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"), 60),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----"), 100),
    ("Bearer Token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{24,}\b"), 75),
    ("Basic Auth", re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{24,}\b"), 70),
]


def detect_secrets(text: str, source_url: str) -> list[Finding]:
    out: list[Finding] = []
    for name, pat, score in SECRET_PATTERNS:
        for m in pat.finditer(text):
            sample = m.group(0)
            sev = severity_from_score(score)
            out.append(
                Finding(
                    title=f"{name} pattern terdeteksi",
                    category="Secrets",
                    severity=sev,
                    score=score,
                    evidence=sample[:120],
                    url=source_url,
                    explanation=explain_secret(name),
                )
            )
    return out


def explain_secret(name: str) -> str:
    if name == "AWS Access Key":
        return "String ini mirip AWS access key. Jika valid, attacker bisa akses resource cloud tanpa izin."
    if name == "Google API Key":
        return "String ini mirip Google API key. Jika tidak direstrict, bisa disalahgunakan untuk billing/akses API."
    if name == "Slack Token":
        return "Token Slack yang bocor sering memberi akses ke workspace/bot API."
    if name == "Private Key":
        return "Private key tidak boleh ada di client-side. Ini berpotensi full compromise."
    if name == "JWT":
        return "Terlihat seperti JWT. Jika ini token aktif yang terekspos, attacker bisa impersonate user."
    if name == "Bearer Token":
        return "Terlihat ada bearer token hardcoded. Jika masih valid, ini bisa jadi akses langsung tanpa login."
    if name == "Basic Auth":
        return "Terlihat ada Basic auth credential base64. Jika valid, ini bisa memberi akses endpoint secara langsung."
    return "Terlihat seperti secret/token yang terekspos di client-side."


def high_entropy_strings(text: str, *, min_len: int = 24, min_entropy: float = 4.0, max_hits: int = 20) -> list[str]:
    hits: list[tuple[float, str]] = []
    for m in re.finditer(r"(['\"])([^'\"\n\r]{%d,})\1" % min_len, text):
        s = m.group(2)
        if len(s) > 250:
            continue
        ent = shannon_entropy(s)
        if ent >= min_entropy and re.search(r"[A-Za-z0-9]", s):
            hits.append((ent, s))
    hits.sort(key=lambda x: x[0], reverse=True)
    uniq: list[str] = []
    seen: set[str] = set()
    for _, s in hits:
        if s in seen:
            continue
        seen.add(s)
        uniq.append(s)
        if len(uniq) >= max_hits:
            break
    return uniq


def score_param(name: str, value: str) -> tuple[int, int, int]:
    n = name.lower()
    v = (value or "").strip()

    idor = 0
    ssrf = 0
    redir = 0

    if re.search(r"(?:^|_)(?:id|uid|user_id|userid|accountid|account_id|member_id|order_id|invoice_id|role|role_id)(?:$|_)", n):
        idor += 55
    if re.search(r"(?:^|_)(?:role|permission|scope)(?:$|_)", n):
        idor += 20
    if re.fullmatch(r"\d{1,10}", v):
        idor += 20
    if re.search(r"(?:^|_)(?:url|uri|dest|destination|host|domain|callback|return_url|returnurl|next|continue|redirect)(?:$|_)", n):
        ssrf += 45
        redir += 45
    if re.search(r"(?:^|_)(?:path|file|template)(?:$|_)", n):
        ssrf += 15
    if re.match(r"^https?://", v, flags=re.I) or re.match(r"^//", v):
        ssrf += 25
        redir += 30
    if v.startswith(("/", "\\\\")):
        redir += 10
    if re.search(r"\b(?:127\.0\.0\.1|localhost|169\.254\.169\.254)\b", v):
        ssrf += 35

    return min(idor, 100), min(ssrf, 100), min(redir, 100)


def explain_param(name: str, idor: int, ssrf: int, redir: int) -> str:
    if idor >= ssrf and idor >= redir and idor >= 40:
        return (
            "Parameter ini terlihat seperti object reference (mis. user_id/accountId). "
            "Jika aplikasi tidak memvalidasi ownership/authorization, ini sering berujung IDOR."
        )
    if ssrf >= idor and ssrf >= redir and ssrf >= 40:
        return (
            "Parameter ini terlihat mengontrol target URL/host. "
            "Jika server melakukan fetch/redirect internal tanpa allowlist, ini bisa SSRF."
        )
    if redir >= 40:
        return (
            "Parameter ini terlihat mengontrol redirect/next/callback. "
            "Tanpa validasi origin/allowlist, ini rawan open redirect/phishing."
        )
    return "Parameter ini menarik untuk ditriage, tapi indikasi risikonya masih moderat."


def rank_parameters(urls: Iterable[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for u in urls:
        try:
            parts = urlsplit(u)
        except Exception:
            continue
        qs = parse_qsl(parts.query, keep_blank_values=True)
        for name, value in qs:
            key = (parts.path, name)
            if key in seen:
                continue
            seen.add(key)
            idor, ssrf, redir = score_param(name, value)
            score = max(idor, ssrf, redir)
            if score < 20:
                continue
            label = "Parameter menarik"
            if idor >= ssrf and idor >= redir and idor >= 40:
                label = "Parameter rawan IDOR"
            elif ssrf >= idor and ssrf >= redir and ssrf >= 40:
                label = "Parameter rawan SSRF"
            elif redir >= 40:
                label = "Parameter rawan Open Redirect"
            sev = severity_from_score(score)
            findings.append(
                Finding(
                    title=f"{label}: {name}",
                    category="SmartParameterRanking",
                    severity=sev,
                    score=score,
                    evidence=f"IDOR={idor} SSRF={ssrf} Redirect={redir}",
                    url=u,
                    explanation=explain_param(name, idor, ssrf, redir),
                )
            )
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings[:40]


def probe_common_paths(base_url: str, *, timeout: float, insecure: bool) -> list[Finding]:
    paths = [
        "/admin",
        "/admin/",
        "/administrator",
        "/login",
        "/wp-admin",
        "/graphql",
        "/api/graphql",
        "/graphiql",
        "/swagger",
        "/swagger-ui",
        "/swagger-ui/",
        "/api-docs",
        "/docs",
        "/.well-known/openid-configuration",
    ]
    findings: list[Finding] = []
    for p in paths:
        url = urljoin(base_url + "/", p.lstrip("/"))
        res = fetch(url, timeout=timeout, insecure=insecure, max_bytes=180_000)
        if not res:
            continue
        if res.status in {200, 401, 403, 302, 301}:
            title = f"Surface: {p} ({res.status})"
            score = 25
            cat = "AttackSurface"
            exp = "Path umum yang sering memuat panel admin, API, atau dokumentasi. Layak ditriage cepat."
            if p.startswith(("/admin", "/administrator", "/wp-admin")) and res.status in {200, 302}:
                score = 70
                exp = "Terlihat ada route admin. Jika bisa diakses tanpa boundary yang jelas, risk meningkat."
            if p.startswith(("/admin", "/administrator", "/wp-admin")) and res.status in {401, 403}:
                score = 60
                title = f"Admin panel kemungkinan internal ({res.status})"
                exp = "Route admin terdeteksi tapi akses dibatasi. Ini sering menandakan panel internal atau auth boundary yang perlu ditest."
            if "swagger" in p or "api-docs" in p:
                score = 55 if res.status == 200 else 35
                exp = "Dokumentasi API sering membuka peta endpoint dan model data. Jika publik, ini mempercepat abuse."
            if "openid-configuration" in p and res.status == 200:
                score = 30
                exp = "OIDC discovery terdeteksi. Berguna untuk memahami auth boundary dan issuer."
            findings.append(
                Finding(
                    title=title,
                    category=cat,
                    severity=severity_from_score(score),
                    score=score,
                    evidence=f"status={res.status} content-type={res.headers.get('content-type','')}",
                    url=res.url,
                    explanation=exp,
                )
            )
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings


def identify_infra(headers: dict[str, str]) -> list[str]:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    out: list[str] = []
    server = h.get("server", "")
    via = h.get("via", "")
    if "cloudflare" in server.lower() or "cf-ray" in h:
        out.append("CDN/WAF: Cloudflare")
    if "akamai" in server.lower() or "akamai" in via.lower() or "akamai" in h.get("x-akamai-transformed", "").lower():
        out.append("CDN/WAF: Akamai")
    if "fastly" in server.lower() or "fastly" in via.lower():
        out.append("CDN: Fastly")
    if h.get("x-powered-by"):
        out.append(f"X-Powered-By: {h.get('x-powered-by')}")
    if server:
        out.append(f"Server: {server}")
    return out[:6]


def probe_weak_auth_endpoints(base_url: str, urls: Iterable[str], *, timeout: float, insecure: bool) -> list[Finding]:
    candidates: list[str] = []
    seen_paths: set[str] = set()
    for u in urls:
        if not is_same_site(base_url, u):
            continue
        try:
            p = urlsplit(u).path or "/"
        except Exception:
            continue
        if "/api" not in p and not p.startswith("/graphql"):
            continue
        if p in seen_paths:
            continue
        seen_paths.add(p)
        candidates.append(u)
        if len(candidates) >= 12:
            break

    findings: list[Finding] = []
    for u in candidates:
        res = fetch(u, timeout=timeout, insecure=insecure, max_bytes=450_000)
        if not res:
            continue
        ct = (res.headers.get("content-type", "") or "").lower()
        if res.status != 200:
            continue
        body = ""
        try:
            body = res.body.decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        if "application/json" not in ct and not body.lstrip().startswith(("{", "[")):
            continue
        score = 55
        evidence = f"status=200 ct={ct}"
        if re.search(r"(?i)\b(password|secret|api_key|access_token|refresh_token)\b", body):
            score = 85
            evidence = "indikator field sensitif ditemukan pada response JSON"
        findings.append(
            Finding(
                title="Endpoint dengan auth lemah (public JSON)",
                category="AuthTriage",
                severity=severity_from_score(score),
                score=score,
                evidence=evidence,
                url=res.url,
                explanation="Endpoint mengembalikan JSON tanpa kredensial yang kita kirim. Jika seharusnya protected, ini indikasi auth lemah/IDOR.",
            )
        )
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings


def graphql_introspection(base_url: str, graphql_url: str, *, timeout: float, insecure: bool) -> Optional[Finding]:
    query = {"query": "query Introspection{__schema{types{name}}}"}
    data = json.dumps(query).encode("utf-8")
    res = fetch(
        graphql_url,
        method="POST",
        data=data,
        headers={"Content-Type": "application/json"},
        timeout=timeout,
        insecure=insecure,
        max_bytes=600_000,
    )
    if not res:
        return None
    body_text = ""
    try:
        body_text = res.body.decode("utf-8", errors="ignore")
    except Exception:
        body_text = ""
    if res.status in {200, 400} and "__schema" in body_text:
        score = 70
        return Finding(
            title="GraphQL menarik: introspection kemungkinan aktif",
            category="GraphQL",
            severity=severity_from_score(score),
            score=score,
            evidence="__schema ditemukan pada response introspection",
            url=res.url,
            explanation="Jika introspection aktif di produksi, attacker bisa enumerate schema untuk triage dan exploit lebih cepat.",
        )
    if res.status in {200, 400} and ("graphql" in body_text.lower() or "errors" in body_text.lower()):
        score = 45
        return Finding(
            title="GraphQL menarik: endpoint terdeteksi",
            category="GraphQL",
            severity=severity_from_score(score),
            score=score,
            evidence=f"status={res.status}",
            url=res.url,
            explanation="GraphQL menarik karena sering punya surface kompleks (auth per field, batching, query depth).",
        )
    return None


def analyze_js_blob(base_url: str, js_url: str, js_text: str) -> tuple[set[str], list[Finding], list[Finding], set[str]]:
    urls = extract_urls_from_text(base_url, js_text)
    secrets = detect_secrets(js_text, js_url)
    entropy_hits = high_entropy_strings(js_text)
    entropy_findings: list[Finding] = []
    for s in entropy_hits:
        score = 55
        entropy_findings.append(
            Finding(
                title="JS file high entropy",
                category="JSIntelligence",
                severity=severity_from_score(score),
                score=score,
                evidence=s[:120],
                url=js_url,
                explanation="String high-entropy sering berupa token, key, atau payload terenkripsi yang layak dicek sebagai secret/leak.",
            )
        )
    internal = detect_internal_indicators(js_text)
    internal_findings: list[Finding] = []
    for ind in sorted(internal)[:20]:
        score = 35
        internal_findings.append(
            Finding(
                title="Indikator internal ditemukan di JS",
                category="JSIntelligence",
                severity=severity_from_score(score),
                score=score,
                evidence=ind,
                url=js_url,
                explanation="Domain/IP internal di client-side bisa mengindikasikan environment internal atau SSRF pivot target.",
            )
        )
    return urls, secrets, entropy_findings + internal_findings, internal


def build_visual_tree_text(state: ReconState, findings: list[Finding]) -> str:
    lines: list[str] = [f"{state.base_url}"]

    def add_section(title: str, items: list[str]) -> None:
        lines.append(f"|- {title}")
        for it in items:
            lines.append(f"|  - {it}")

    add_section("Attack Surface", [f"[{f.severity}] {f.title}" for f in state.surface_findings[:8]])
    add_section("JS Intelligence", [f"[{f.severity}] {f.title}" for f in (state.secrets + [x for x in findings if x.category == "JSIntelligence"])[:10]])
    add_section("Smart Parameters", [f"[{f.severity}] {f.title}" for f in state.param_findings[:10]])
    add_section("GraphQL", [f"[{f.severity}] {f.title}" for f in state.graphql_findings[:5]])
    return "\n".join(lines)


def build_visual_tree(state: ReconState, findings: list[Finding]) -> Tree:
    t = Tree(f"[bold cyan]{state.base_url}[/bold cyan]")
    surface = t.add("[bold]Attack Surface[/bold]")
    js = t.add("[bold]JS Intelligence[/bold]")
    params = t.add("[bold]Smart Parameters[/bold]")
    gql = t.add("[bold]GraphQL[/bold]")

    for f in state.surface_findings[:8]:
        surface.add(Text(f"[{f.severity}] {f.title}", style=severity_style(f.severity)))
    for f in (state.secrets + [x for x in findings if x.category == "JSIntelligence"])[:10]:
        js.add(Text(f"[{f.severity}] {f.title}", style=severity_style(f.severity)))
    for f in state.param_findings[:10]:
        params.add(Text(f"[{f.severity}] {f.title}", style=severity_style(f.severity)))
    for f in state.graphql_findings[:5]:
        gql.add(Text(f"[{f.severity}] {f.title}", style=severity_style(f.severity)))
    return t


def render_summary(state: ReconState, findings: list[Finding]) -> None:
    total_urls = len(state.discovered_urls)
    js_count = len(state.js_urls)
    endpoint_count = len(state.endpoints_from_js)
    high = sum(1 for f in findings if f.severity in {"CRITICAL", "HIGH"})

    grid = Table.grid(expand=True)
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_row(
        f"[bold cyan]URLs[/bold cyan]\n[white]{total_urls}[/white]",
        f"[bold green]JS Files[/bold green]\n[white]{js_count}[/white]",
        f"[bold yellow]Endpoints(JS)[/bold yellow]\n[white]{endpoint_count}[/white]",
        f"[bold red]High+[/bold red]\n[white]{high}[/white]",
    )
    console.print(Panel(grid, title="[bold]ReconAI Metrics[/bold]", border_style="cyan", box=BOX_STYLE))


def render_findings(findings: list[Finding], *, title: str) -> None:
    table = Table(title=title, box=BOX_STYLE, border_style="red")
    table.add_column("Severity", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Title", style="white")
    table.add_column("Evidence", style="cyan")
    table.add_column("URL", style="green")
    for f in findings[:30]:
        ev = (f.evidence or "").replace("\n", " ")
        if len(ev) > 70:
            ev = ev[:67] + "..."
        u = f.url or ""
        if len(u) > 60:
            u = u[:57] + "..."
        table.add_row(Text(f.severity, style=severity_style(f.severity)), str(f.score), f.title, ev, u)
    console.print(table)


def render_quick_triage(findings: list[Finding]) -> None:
    buckets: list[tuple[str, list[Finding]]] = []
    buckets.append(("Admin panel kemungkinan internal", [f for f in findings if f.title.startswith("Admin panel kemungkinan internal")]))
    buckets.append(("Endpoint dengan auth lemah", [f for f in findings if f.category == "AuthTriage"]))
    buckets.append(("GraphQL menarik", [f for f in findings if f.category == "GraphQL"]))
    buckets.append(("Parameter rawan IDOR/SSRF/Redirect", [f for f in findings if f.category == "SmartParameterRanking"]))
    buckets.append(("JS file high entropy", [f for f in findings if f.title == "JS file high entropy"]))
    buckets.append(("API shadow endpoints", [f for f in findings if f.title.startswith("API shadow endpoints")]))

    table = Table(title="Quick Triage", box=BOX_STYLE, border_style="cyan")
    table.add_column("Kategori", style="white")
    table.add_column("Count", justify="right")
    table.add_column("Top", style="green")
    table.add_column("Severity", justify="center")
    table.add_column("Score", justify="right")
    for name, items in buckets:
        if not items:
            continue
        items_sorted = sorted(items, key=lambda f: f.score, reverse=True)
        top = items_sorted[0]
        top_text = top.title
        if top.url:
            top_text = f"{top_text}  ({top.url})"
        if len(top_text) > 80:
            top_text = top_text[:77] + "..."
        table.add_row(name, str(len(items)), top_text, Text(top.severity, style=severity_style(top.severity)), str(top.score))
    console.print(table)


def render_explanations(findings: list[Finding]) -> None:
    top = [f for f in findings if f.explanation][:8]
    if not top:
        return
    out = Text()
    for f in top:
        out.append(f"[{f.severity}] ", style=severity_style(f.severity))
        out.append(f"{f.title}\n", style="bold white")
        out.append(f"{f.explanation}\n", style="white")
        if f.url:
            out.append("URL: ", style="dim")
            out.append(f"{f.url}\n", style="dim cyan")
        if f.evidence:
            out.append("Evidence: ", style="dim")
            out.append(f"{f.evidence}\n", style="dim yellow")
        out.append("\n")
    console.print(Panel(out, title="AI Explanation", border_style="magenta", box=BOX_STYLE))


def render_infra_hints(lines: list[str]) -> None:
    out = Text()
    for line in lines:
        if line.startswith("CDN/WAF:") or line.startswith("CDN:"):
            out.append(line + "\n", style="bold cyan")
        elif line.startswith("X-Powered-By:"):
            out.append(line + "\n", style="bold yellow")
        elif line.startswith("Server:"):
            out.append(line + "\n", style="dim white")
        else:
            out.append(line + "\n", style="white")
    console.print(Panel(out, title="Infra Hints", border_style="cyan", box=BOX_STYLE))


def render_subdomains_section(subdomains: set[str], live: dict[str, int]) -> None:
    if not subdomains:
        return
    rows: list[tuple[int, str, int]] = []
    for host in subdomains:
        status = int(live.get(host, 0) or 0)
        score, _ = score_subdomain(host, status)
        rows.append((score, host, status))
    rows.sort(key=lambda x: x[0], reverse=True)

    table = Table(title="Subdomains", box=BOX_STYLE, border_style="cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Subdomain", style="white")
    table.add_column("Live", justify="right")
    for score, host, status in rows[:60]:
        sev = severity_from_score(score)
        live_txt = str(status) if status else "-"
        table.add_row(Text(sev, style=severity_style(sev)), str(score), host, live_txt)
    console.print(table)


def run_recon(target: str, *, profile: str, timeout: float, insecure: bool, max_js: int, workers: int) -> int:
    candidate = normalize_target(target)
    base_url = pick_working_base_url(candidate, timeout=timeout, insecure=insecure)
    base_host = urlparse(base_url).netloc.lower()
    root_domain = normalize_domain_only(base_url)
    state = ReconState(base_url=base_url)
    state.discovered_urls.add(base_url)

    banner = BANNER if supports_unicode_banner() else BANNER_ASCII
    console.print(Text(banner + "\n", style="bold cyan"))
    console.print("[bold cyan]ReconAI[/bold cyan]")
    console.print(f"[bold white]ReconAI Triage[/bold white]  profile={profile}\n")
    console.print(f"[bold green]Target[/bold green] {base_url}\n")
    js_intel_findings: list[Finding] = []
    internal_seen: set[str] = set()
    openapi_findings: list[Finding] = []
    openapi_param_refs: list[tuple[str, str, str]] = []
    openapi_endpoints: set[str] = set()
    shadow_endpoints: list[Finding] = []

    with console.status("[bold cyan]Scanning...[/bold cyan]", spinner="line") as status:
        status.update("[bold cyan]Resolving target & fetching root...[/bold cyan]")
        root = fetch(base_url, timeout=timeout, insecure=insecure, max_bytes=1_500_000)
        html_text = ""
        if root and root.body:
            html_text = root.body.decode("utf-8", errors="ignore")
        if root:
            state.notes.extend(identify_infra(root.headers))

        links, scripts, forms, inline_scripts = parse_html_for_assets(base_url, html_text)
        extracted_from_root = extract_urls_from_text(base_url, html_text)
        for blob in inline_scripts:
            extracted_from_root |= extract_urls_from_text(base_url, blob)
        state.discovered_urls |= extracted_from_root
        if profile in {"full", "deep"} and root_domain:
            state.subdomains |= extract_subdomains_from_text(root_domain, html_text)
            for blob in inline_scripts:
                state.subdomains |= extract_subdomains_from_text(root_domain, blob)

        for u in links.union(forms):
            if is_same_site(base_url, u):
                state.html_urls.add(u)
                state.discovered_urls.add(u)
        for s in scripts:
            try:
                host = urlparse(s).netloc.lower()
            except Exception:
                host = ""
            if not host or is_related_host(base_host, host):
                state.js_urls.add(s)
                state.discovered_urls.add(s)

        if profile in {"full", "deep", "api", "javascript"}:
            status.update("[bold cyan]Probing common attack-surface paths...[/bold cyan]")
            state.surface_findings.extend(probe_common_paths(base_url, timeout=timeout, insecure=insecure))
            for f in state.surface_findings:
                state.discovered_urls.add(f.url)

        if profile in {"full", "deep"} and root_domain:
            status.update("[bold cyan]Enumerating subdomains (OSINT + DNS)...[/bold cyan]")
            subs: set[str] = set()
            subs |= certspotter_subdomains(root_domain, timeout=timeout, insecure=insecure)
            subs |= crtsh_subdomains(root_domain, timeout=timeout, insecure=insecure)
            subs |= bufferover_subdomains(root_domain, timeout=timeout, insecure=insecure)
            subs |= rapiddns_subdomains(root_domain, timeout=timeout, insecure=insecure)
            subs |= bruteforce_subdomains(root_domain, timeout=timeout, insecure=insecure, max_hits=80)
            subs |= extract_subdomains_from_urls(root_domain, state.discovered_urls)
            subs |= extract_subdomains_from_urls(root_domain, (f.url for f in state.surface_findings))
            subs = {s for s in subs if s and s != root_domain}
            state.subdomains |= subs
            status.update("[bold cyan]Probing live subdomains...[/bold cyan]")
            state.live_subdomains |= probe_live_hosts(subs, timeout=timeout, insecure=insecure, max_hosts=40)
            state.notes.append(f"Subdomains: {len(state.subdomains)} (live: {len(state.live_subdomains)})")

        status.update("[bold cyan]Crawling HTML & collecting assets...[/bold cyan]")
        crawl_depth = 1 if profile in {"full", "deep"} else 0
        crawl_pages = 18 if profile in {"full", "deep"} else 8
        crawled_html, crawled_js, crawled_inline, crawled_urls = crawl_html(
            base_url,
            [base_url] + list(state.html_urls)[:8] + [f.url for f in state.surface_findings[:6]],
            timeout=timeout,
            insecure=insecure,
            max_depth=crawl_depth,
            max_pages=crawl_pages,
        )
        state.html_urls |= crawled_html
        state.js_urls |= crawled_js
        state.discovered_urls |= crawled_html | crawled_js | crawled_urls
        if profile in {"full", "deep"} and root_domain:
            state.subdomains |= extract_subdomains_from_urls(root_domain, crawled_urls)
            state.subdomains |= extract_subdomains_from_urls(root_domain, crawled_js)
            for blob in crawled_inline[:40]:
                state.subdomains |= extract_subdomains_from_text(root_domain, blob)

        js_to_fetch = list(state.js_urls)[:max_js] if profile in {"full", "deep", "javascript"} else []
        js_texts: dict[str, str] = {}
        if js_to_fetch:
            status.update("[bold cyan]Fetching JavaScript bundles...[/bold cyan]")
            with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
                futs = {
                    ex.submit(fetch, u, timeout=timeout, insecure=insecure, max_bytes=2_000_000): u for u in js_to_fetch
                }
                for fut in as_completed(futs):
                    u = futs[fut]
                    res = None
                    try:
                        res = fut.result()
                    except Exception:
                        res = None
                    if not res or not res.body:
                        continue
                    js_texts[u] = res.body.decode("utf-8", errors="ignore")

        status.update("[bold cyan]Analyzing JS intelligence...[/bold cyan]")
        for js_url, js_text in js_texts.items():
            endpoints, secrets, intel, internal = analyze_js_blob(base_url, js_url, js_text)
            for u in endpoints:
                if is_same_site(base_url, u):
                    state.endpoints_from_js.add(u)
                    state.discovered_urls.add(u)
            state.secrets.extend(secrets)
            js_intel_findings.extend(intel)
            internal_seen |= internal
            if profile in {"full", "deep"} and root_domain:
                state.subdomains |= extract_subdomains_from_text(root_domain, js_text)

        if profile in {"full", "deep", "javascript"}:
            for idx, blob in enumerate(crawled_inline[:25]):
                pseudo = f"{base_url}#inline-{idx+1}"
                endpoints, secrets, intel, internal = analyze_js_blob(base_url, pseudo, blob)
                for u in endpoints:
                    if is_same_site(base_url, u):
                        state.endpoints_from_js.add(u)
                        state.discovered_urls.add(u)
                state.secrets.extend(secrets)
                js_intel_findings.extend(intel)
                internal_seen |= internal
        if profile in {"full", "deep"} and root_domain:
            state.subdomains |= extract_subdomains_from_urls(root_domain, state.endpoints_from_js)

        if state.endpoints_from_js:
            html_set = {urlsplit(u).path for u in state.html_urls}
            for u in sorted(state.endpoints_from_js):
                p = urlsplit(u).path
                if p and p not in html_set:
                    score = 40
                    shadow_endpoints.append(
                        Finding(
                            title="API shadow endpoints (hanya dari JS)",
                            category="JSIntelligence",
                            severity=severity_from_score(score),
                            score=score,
                            evidence=p,
                            url=u,
                            explanation="Endpoint ini muncul di JavaScript tapi tidak terlihat di HTML. Sering jadi surface tersembunyi atau internal feature flag.",
                        )
                    )
                if len(shadow_endpoints) >= 15:
                    break

        if profile in {"full", "deep", "api"}:
            status.update("[bold cyan]Detecting OpenAPI/Swagger specs...[/bold cyan]")
            spec_urls: set[str] = set(openapi_candidate_urls(base_url))
            for f in state.surface_findings:
                if any(k in f.url for k in ("/swagger", "/swagger-ui", "/api-docs", "/docs")):
                    res = fetch(f.url, timeout=timeout, insecure=insecure, max_bytes=700_000)
                    if res and res.body and is_html_content_type(res.headers.get("content-type", "")):
                        spec_urls |= extract_openapi_urls_from_html(base_url, decode_bytes(res.body))
            for spec_url in list(spec_urls)[:10]:
                res = fetch(spec_url, timeout=timeout, insecure=insecure, max_bytes=2_000_000)
                if not res or not res.body:
                    continue
                text = decode_bytes(res.body)
                endpoints, param_refs, auth_schemes = parse_openapi_spec(text)
                if not endpoints:
                    continue
                openapi_findings.append(score_openapi_presence(res.url, len(endpoints)))
                if auth_schemes:
                    openapi_findings.append(
                        Finding(
                            title="Auth scheme terdeteksi dari OpenAPI",
                            category="ApiSpec",
                            severity=severity_from_score(45),
                            score=45,
                            evidence=", ".join(sorted(auth_schemes))[:140],
                            url=res.url,
                            explanation="Auth scheme dari OpenAPI membantu fokus: bearer/jwt/apiKey sering jadi target uji (misconfig, scope, permission).",
                        )
                    )
                for pth in endpoints:
                    openapi_endpoints.add(urljoin(base_url + "/", str(pth).lstrip("/")))
                openapi_param_refs.extend(param_refs)
                break
            if root_domain:
                state.subdomains |= extract_subdomains_from_urls(root_domain, openapi_endpoints)

    if profile in {"full", "deep", "api", "javascript"}:
        candidate_urls = set(state.discovered_urls) | set(state.endpoints_from_js)
        state.param_findings = rank_parameters(candidate_urls)
        if openapi_param_refs:
            state.param_findings = (state.param_findings + rank_parameters_from_refs(base_url, openapi_param_refs))[:80]

    auth_findings: list[Finding] = []
    if profile in {"full", "deep", "api"}:
        auth_findings = probe_weak_auth_endpoints(
            base_url,
            list(state.endpoints_from_js) + list(openapi_endpoints) + list(state.html_urls),
            timeout=timeout,
            insecure=insecure,
        )

    if profile in {"full", "deep", "api"}:
        gql_candidates = []
        for p in ["/graphql", "/api/graphql"]:
            gql_candidates.append(urljoin(base_url + "/", p.lstrip("/")))
        for u in sorted(state.endpoints_from_js):
            if re.search(r"/graphql\b", u):
                gql_candidates.append(u)
        gql_unique = []
        seen_gql: set[str] = set()
        for u in gql_candidates:
            if u in seen_gql:
                continue
            seen_gql.add(u)
            gql_unique.append(u)
        for u in gql_unique[:5]:
            f = graphql_introspection(base_url, u, timeout=timeout, insecure=insecure)
            if f:
                state.graphql_findings.append(f)

    all_findings = (
        state.secrets
        + state.graphql_findings
        + state.surface_findings
        + openapi_findings
        + js_intel_findings
        + shadow_endpoints
        + auth_findings
        + state.param_findings
    )
    all_findings.sort(key=lambda f: f.score, reverse=True)

    render_summary(state, all_findings)
    if USE_ASCII_BOX:
        console.print(build_visual_tree_text(state, all_findings))
    else:
        console.print(build_visual_tree(state, all_findings))

    render_subdomains_section(state.subdomains, state.live_subdomains)
    render_quick_triage(all_findings)
    render_findings(all_findings, title="Prioritized Findings")
    render_explanations(all_findings)

    if internal_seen:
        console.print(
            Panel("\n".join(sorted(internal_seen)[:30]), title="Internal Indicators", border_style="blue", box=BOX_STYLE)
        )
    if state.notes:
        render_infra_hints(state.notes)

    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="reconai", add_help=True)
    p.add_argument("-d", "--domain", dest="domain", help="Target domain/URL (contoh: target.com atau https://target.com)")
    p.add_argument(
        "-p",
        "--profile",
        default="full",
        choices=["passive", "deep", "api", "javascript", "full"],
        help="Mode scanning/triage",
    )
    p.add_argument("--timeout", type=float, default=12.0, help="Timeout per request (detik)")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verify (jika HTTPS bermasalah)")
    p.add_argument("--max-js", type=int, default=12, help="Maksimum file JS yang didownload untuk analisis")
    p.add_argument("--workers", type=int, default=6, help="Jumlah worker concurrent untuk fetch JS")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if not args.domain:
        console.print("[red]Target belum diisi. Pakai: reconai -d target.com[/red]")
        return 2
    return run_recon(
        args.domain,
        profile=args.profile,
        timeout=args.timeout,
        insecure=args.insecure,
        max_js=max(0, args.max_js),
        workers=max(1, args.workers),
    )


if __name__ == "__main__":
    raise SystemExit(main())
