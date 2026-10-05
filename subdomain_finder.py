#!/usr/bin/env python3
"""
subdomain_finder.py

Orchestrates well-known subdomain enumeration tools over a list of root
domains (FQDNs), merges and de-duplicates the results, then probes which
discovered hosts are alive.

Usage:
    python3 subdomain_finder.py --subdomains FQDNS.txt --outfile subdomains.txt

Enumeration tools used (whichever are installed on PATH):
    findomain, subfinder, assetfinder, amass

Liveness probe (whichever is installed on PATH):
    httprobe   (default)   or   httpx

Only use this against assets you own or are explicitly authorized to test.
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
import os
import json
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------
# Each enumerator is a function that takes a single root domain and returns
# a set of discovered subdomains. We invoke the external binary and parse
# stdout (one host per line is the common convention for all of these).

def _run(cmd, timeout=600, stdin_data=None):
    """
    Run a command, return stdout as text. Never raise on tool failure.

    Hardened for fully unattended runs: each child is started in its own
    session with NO controlling terminal (start_new_session=True) and with
    stdin detached when we aren't feeding it data. If any tool tries to call
    `sudo`, it can't find a tty to prompt on, so it fails immediately
    ("sudo: no tty present...") instead of hanging the whole scan waiting
    for a password. We also strip SUDO_ASKPASS from the child env so sudo
    has no GUI/askpass fallback either.
    """
    env = dict(os.environ)
    env.pop("SUDO_ASKPASS", None)

    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            # detach stdin unless we're piping data in
            stdin=(subprocess.DEVNULL if stdin_data is None else None),
            capture_output=True,
            text=True,
            timeout=timeout,
            start_new_session=True,  # no controlling tty -> sudo can't prompt
            env=env,
        )
        return proc.stdout or ""
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"[!] timeout: {' '.join(cmd)}\n")
        return ""
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"[!] error running {cmd[0]}: {e}\n")
        return ""


def enum_findomain(domain):
    # -q = quiet (hosts only), -t = target
    out = _run(["findomain", "-q", "-t", domain])
    return _clean_lines(out, domain)


def enum_subfinder(domain):
    # -silent = hosts only, -d = domain
    out = _run(["subfinder", "-silent", "-d", domain])
    return _clean_lines(out, domain)


def enum_assetfinder(domain):
    # --subs-only limits output to subdomains of the target
    out = _run(["assetfinder", "--subs-only", domain])
    return _clean_lines(out, domain)


def enum_amass(domain):
    # passive mode keeps it fast and non-intrusive; drop -passive for more
    out = _run(["amass", "enum", "-passive", "-norecursive", "-d", domain],
               timeout=1200)
    return _clean_lines(out, domain)


ENUMERATORS = {
    "findomain": enum_findomain,
    "subfinder": enum_subfinder,
    "assetfinder": enum_assetfinder,
    "amass": enum_amass,
}


# ---------------------------------------------------------------------------
# Native (no-binary) sources — queried directly over HTTP, no API key needed
# ---------------------------------------------------------------------------
def _http_get(url, timeout=60, label="http"):
    """GET a URL and return the body as text, or '' on any failure."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "subdomain_finder/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        sys.stderr.write(f"[!] {label} request failed: {e}\n")
        return ""


def source_crtsh(domain, timeout=60):
    """
    crt.sh — Certificate Transparency logs (Sectigo).
    JSON endpoint: https://crt.sh/?q=%.example.com&output=json
    name_value / common_name may hold multiple newline-separated hostnames
    and wildcards like *.example.com.
    """
    raw = _http_get(f"https://crt.sh/?q=%25.{domain}&output=json",
                    timeout, label=f"crt.sh ({domain})")
    if not raw.strip():
        return set()

    try:
        records = json.loads(raw)
    except json.JSONDecodeError:
        # crt.sh occasionally returns concatenated JSON objects, not an array
        try:
            records = json.loads("[" + raw.replace("}\n{", "},{") + "]")
        except json.JSONDecodeError:
            sys.stderr.write(f"[!] crt.sh returned unparseable data for "
                             f"{domain}\n")
            return set()

    names = []
    for rec in records:
        for field in ("name_value", "common_name"):
            names.extend((rec.get(field) or "").splitlines())
    return _clean_lines("\n".join(names).replace("*.", ""), domain)


def source_certspotter(domain, timeout=60):
    """
    Certspotter (SSLMate) — a different CT log operator than crt.sh, so it
    often surfaces certificates crt.sh misses. Keyless endpoint returns JSON
    objects each carrying a 'dns_names' array.
    """
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           f"&include_subdomains=true&expand=dns_names")
    raw = _http_get(url, timeout, label=f"certspotter ({domain})")
    if not raw.strip():
        return set()
    try:
        records = json.loads(raw)
    except json.JSONDecodeError:
        return set()

    names = []
    for rec in records:
        names.extend(rec.get("dns_names", []) or [])
    return _clean_lines("\n".join(names).replace("*.", ""), domain)


def source_hackertarget(domain, timeout=60):
    """
    HackerTarget hostsearch — passive DNS. Returns CSV lines 'hostname,ip'.
    Free with a daily rate limit; on limit it returns a plain-text error,
    which _clean_lines harmlessly filters out.
    """
    raw = _http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                    timeout, label=f"hackertarget ({domain})")
    if not raw.strip():
        return set()
    # take the hostname (first CSV field) from each line
    hosts = [line.split(",")[0] for line in raw.splitlines() if line.strip()]
    return _clean_lines("\n".join(hosts), domain)


def source_otx(domain, timeout=60):
    """
    AlienVault OTX passive DNS — keyless. Returns JSON with a 'passive_dns'
    array of observed hostname records.
    """
    url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
           f"{domain}/passive_dns")
    raw = _http_get(url, timeout, label=f"otx ({domain})")
    if not raw.strip():
        return set()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return set()

    names = [rec.get("hostname", "") for rec in data.get("passive_dns", [])]
    return _clean_lines("\n".join(names), domain)


NATIVE_SOURCES = {
    "crtsh": source_crtsh,
    "certspotter": source_certspotter,
    "hackertarget": source_hackertarget,
    "otx": source_otx,
}


def _strip_scheme(url):
    """Remove a leading http:// or https:// (and any trailing slash/path)."""
    host = url.strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    # drop anything after the host (path, query) but keep host:port
    host = host.split("/", 1)[0]
    return host


def _clean_lines(output, domain):
    """Normalize tool output into a clean set of hostnames."""
    hosts = set()
    for line in output.splitlines():
        host = line.strip().lower()
        if not host:
            continue
        # strip any scheme/port/path that a tool might emit
        host = host.split("//")[-1].split("/")[0].split(":")[0]
        # keep only things that actually belong to the target domain
        if host == domain or host.endswith("." + domain):
            hosts.add(host)
    return hosts


# ---------------------------------------------------------------------------
# Liveness probing
# ---------------------------------------------------------------------------
def probe_alive(hosts, prober, concurrency):
    """Feed hosts into httprobe/httpx and return the set that responded."""
    if not hosts:
        return set()

    stdin_data = "\n".join(sorted(hosts)) + "\n"

    if prober == "httprobe":
        # -c sets concurrency; outputs full URLs (http://host, https://host)
        cmd = ["httprobe", "-c", str(concurrency)]
    elif prober == "httpx":
        # -silent hosts-only; outputs probed URLs
        cmd = ["httpx", "-silent", "-threads", str(concurrency)]
    else:
        return set()

    out = _run(cmd, stdin_data=stdin_data, timeout=1800)
    return {line.strip() for line in out.splitlines() if line.strip()}


# ---------------------------------------------------------------------------
# Screenshotting
# ---------------------------------------------------------------------------
def screenshot_hosts(urls, outdir, timeout_per_batch=3600):
    """
    Screenshot the given URLs with gowitness. Writes a file of URLs to a
    temp path and hands it to gowitness, saving images (and a SQLite db /
    report) into `outdir`.

    gowitness changed its CLI between v2 and v3, so we detect which syntax
    the installed binary accepts and call accordingly.
    """
    if not urls:
        sys.stderr.write("[!] no live URLs to screenshot\n")
        return

    os.makedirs(outdir, exist_ok=True)

    # write the URL list to a temp file for gowitness to consume
    fd, url_file = tempfile.mkstemp(prefix="gowitness_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(urls)) + "\n")

        # detect v3 ("scan" subcommand) vs v2 ("file" subcommand)
        help_out = _run(["gowitness", "scan", "--help"], timeout=30)
        is_v3 = "file" in help_out or "scan" in help_out

        if is_v3:
            # gowitness v3: gowitness scan file -f urls.txt -s ./dir
            cmd = ["gowitness", "scan", "file",
                   "-f", url_file,
                   "-s", outdir]
        else:
            # gowitness v2: gowitness file -f urls.txt -P ./dir --no-http-server
            cmd = ["gowitness", "file",
                   "-f", url_file,
                   "-P", outdir]

        sys.stderr.write(f"[*] screenshotting {len(urls)} host(s) with "
                         f"gowitness ({'v3' if is_v3 else 'v2'} syntax)...\n")
        _run(cmd, timeout=timeout_per_batch)
        sys.stderr.write(f"[*] screenshots saved under {outdir}/\n")
    finally:
        try:
            os.remove(url_file)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def detect_tools(available):
    """Return the subset of tools actually installed on PATH."""
    return [name for name in available if shutil.which(name)]


def read_domains(path):
    with open(path, "r", encoding="utf-8") as fh:
        domains = []
        for line in fh:
            d = line.strip().lower()
            if not d or d.startswith("#"):
                continue
            # normalize in case someone pasted URLs
            d = d.split("//")[-1].split("/")[0].split(":")[0]
            domains.append(d)
    # dedupe, preserve nothing special about order
    return sorted(set(domains))


def enumerate_all(domains, tools, workers):
    """Run every (tool, domain) pair; return the merged set of subdomains."""
    found = set()
    # dispatch table combines binary tools and native HTTP sources
    registry = {**ENUMERATORS, **NATIVE_SOURCES}
    tasks = [(tool, domain) for tool in tools for domain in domains]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(registry[tool], domain): (tool, domain)
            for tool, domain in tasks
        }
        for fut in as_completed(futures):
            tool, domain = futures[fut]
            try:
                hosts = fut.result()
                sys.stderr.write(
                    f"[+] {tool:<12} {domain:<30} -> {len(hosts)} hosts\n"
                )
                found |= hosts
            except Exception as e:  # noqa: BLE001
                sys.stderr.write(f"[!] {tool} failed on {domain}: {e}\n")
    return found


def main():
    parser = argparse.ArgumentParser(
        description="Enumerate subdomains from a list of FQDNs and probe for "
                    "live hosts.",
    )
    parser.add_argument(
        "--subdomains", "-s", required=True, metavar="FILE",
        help="Input file: one root domain (FQDN) per line.",
    )
    parser.add_argument(
        "--outfile", "-o", required=True, metavar="FILE",
        help="Output file for the alive subdomains.",
    )
    parser.add_argument(
        "--all-file", metavar="FILE", default=None,
        help="Optional: also write ALL discovered subdomains (pre-probe).",
    )
    parser.add_argument(
        "--prober", choices=["httprobe", "httpx"], default="httprobe",
        help="Which liveness prober to use (default: httprobe).",
    )
    parser.add_argument(
        "--no-probe", action="store_true",
        help="Skip the liveness check; output all discovered subdomains.",
    )
    parser.add_argument(
        "--no-native", action="store_true",
        help="Disable built-in HTTP sources (crt.sh); use only installed "
             "binaries.",
    )
    parser.add_argument(
        "--screenshot", action="store_true",
        help="Screenshot every alive host with gowitness.",
    )
    parser.add_argument(
        "--screenshot-dir", metavar="DIR", default="screenshots",
        help="Directory for gowitness output (default: ./screenshots).",
    )
    parser.add_argument(
        "--workers", type=int, default=8,
        help="Parallel enumeration jobs (default: 8).",
    )
    parser.add_argument(
        "--concurrency", type=int, default=50,
        help="Concurrency passed to the prober (default: 50).",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.subdomains):
        sys.exit(f"[!] input file not found: {args.subdomains}")

    domains = read_domains(args.subdomains)
    if not domains:
        sys.exit("[!] no domains found in input file")
    sys.stderr.write(f"[*] {len(domains)} root domain(s) loaded\n")

    # --- pick the enumeration tools that are installed ---------------------
    binary_tools = detect_tools(ENUMERATORS.keys())

    # native HTTP sources (crt.sh, ...) need no binary and are always
    # available unless explicitly disabled.
    native = [] if args.no_native else list(NATIVE_SOURCES.keys())

    tools = binary_tools + native
    if not tools:
        sys.exit(
            "[!] no enumeration sources available.\n"
            "    Install at least one of: findomain, subfinder, "
            "assetfinder, amass\n"
            "    (or drop --no-native to use built-in sources like crt.sh)"
        )
    sys.stderr.write(f"[*] binary tools: "
                     f"{', '.join(binary_tools) or '(none)'}\n")
    sys.stderr.write(f"[*] native sources: "
                     f"{', '.join(native) or '(none)'}\n")

    # --- enumerate ---------------------------------------------------------
    all_subs = enumerate_all(domains, tools, args.workers)
    sys.stderr.write(f"[*] {len(all_subs)} unique subdomains discovered\n")

    if args.all_file:
        with open(args.all_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(all_subs)) + "\n")
        sys.stderr.write(f"[*] all subdomains written to {args.all_file}\n")

    # --- probe -------------------------------------------------------------
    if args.no_probe:
        results = {f"(unprobed) {h}" for h in all_subs}
        alive = sorted(all_subs)
    else:
        if not shutil.which(args.prober):
            sys.exit(
                f"[!] prober '{args.prober}' not installed. "
                f"Install it or rerun with --no-probe."
            )
        sys.stderr.write(f"[*] probing {len(all_subs)} hosts with "
                         f"{args.prober}...\n")
        alive = sorted(probe_alive(all_subs, args.prober, args.concurrency))
        sys.stderr.write(f"[*] {len(alive)} alive host(s)\n")

    # --- output ------------------------------------------------------------
    # Strip any http:// or https:// prefix for the output file, and dedupe
    # (a host answering on both schemes would otherwise appear twice).
    # Note: `alive` is kept intact with schemes for the screenshot stage.
    hostnames = sorted({_strip_scheme(h) for h in alive})
    with open(args.outfile, "w", encoding="utf-8") as fh:
        fh.write("\n".join(hostnames) + ("\n" if hostnames else ""))
    sys.stderr.write(f"[*] {len(hostnames)} host(s) written to "
                     f"{args.outfile}\n")

    # --- screenshot --------------------------------------------------------
    if args.screenshot:
        if not shutil.which("gowitness"):
            sys.stderr.write(
                "[!] gowitness not installed; skipping screenshots.\n"
                "    Install: go install "
                "github.com/sensepost/gowitness@latest\n"
            )
        elif args.no_probe:
            # unprobed hosts are bare hostnames, not URLs — prefix schemes
            urls = set()
            for h in alive:
                urls.add("http://" + h)
                urls.add("https://" + h)
            screenshot_hosts(urls, args.screenshot_dir)
        else:
            # httprobe/httpx already emit full URLs
            screenshot_hosts(set(alive), args.screenshot_dir)


if __name__ == "__main__":
    main()
