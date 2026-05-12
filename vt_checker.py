#!/usr/bin/env python3
"""
VirusTotal Target Checker
Accepts a file containing IPs, domains, URLs, or file hashes and queries
the VirusTotal API v3 for each.

Usage:
    python vt_checker.py -t targets.txt -k YOUR_API_KEY [-o results.json] [-v]

Requirements:
    pip install requests
"""

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse
import base64

def _ensure_requests():
    """Check for 'requests' and offer to install it if missing."""
    try:
        import requests  # noqa: F401
    except ImportError:
        print("[!] Required library 'requests' is not installed.")
        try:
            answer = input("    Install it now via pip? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Aborted.")
            sys.exit(1)
        if answer == "y":
            import subprocess
            print("[*] Installing 'requests'...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "requests"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print("[*] Installation successful.\n")
            else:
                print(f"[!] Installation failed:\n{result.stderr}")
                sys.exit(1)
        else:
            print("[!] Cannot continue without 'requests'. Exiting.")
            sys.exit(1)

_ensure_requests()
import requests  # noqa: E402 — imported after preflight


VT_BASE = "https://www.virustotal.com/api/v3"

# ── Type Detection ─────────────────────────────────────────────────────────────

IPV4_RE   = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE   = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
URL_RE    = re.compile(r"^https?://", re.IGNORECASE)

def detect_type(target: str) -> str:
    """Classify a target as ip, domain, url, or hash."""
    if IPV4_RE.match(target):
        return "ip"
    if MD5_RE.match(target) or SHA1_RE.match(target) or SHA256_RE.match(target):
        return "hash"
    if URL_RE.match(target):
        return "url"
    return "domain"


# ── VT API Calls ───────────────────────────────────────────────────────────────

def vt_get(endpoint: str, api_key: str) -> dict | None:
    """Perform a GET request against the VT API. Returns parsed JSON or None."""
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        resp = requests.get(f"{VT_BASE}{endpoint}", headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return None  # Not found in VT
        else:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
    except requests.RequestException as e:
        raise RuntimeError(str(e))


def query_ip(ip: str, api_key: str) -> dict:
    data = vt_get(f"/ip_addresses/{ip}", api_key)
    if not data:
        return {"error": "Not found in VirusTotal"}
    return data.get("data", {})


def query_domain(domain: str, api_key: str) -> dict:
    data = vt_get(f"/domains/{domain}", api_key)
    if not data:
        return {"error": "Not found in VirusTotal"}
    return data.get("data", {})


def query_url(url: str, api_key: str) -> dict:
    # VT URL lookups use a URL-safe base64-encoded identifier
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    data = vt_get(f"/urls/{url_id}", api_key)
    if not data:
        return {"error": "Not found in VirusTotal"}
    return data.get("data", {})


def query_hash(file_hash: str, api_key: str) -> dict:
    data = vt_get(f"/files/{file_hash}", api_key)
    if not data:
        return {"error": "Not found in VirusTotal"}
    return data.get("data", {})


# ── Result Parsing ─────────────────────────────────────────────────────────────

def parse_analysis_stats(stats: dict) -> dict:
    total     = sum(stats.values())
    malicious = stats.get("malicious", 0)
    suspicious= stats.get("suspicious", 0)
    return {
        "malicious":  malicious,
        "suspicious": suspicious,
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total":      total,
        "score":      f"{malicious + suspicious}/{total}" if total else "0/0",
    }


def flag_level(malicious: int, suspicious: int) -> str:
    if malicious >= 5:
        return "MALICIOUS"
    if malicious >= 1 or suspicious >= 3:
        return "SUSPICIOUS"
    return "CLEAN"


def parse_vendors(result_map: dict) -> list[dict]:
    """Return only vendors that flagged the target (malicious/suspicious)."""
    flagged = []
    for vendor, detail in result_map.items():
        cat = detail.get("category", "")
        if cat in ("malicious", "suspicious"):
            flagged.append({
                "vendor":   vendor,
                "category": cat,
                "result":   detail.get("result") or detail.get("verdict") or cat,
            })
    return sorted(flagged, key=lambda x: x["vendor"])


def format_ip_result(target: str, raw: dict) -> dict:
    if "error" in raw:
        return {"target": target, "type": "ip", "error": raw["error"]}

    attrs  = raw.get("attributes", {})
    stats  = parse_analysis_stats(attrs.get("last_analysis_stats", {}))
    flags  = parse_vendors(attrs.get("last_analysis_results", {}))

    return {
        "target":          target,
        "type":            "ip",
        "flag":            flag_level(stats["malicious"], stats["suspicious"]),
        "score":           stats["score"],
        "stats":           stats,
        "asn":             attrs.get("asn"),
        "org":             attrs.get("as_owner"),
        "country":         attrs.get("country"),
        "continent":       attrs.get("continent"),
        "network":         attrs.get("network"),
        "reputation":      attrs.get("reputation"),
        "categories":      attrs.get("categories", {}),
        "tags":            attrs.get("tags", []),
        "whois":           (attrs.get("whois") or "")[:500] or None,
        "last_analysis":   attrs.get("last_analysis_date"),
        "flagged_vendors": flags,
    }


def format_domain_result(target: str, raw: dict) -> dict:
    if "error" in raw:
        return {"target": target, "type": "domain", "error": raw["error"]}

    attrs  = raw.get("attributes", {})
    stats  = parse_analysis_stats(attrs.get("last_analysis_stats", {}))
    flags  = parse_vendors(attrs.get("last_analysis_results", {}))

    dns_records = attrs.get("last_dns_records", [])
    a_records   = [r["value"] for r in dns_records if r.get("type") == "A"]

    return {
        "target":          target,
        "type":            "domain",
        "flag":            flag_level(stats["malicious"], stats["suspicious"]),
        "score":           stats["score"],
        "stats":           stats,
        "registrar":       attrs.get("registrar"),
        "creation_date":   attrs.get("creation_date"),
        "reputation":      attrs.get("reputation"),
        "categories":      attrs.get("categories", {}),
        "tags":            attrs.get("tags", []),
        "a_records":       a_records,
        "last_analysis":   attrs.get("last_analysis_date"),
        "flagged_vendors": flags,
    }


def format_url_result(target: str, raw: dict) -> dict:
    if "error" in raw:
        return {"target": target, "type": "url", "error": raw["error"]}

    attrs  = raw.get("attributes", {})
    stats  = parse_analysis_stats(attrs.get("last_analysis_stats", {}))
    flags  = parse_vendors(attrs.get("last_analysis_results", {}))

    return {
        "target":          target,
        "type":            "url",
        "flag":            flag_level(stats["malicious"], stats["suspicious"]),
        "score":           stats["score"],
        "stats":           stats,
        "final_url":       attrs.get("last_final_url"),
        "title":           attrs.get("title"),
        "reputation":      attrs.get("reputation"),
        "categories":      attrs.get("categories", {}),
        "tags":            attrs.get("tags", []),
        "last_analysis":   attrs.get("last_analysis_date"),
        "flagged_vendors": flags,
    }


def format_hash_result(target: str, raw: dict) -> dict:
    if "error" in raw:
        return {"target": target, "type": "hash", "error": raw["error"]}

    attrs  = raw.get("attributes", {})
    stats  = parse_analysis_stats(attrs.get("last_analysis_stats", {}))
    flags  = parse_vendors(attrs.get("last_analysis_results", {}))

    sig_info = attrs.get("signature_info", {})

    return {
        "target":          target,
        "type":            "hash",
        "flag":            flag_level(stats["malicious"], stats["suspicious"]),
        "score":           stats["score"],
        "stats":           stats,
        "md5":             attrs.get("md5"),
        "sha1":            attrs.get("sha1"),
        "sha256":          attrs.get("sha256"),
        "file_type":       attrs.get("type_description"),
        "magic":           attrs.get("magic"),
        "size":            attrs.get("size"),
        "name":            (attrs.get("meaningful_name") or
                           (attrs.get("names") or [None])[0]),
        "tags":            attrs.get("tags", []),
        "popular_threat":  attrs.get("popular_threat_classification", {}).get("suggested_threat_label"),
        "signed":          bool(sig_info.get("verified") == "Signed"),
        "signer":          sig_info.get("signers"),
        "first_seen":      attrs.get("first_submission_date"),
        "last_seen":       attrs.get("last_submission_date"),
        "times_submitted": attrs.get("times_submitted"),
        "last_analysis":   attrs.get("last_analysis_date"),
        "flagged_vendors": flags,
    }


# ── Display ────────────────────────────────────────────────────────────────────

FLAG_ICONS = {"MALICIOUS": "🔴", "SUSPICIOUS": "🟡", "CLEAN": "🟢"}

def print_result(result: dict, verbose: bool) -> None:
    sep  = "─" * 62
    flag = result.get("flag", "UNKNOWN")
    icon = FLAG_ICONS.get(flag, "⚪")
    err  = result.get("error")

    print(f"\n{sep}")
    print(f"  {icon} [{flag}]  {result['target']}  ({result['type'].upper()})")
    print(sep)

    if err:
        print(f"  [-] {err}")
        return

    print(f"  Score       : {result.get('score', 'N/A')}")

    t = result["type"]

    if t == "ip":
        print(f"  Org/ASN     : {result.get('org')} / AS{result.get('asn')}")
        print(f"  Country     : {result.get('country')}")
        print(f"  Network     : {result.get('network')}")
        print(f"  Reputation  : {result.get('reputation')}")
    elif t == "domain":
        print(f"  Registrar   : {result.get('registrar')}")
        print(f"  A Records   : {', '.join(result.get('a_records', [])) or 'N/A'}")
        print(f"  Reputation  : {result.get('reputation')}")
    elif t == "url":
        if result.get("final_url") and result["final_url"] != result["target"]:
            print(f"  Final URL   : {result['final_url']}")
        if result.get("title"):
            print(f"  Page Title  : {result['title']}")
        print(f"  Reputation  : {result.get('reputation')}")
    elif t == "hash":
        print(f"  File Type   : {result.get('file_type')} ({result.get('magic', '')})")
        print(f"  File Name   : {result.get('name', 'N/A')}")
        print(f"  Size        : {result.get('size', 'N/A')} bytes")
        print(f"  MD5         : {result.get('md5', 'N/A')}")
        print(f"  SHA1        : {result.get('sha1', 'N/A')}")
        print(f"  SHA256      : {result.get('sha256', 'N/A')}")
        if result.get("popular_threat"):
            print(f"  Threat Label: {result['popular_threat']}")
        print(f"  Signed      : {'Yes — ' + str(result.get('signer')) if result.get('signed') else 'No'}")
        print(f"  Submissions : {result.get('times_submitted', 'N/A')}")
        print(f"  First seen  : {result.get('first_seen', 'N/A')}")

    if result.get("tags"):
        print(f"  Tags        : {', '.join(result['tags'])}")

    cats = result.get("categories", {})
    if cats:
        unique_cats = list(dict.fromkeys(cats.values()))
        print(f"  Categories  : {', '.join(unique_cats)}")

    flagged = result.get("flagged_vendors", [])
    if flagged:
        print(f"\n  Flagged by {len(flagged)} vendor(s):")
        limit = None if verbose else 10
        for v in flagged[:limit]:
            icon_v = "🔴" if v["category"] == "malicious" else "🟡"
            print(f"    {icon_v} {v['vendor']:<30} {v['result']}")
        if not verbose and len(flagged) > 10:
            print(f"    ... and {len(flagged) - 10} more (use -v to see all)")
    else:
        print(f"\n  No vendors flagged this target.")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Query VirusTotal v3 for a list of IPs, domains, URLs, or file hashes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Target types auto-detected per line:
  IP      →  1.2.3.4
  Domain  →  example.com
  URL     →  https://example.com/path
  Hash    →  MD5 / SHA-1 / SHA-256

Examples:
  python vt_checker.py -t targets.txt -k YOUR_API_KEY
  python vt_checker.py -t targets.txt -k YOUR_API_KEY -o results.json -v
        """,
    )
    parser.add_argument("-t", "--targets",  required=True,  help="Path to target list file")
    parser.add_argument("-k", "--api-key",  required=True,  help="VirusTotal API key")
    parser.add_argument("-o", "--output",   default=None,   help="Save JSON results to file")
    parser.add_argument("-v", "--verbose",  action="store_true", help="Show all flagging vendors")
    parser.add_argument("--delay",          type=float, default=15.0,
                        help="Seconds between requests — free tier allows 4/min (default: 15)")
    args = parser.parse_args()

    if not Path(args.targets).is_file():
        print(f"[!] Target file not found: {args.targets}")
        sys.exit(1)

    # Load and classify targets
    targets = []
    with open(args.targets) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append((line, detect_type(line)))

    if not targets:
        print("[!] No targets found in file.")
        sys.exit(1)

    type_counts = {}
    for _, t in targets:
        type_counts[t] = type_counts.get(t, 0) + 1

    print(f"[*] Loaded {len(targets)} target(s): " +
          ", ".join(f"{v} {k}(s)" for k, v in type_counts.items()))
    print(f"[*] Request delay: {args.delay}s  (free tier: 4 req/min — adjust with --delay)")

    results = []
    errors  = []

    for i, (target, ttype) in enumerate(targets, start=1):
        print(f"\n[{i}/{len(targets)}] {ttype.upper():6} → {target}")

        try:
            if ttype == "ip":
                raw    = query_ip(target, args.api_key)
                result = format_ip_result(target, raw)
            elif ttype == "domain":
                raw    = query_domain(target, args.api_key)
                result = format_domain_result(target, raw)
            elif ttype == "url":
                raw    = query_url(target, args.api_key)
                result = format_url_result(target, raw)
            else:  # hash
                raw    = query_hash(target, args.api_key)
                result = format_hash_result(target, raw)

            results.append(result)
            print_result(result, args.verbose)

        except RuntimeError as e:
            msg = str(e)
            print(f"  [!] Error: {msg}")
            errors.append({"target": target, "type": ttype, "error": msg})

        if i < len(targets):
            time.sleep(args.delay)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'═' * 62}")
    print(f"  SUMMARY")
    print(f"{'═' * 62}")
    print(f"  Total queried : {len(targets)}")
    print(f"  Successful    : {len(results)}")
    print(f"  Errors        : {len(errors)}")

    malicious  = [r for r in results if r.get("flag") == "MALICIOUS"]
    suspicious = [r for r in results if r.get("flag") == "SUSPICIOUS"]
    clean      = [r for r in results if r.get("flag") == "CLEAN"]

    print(f"\n  🔴 Malicious  : {len(malicious)}")
    print(f"  🟡 Suspicious : {len(suspicious)}")
    print(f"  🟢 Clean      : {len(clean)}")

    if malicious or suspicious:
        print(f"\n  Flagged targets:")
        for r in malicious + suspicious:
            icon = "🔴" if r["flag"] == "MALICIOUS" else "🟡"
            print(f"    {icon} [{r['flag']}] {r['target']}  ({r.get('score', '?')} vendors)")

    # ── Save output ───────────────────────────────────────────────────────────
    if args.output:
        output_data = {
            "meta": {
                "targets_file":  args.targets,
                "total_targets": len(targets),
                "successful":    len(results),
                "errors":        len(errors),
                "malicious":     len(malicious),
                "suspicious":    len(suspicious),
                "clean":         len(clean),
            },
            "results": results,
            "errors":  errors,
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\n[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
