#!/usr/bin/env python3
"""
Shodan Target Checker
Accepts a file containing a list of IPs/hostnames and queries Shodan for each.

Usage:
    python shodan_checker.py -t targets.txt -k YOUR_API_KEY [-o results.json] [-v]

Requirements:
    pip install shodan
"""

import argparse
import json
import sys
import time
import socket
from pathlib import Path

try:
    import shodan
except ImportError:
    print("[!] Shodan library not installed. Run: pip install shodan")
    sys.exit(1)


# ── Helpers ───────────────────────────────────────────────────────────────────

def resolve_hostname(host: str) -> str | None:
    """Resolve a hostname to an IP address. Returns None on failure."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def is_ip(value: str) -> bool:
    """Return True if the string looks like an IPv4 address."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def load_targets(path: str) -> list[str]:
    """Read targets from a file, one per line. Skips blank lines and comments."""
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def format_host_result(host: dict, original_target: str, resolved_ip: str | None) -> dict:
    """Extract the most useful fields from a Shodan host response."""
    ports   = sorted({item["port"] for item in host.get("data", [])})
    vulns   = list(host.get("vulns", {}).keys())
    banners = []

    for item in host.get("data", []):
        banner = {
            "port":      item.get("port"),
            "transport": item.get("transport", "tcp"),
            "product":   item.get("product"),
            "version":   item.get("version"),
            "banner":    (item.get("data") or "").strip()[:300] or None,
        }
        # Include SSL/TLS info if present
        if "ssl" in item:
            ssl = item["ssl"]
            banner["ssl"] = {
                "subject": ssl.get("cert", {}).get("subject", {}),
                "issuer":  ssl.get("cert", {}).get("issuer", {}),
                "expires": ssl.get("cert", {}).get("expires"),
                "cipher":  ssl.get("cipher", {}).get("name"),
            }
        banners.append(banner)

    return {
        "target":       original_target,
        "ip":           resolved_ip or host.get("ip_str"),
        "hostnames":    host.get("hostnames", []),
        "org":          host.get("org"),
        "isp":          host.get("isp"),
        "asn":          host.get("asn"),
        "country":      host.get("country_name"),
        "city":         host.get("city"),
        "os":           host.get("os"),
        "open_ports":   ports,
        "tags":         host.get("tags", []),
        "vulns":        vulns,
        "last_update":  host.get("last_update"),
        "services":     banners,
    }


def print_result(result: dict, verbose: bool) -> None:
    """Pretty-print a single host result to stdout."""
    sep = "─" * 60
    print(f"\n{sep}")
    print(f"  Target   : {result['target']}")
    print(f"  IP       : {result['ip']}")
    if result["hostnames"]:
        print(f"  Hostnames: {', '.join(result['hostnames'])}")
    print(f"  Org/ISP  : {result['org']} / {result['isp']}")
    print(f"  ASN      : {result['asn']}")
    print(f"  Location : {result['city']}, {result['country']}")
    if result["os"]:
        print(f"  OS       : {result['os']}")
    print(f"  Ports    : {result['open_ports']}")
    if result["tags"]:
        print(f"  Tags     : {', '.join(result['tags'])}")
    if result["vulns"]:
        print(f"  [!] CVEs : {', '.join(result['vulns'])}")
    if verbose:
        print("\n  Services:")
        for svc in result["services"]:
            label = f"    [{svc['port']}/{svc['transport']}]"
            if svc.get("product"):
                label += f" {svc['product']}"
            if svc.get("version"):
                label += f" {svc['version']}"
            print(label)
            if svc.get("ssl"):
                ssl = svc["ssl"]
                cn = ssl["subject"].get("CN", "N/A")
                print(f"      TLS Subject CN : {cn}")
                print(f"      TLS Expires    : {ssl.get('expires', 'N/A')}")
            if svc.get("banner"):
                snippet = svc["banner"].replace("\n", " ")[:120]
                print(f"      Banner         : {snippet}")
    print(f"  Last seen: {result['last_update']}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Query Shodan for a list of IPs or hostnames.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python shodan_checker.py -t targets.txt -k YOUR_API_KEY
  python shodan_checker.py -t targets.txt -k YOUR_API_KEY -o out.json -v
        """,
    )
    parser.add_argument("-t", "--targets",  required=True,  help="Path to target list file (one IP/host per line)")
    parser.add_argument("-k", "--api-key",  required=True,  help="Shodan API key")
    parser.add_argument("-o", "--output",   default=None,   help="Save JSON results to this file")
    parser.add_argument("-v", "--verbose",  action="store_true", help="Show full service/banner details")
    parser.add_argument("--delay",          type=float, default=1.0, help="Seconds to wait between API calls (default: 1)")
    args = parser.parse_args()

    # Validate target file
    if not Path(args.targets).is_file():
        print(f"[!] Target file not found: {args.targets}")
        sys.exit(1)

    targets = load_targets(args.targets)
    if not targets:
        print("[!] No targets found in file.")
        sys.exit(1)

    print(f"[*] Loaded {len(targets)} target(s) from {args.targets}")

    # Initialize Shodan client
    api = shodan.Shodan(args.api_key)
    try:
        info = api.info()
        print(f"[*] Shodan API key valid — query credits remaining: {info.get('query_credits', 'N/A')}")
    except shodan.APIError as e:
        print(f"[!] Shodan API error: {e}")
        sys.exit(1)

    results   = []
    errors    = []

    for i, target in enumerate(targets, start=1):
        print(f"\n[{i}/{len(targets)}] Querying: {target}")

        # Resolve hostname → IP if needed
        ip = target if is_ip(target) else resolve_hostname(target)
        if not ip:
            msg = f"Could not resolve hostname: {target}"
            print(f"  [-] {msg}")
            errors.append({"target": target, "error": msg})
            continue

        if ip != target:
            print(f"  [→] Resolved to: {ip}")

        try:
            host = api.host(ip)
            result = format_host_result(host, target, ip)
            results.append(result)
            print_result(result, args.verbose)

            if result["vulns"]:
                print(f"\n  [!] WARNING: {len(result['vulns'])} known CVE(s) found!")

        except shodan.APIError as e:
            msg = str(e)
            if "No information available" in msg:
                print(f"  [-] No Shodan data for {ip}")
            else:
                print(f"  [!] API error for {ip}: {msg}")
            errors.append({"target": target, "ip": ip, "error": msg})

        # Respect rate limits
        if i < len(targets):
            time.sleep(args.delay)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'═' * 60}")
    print(f"  SUMMARY")
    print(f"{'═' * 60}")
    print(f"  Targets queried : {len(targets)}")
    print(f"  Successful      : {len(results)}")
    print(f"  Errors/not found: {len(errors)}")

    all_ports = sorted({p for r in results for p in r["open_ports"]})
    if all_ports:
        print(f"  Unique ports    : {all_ports}")

    vulnerable = [r for r in results if r["vulns"]]
    if vulnerable:
        print(f"\n  [!] Hosts with known CVEs ({len(vulnerable)}):")
        for r in vulnerable:
            print(f"      {r['ip']} ({r['target']}) → {', '.join(r['vulns'])}")

    # ── Save output ───────────────────────────────────────────────────────────
    if args.output:
        output_data = {
            "meta": {
                "targets_file": args.targets,
                "total_targets": len(targets),
                "successful": len(results),
                "errors": len(errors),
            },
            "results": results,
            "errors": errors,
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\n[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
