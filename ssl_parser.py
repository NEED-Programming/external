#!/usr/bin/env python3
"""
ssl_parser.py — SSL/TLS Findings Parser from pentest_recon.sh
Parses sslscan + sslyze output files and flags vulnerabilities
against OWASP TLS Cheat Sheet best practices.

Usage:
    python3 ssl_parser.py <recon_output_dir>
    python3 ssl_parser.py ./recon_tesla.com_20260506_114443
"""

import os
import re
import sys
from pathlib import Path
from datetime import datetime

# ── Colours ───────────────────────────────────────────────────────────────────
RED     = '\033[0;31m'
ORANGE  = '\033[0;33m'
YELLOW  = '\033[1;33m'
GREEN   = '\033[0;32m'
CYAN    = '\033[0;36m'
BLUE    = '\033[0;34m'
BOLD    = '\033[1m'
DIM     = '\033[2m'
RESET   = '\033[0m'

def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗
║           SSL/TLS Findings Parser — OWASP Baseline        ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")

def sev(level):
    return {
        'CRITICAL': f'{BOLD}{RED}[CRITICAL]{RESET}',
        'HIGH':     f'{RED}[HIGH]{RESET}    ',
        'MEDIUM':   f'{ORANGE}[MEDIUM]{RESET}  ',
        'LOW':      f'{BLUE}[LOW]{RESET}     ',
        'INFO':     f'{CYAN}[INFO]{RESET}    ',
        'OK':       f'{GREEN}[OK]{RESET}      ',
    }.get(level, level)

def header(title):
    print(f'\n{BOLD}{BLUE}── {title} {RESET}' + '─' * max(0, 60 - len(title)))

def finding(level, title, detail=None):
    print(f'  {sev(level)} {BOLD}{title}{RESET}')
    if detail:
        for line in detail if isinstance(detail, list) else [detail]:
            print(f'            {DIM}{line}{RESET}')

# ── OWASP Weak Cipher Definitions ─────────────────────────────────────────────
# Ciphers that should never be accepted per OWASP TLS Cheat Sheet
WEAK_CIPHERS = {
    # No forward secrecy — RSA key exchange
    'rsa_no_fs': {
        'pattern': re.compile(r'TLS_RSA_WITH_', re.IGNORECASE),
        'title': 'RSA Key Exchange (No Forward Secrecy)',
        'severity': 'HIGH',
        'detail': 'If private key is compromised, all past sessions can be decrypted. OWASP requires PFS.'
    },
    # Deprecated CBC mode
    'cbc': {
        'pattern': re.compile(r'_CBC_SHA(?!384|256)', re.IGNORECASE),
        'title': 'CBC Mode Cipher (BEAST / LUCKY13 Risk)',
        'severity': 'MEDIUM',
        'detail': 'CBC mode ciphers risk BEAST (CVE-2011-3389 CVSS 2.6) and LUCKY13. Both require MitM — largely mitigated in modern clients but should be disabled.'
    },
    # Truncated MAC
    'ccm8': {
        'pattern': re.compile(r'_CCM_8|_CCM8', re.IGNORECASE),
        'title': 'Truncated MAC (CCM8)',
        'severity': 'MEDIUM',
        'detail': 'CCM8 uses a shortened 8-byte authentication tag, weakening message integrity.'
    },
    # RC4
    'rc4': {
        'pattern': re.compile(r'RC4', re.IGNORECASE),
        'title': 'RC4 Stream Cipher',
        'severity': 'HIGH',
        'detail': 'RC4 is broken and prohibited by RFC 7465. CVE-2015-2808 CVSS 5.0. Should never be accepted.'
    },
    # NULL ciphers
    'null': {
        'pattern': re.compile(r'_NULL_|WITH_NULL', re.IGNORECASE),
        'title': 'NULL Cipher (No Encryption)',
        'severity': 'CRITICAL',
        'detail': 'NULL ciphers provide authentication with no encryption whatsoever.'
    },
    # Export grade
    'export': {
        'pattern': re.compile(r'EXPORT|EXP-', re.IGNORECASE),
        'title': 'Export-Grade Cipher (FREAK Risk)',
        'severity': 'HIGH',
        'detail': 'Export ciphers use intentionally weakened key sizes. FREAK CVE-2015-0204 CVSS 4.3. Allows downgrade to 512-bit RSA.'
    },
    # DES / 3DES
    'des': {
        'pattern': re.compile(r'_DES_|3DES|DES-', re.IGNORECASE),
        'title': 'DES / 3DES Cipher (SWEET32 Risk)',
        'severity': 'HIGH',
        'detail': '3DES is vulnerable to SWEET32 birthday attack. DES is completely broken.'
    },
    # Anonymous / no auth
    'anon': {
        'pattern': re.compile(r'_anon_|ADH-|AECDH-', re.IGNORECASE),
        'title': 'Anonymous Cipher (No Authentication)',
        'severity': 'CRITICAL',
        'detail': 'Anonymous ciphers provide no server authentication — trivially MITMed.'
    },
    # Non-standard / unnecessary
    'camellia': {
        'pattern': re.compile(r'CAMELLIA', re.IGNORECASE),
        'title': 'CAMELLIA Cipher (Non-Standard)',
        'severity': 'LOW',
        'detail': 'Not recommended by OWASP. Increases attack surface unnecessarily.'
    },
    'aria': {
        'pattern': re.compile(r'_ARIA_', re.IGNORECASE),
        'title': 'ARIA Cipher (Non-Standard)',
        'severity': 'LOW',
        'detail': 'Not recommended by OWASP. Increases attack surface unnecessarily.'
    },
}

DEPRECATED_TLS = {
    'SSLv2':  ('CRITICAL', 'SSLv2 Enabled — Completely Broken',  'SSLv2 has critical vulnerabilities. Must be disabled immediately.'),
    'SSLv3':  ('CRITICAL', 'SSLv3 Enabled — POODLE Vulnerable',  'SSLv3 is vulnerable to POODLE. Must be disabled.'),
    'TLSv1.0': ('HIGH',    'TLS 1.0 Enabled — Deprecated',        'Vulnerable to BEAST, POODLE downgrade. OWASP requires TLS 1.2 minimum.'),
    'TLSv1.1': ('MEDIUM',  'TLS 1.1 Enabled — Deprecated',        'No known practical exploits but cryptographically obsolete. OWASP requires TLS 1.2 minimum.'),
}

# ── sslscan Parser ─────────────────────────────────────────────────────────────
def parse_sslscan(filepath, hostname):
    findings = []
    content = open(filepath, errors='replace').read()
    # Strip ANSI codes for parsing
    clean = re.sub(r'\x1b\[[0-9;]*m', '', content)

    # Check for connection error
    if 'ERROR: Could not resolve' in clean or 'ERROR: Could not connect' in clean:
        return None  # skip unreachable hosts silently

    # Deprecated protocol checks
    for proto, (severity, title, detail) in DEPRECATED_TLS.items():
        match = re.search(rf'{proto}\s+enabled', clean, re.IGNORECASE)
        if match:
            findings.append((severity, title, detail))

    # Collect accepted cipher lines
    accepted_ciphers = re.findall(r'(?:Accepted|Preferred)\s+\S+\s+\d+\s+bits\s+(\S+)', clean)

    # Track which weak categories were found (deduplicate per host)
    found_categories = {}
    for cipher in accepted_ciphers:
        for cat_key, cat in WEAK_CIPHERS.items():
            if cat['pattern'].search(cipher):
                if cat_key not in found_categories:
                    found_categories[cat_key] = []
                found_categories[cat_key].append(cipher)

    for cat_key, ciphers in found_categories.items():
        cat = WEAK_CIPHERS[cat_key]
        detail = [cat['detail'], f'Examples: {", ".join(ciphers[:3])}{"..." if len(ciphers) > 3 else ""}']
        findings.append((cat['severity'], cat['title'], detail))

    # Heartbleed — explicitly check for vulnerable without "not" before it
    if re.search(r'(?<!not )vulnerable to heartbleed', clean, re.IGNORECASE):
        findings.append(('CRITICAL', 'Heartbleed Vulnerable (CVE-2014-0160)', 'Server is vulnerable to Heartbleed. Patch OpenSSL immediately.'))

    return findings

# ── sslyze Parser ──────────────────────────────────────────────────────────────
def parse_sslyze(filepath, hostname):
    findings = []
    content = open(filepath, errors='replace').read()
    clean = re.sub(r'\x1b\[[0-9;]*m', '', content)

    if 'Could not resolve hostname' in clean or 'ERROR' in clean[:200]:
        return None

    # Certificate lifespan
    lifespan_match = re.search(r'Certificate life span is (\d+) days', clean)
    if lifespan_match:
        days = int(lifespan_match.group(1))
        if days > 398:
            findings.append(('MEDIUM', f'Certificate Lifespan Too Long ({days} days)',
                f'No direct CVSS score — compliance/policy finding. CA/Browser Forum limits certs to 398 days. At {days} days, a compromised private key stays valid significantly longer.'))
        elif days > 366:
            findings.append(('LOW', f'Certificate Lifespan Exceeds Recommended ({days} days)',
                'Mozilla intermediate config recommends max 366 days.'))

    # Chain order
    if 'Received Chain Order:              FAILED' in clean:
        findings.append(('LOW', 'Certificate Chain Out of Order',
            'No CVE — interoperability/misconfiguration issue only. Most browsers compensate but strict TLS clients may reject the handshake.'))

    # OCSP stapling
    if 'OCSP Stapling' in clean and 'NOT SUPPORTED' in clean:
        findings.append(('LOW', 'OCSP Stapling Not Supported',
            'Without OCSP stapling, revocation checks are slow and often skipped. Revoked certs may still be trusted.'))

    # OCSP Must-Staple
    if 'OCSP Must-Staple:                  NOT SUPPORTED' in clean:
        findings.append(('LOW', 'OCSP Must-Staple Not Set',
            'OCSP Must-Staple extension not present. Clients cannot enforce stapling requirement.'))

    # Renegotiation
    if 'Client Renegotiation DoS Attack:   VULNERABLE' in clean:
        findings.append(('HIGH', 'Client-Initiated Renegotiation DoS',
            'Server allows client-initiated renegotiation — can be used for CPU exhaustion DoS.'))

    # CCS Injection — case-insensitive, must confirm absence of "not vulnerable"
    if 'CCS Injection' in clean and not re.search(r'not vulnerable to openssl ccs injection', clean, re.IGNORECASE):
        findings.append(('HIGH', 'OpenSSL CCS Injection Vulnerable (CVE-2014-0224)',
            'CVE-2014-0224 CVSS 6.8 Medium. Allows MitM to intercept key material and decrypt sessions.'))

    # ROBOT — case-insensitive check
    if 'ROBOT Attack' in clean and not re.search(r'not vulnerable', clean, re.IGNORECASE):
        findings.append(('MEDIUM', 'ROBOT Attack Vulnerable',
            'CVE-2017-13099 CVSS 5.9 Medium. RSA decryption oracle — requires many crafted queries to exploit.'))

    # Compression (CRIME)
    if 'Compression' in clean and 'ENABLED' in clean:
        findings.append(('MEDIUM', 'TLS Compression Enabled (CRIME Risk)',
            'CVE-2012-4929 CVSS 2.6 Low. CRIME requires MitM and injected JavaScript — uncommon in practice but compression should be disabled.'))

    # Untrusted certificate — only check the SNI-enabled section
    # sslyze clearly marks the SNI-disabled section as "can be ignored", so strip it first
    sni_enabled_section = re.split(r'Certificate Chain with SNI disabled', clean)[0]
    if 'Certificate is NOT Trusted' in sni_enabled_section:
        findings.append(('HIGH', 'Untrusted Certificate Detected',
            'Certificate fails validation against one or more major trust stores.'))

    return findings

# ── Severity Sorter ────────────────────────────────────────────────────────────
SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4, 'OK': 5}

def sort_findings(findings):
    return sorted(findings, key=lambda x: SEV_ORDER.get(x[0], 99))

# ── Summary Counter ────────────────────────────────────────────────────────────
def count_sevs(all_findings):
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for findings in all_findings.values():
        for f in findings:
            if f[0] in counts:
                counts[f[0]] += 1
    return counts

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print(f'Usage: python3 ssl_parser.py <recon_output_dir>')
        sys.exit(1)

    recon_dir = Path(sys.argv[1])
    ssl_dir = recon_dir / 'ssl'

    if not ssl_dir.exists():
        print(f'{RED}Error: ssl/ directory not found in {recon_dir}{RESET}')
        sys.exit(1)

    banner()
    print(f'{BOLD}Target Directory:{RESET} {recon_dir}')
    print(f'{BOLD}Scan Time:{RESET}       {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

    # Collect all hosts
    sslscan_files = sorted(ssl_dir.glob('sslscan_*.txt'))
    sslyze_files  = {f.stem.replace('sslyze_', ''): f for f in ssl_dir.glob('sslyze_*.txt')}

    all_host_findings = {}
    skipped = 0

    for sslscan_file in sslscan_files:
        hostname = sslscan_file.stem.replace('sslscan_', '')
        sslyze_file = sslyze_files.get(hostname)

        scan_findings = parse_sslscan(sslscan_file, hostname)
        if scan_findings is None:
            skipped += 1
            continue

        if sslyze_file:
            lyze_findings = parse_sslyze(sslyze_file, hostname)
            if lyze_findings:
                scan_findings.extend(lyze_findings)

        if scan_findings:
            all_host_findings[hostname] = sort_findings(scan_findings)

    # ── Per-Host Output ────────────────────────────────────────────────────────
    print(f'\n{BOLD}Hosts scanned: {len(sslscan_files) - skipped}  |  Hosts with findings: {len(all_host_findings)}  |  Unreachable (skipped): {skipped}{RESET}')

    for hostname, findings in sorted(all_host_findings.items()):
        # Only print hosts that have medium or higher
        worst = SEV_ORDER.get(findings[0][0], 99) if findings else 99
        if worst > SEV_ORDER['LOW']:
            continue

        header(hostname)
        for f in findings:
            detail = f[2] if len(f) > 2 else None
            finding(f[0], f[1], detail)

    # ── Summary ────────────────────────────────────────────────────────────────
    counts = count_sevs(all_host_findings)
    vuln_hosts = len(all_host_findings)

    print(f'\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗')
    print(f'║                      FINDINGS SUMMARY                    ║')
    print(f'╚══════════════════════════════════════════════════════════╝{RESET}')
    print(f'  {BOLD}{RED}Critical:{RESET}  {counts["CRITICAL"]}')
    print(f'  {BOLD}{RED}High:{RESET}      {counts["HIGH"]}')
    print(f'  {BOLD}{ORANGE}Medium:{RESET}    {counts["MEDIUM"]}')
    print(f'  {BOLD}{BLUE}Low:{RESET}       {counts["LOW"]}')
    print(f'\n  {BOLD}Hosts with findings:{RESET} {vuln_hosts}')

    # Top offenders
    if all_host_findings:
        print(f'\n  {BOLD}Top offenders (most findings):{RESET}')
        sorted_hosts = sorted(all_host_findings.items(), key=lambda x: len(x[1]), reverse=True)
        for hostname, findings in sorted_hosts[:10]:
            crit = sum(1 for f in findings if f[0] == 'CRITICAL')
            high = sum(1 for f in findings if f[0] == 'HIGH')
            med  = sum(1 for f in findings if f[0] == 'MEDIUM')
            badges = ''
            if crit: badges += f' {RED}{crit}C{RESET}'
            if high: badges += f' {RED}{high}H{RESET}'
            if med:  badges += f' {ORANGE}{med}M{RESET}'
            print(f'    {DIM}{hostname}{RESET}{badges}')

    print()

if __name__ == '__main__':
    main()
