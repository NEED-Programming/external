#!/usr/bin/env bash
# ============================================================
#  recon.sh — Automated Recon Pipeline
#  Tools: subfinder, crt.sh, dnsrecon, sslscan, sslyze
# ============================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[-]${RESET} $*"; }
banner()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${RESET}"; echo -e "${BOLD}${CYAN}  $*${RESET}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════${RESET}\n"; }

# ── Usage ─────────────────────────────────────────────────────
usage() {
    echo -e "Usage: $0 -d <domain> [-o <output_dir>] [-p <parallel_jobs>]"
    echo -e "  -d  Target domain (required)"
    echo -e "  -o  Output directory (default: ./recon_<domain>_<timestamp>)"
    echo -e "  -p  Parallel SSL scan jobs (default: 3)"
    exit 1
}

# ── Argument Parsing ──────────────────────────────────────────
DOMAIN=""
OUTPUT_DIR=""
PARALLEL_JOBS=3

while getopts "d:o:p:h" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        p) PARALLEL_JOBS="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$DOMAIN" ]] && { error "No domain specified."; usage; }

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="${OUTPUT_DIR:-./recon_${DOMAIN}_${TIMESTAMP}}"
mkdir -p "$OUTPUT_DIR"

# ── Flight Controls: Tool Check & Install ─────────────────────
banner "Flight Controls — Verifying Tools"

# Detect package manager
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt-get"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
elif command -v brew &>/dev/null; then
    PKG_MANAGER="brew"
else
    warn "No supported package manager found. Manual installs may be required."
    PKG_MANAGER=""
fi

check_and_install() {
    local tool="$1"
    local install_cmd="$2"

    if command -v "$tool" &>/dev/null; then
        success "$tool is installed ($(command -v "$tool"))"
    else
        warn "$tool not found — attempting install..."
        if eval "$install_cmd"; then
            success "$tool installed successfully."
        else
            error "Failed to install $tool. Please install it manually and re-run."
            exit 1
        fi
    fi
}

# subfinder (replaces amass — lighter, faster, more sources)
check_and_install "subfinder" "
    if [[ '$PKG_MANAGER' == 'apt-get' ]]; then
        sudo apt-get install -y subfinder
    elif [[ '$PKG_MANAGER' == 'brew' ]]; then
        brew install subfinder
    elif command -v go &>/dev/null; then
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    else
        echo 'Install subfinder manually: https://github.com/projectdiscovery/subfinder' && exit 1
    fi
"

# dnsx (live host resolution probing)
check_and_install "dnsx" "
    if [[ '$PKG_MANAGER' == 'apt-get' ]]; then
        sudo apt-get install -y dnsx
    elif [[ '$PKG_MANAGER' == 'brew' ]]; then
        brew install dnsx
    elif command -v go &>/dev/null; then
        go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    else
        echo 'Install dnsx manually: https://github.com/projectdiscovery/dnsx' && exit 1
    fi
"

# dnsrecon
check_and_install "dnsrecon" "
    if command -v pip3 &>/dev/null; then
        pip3 install dnsrecon --break-system-packages 2>/dev/null || pip3 install dnsrecon
    elif [[ '$PKG_MANAGER' == 'apt-get' ]]; then
        sudo apt-get install -y dnsrecon
    else
        echo 'Install dnsrecon manually: pip3 install dnsrecon' && exit 1
    fi
"

# sslscan
check_and_install "sslscan" "
    if [[ '$PKG_MANAGER' == 'apt-get' ]]; then
        sudo apt-get install -y sslscan
    elif [[ '$PKG_MANAGER' == 'brew' ]]; then
        brew install sslscan
    else
        echo 'Install sslscan manually: https://github.com/rbsec/sslscan' && exit 1
    fi
"

# sslyze
check_and_install "sslyze" "
    if command -v pip3 &>/dev/null; then
        pip3 install sslyze --break-system-packages 2>/dev/null || pip3 install sslyze
    else
        echo 'Install sslyze manually: pip3 install sslyze' && exit 1
    fi
"

# curl + jq (needed for crt.sh)
if [[ -n "$PKG_MANAGER" ]]; then
    check_and_install "curl" "sudo $PKG_MANAGER install -y curl"
    check_and_install "jq"   "sudo $PKG_MANAGER install -y jq"
else
    check_and_install "curl" "echo 'Install curl manually' && exit 1"
    check_and_install "jq"   "echo 'Install jq manually: https://jqlang.github.io/jq/' && exit 1"
fi

# ── Phase 1: Subdomain Enumeration ────────────────────────────
banner "Phase 1 — Subdomain Enumeration"

SUBDOMAINS_FILE="$OUTPUT_DIR/subdomains_all.txt"
touch "$SUBDOMAINS_FILE"

# subfinder
info "Running subfinder passive enumeration on $DOMAIN..."
subfinder -d "$DOMAIN" -silent -o "$OUTPUT_DIR/subdomains_subfinder.txt" 2>/dev/null \
    && success "subfinder complete → $OUTPUT_DIR/subdomains_subfinder.txt" \
    || warn "subfinder encountered errors (partial results may exist)"

# crt.sh — wait 10s for server-side generation, then retry up to 3 times
info "Querying crt.sh for $DOMAIN..."
info "  Waiting 10s for crt.sh to generate results..."
sleep 10
CRTSH_RAW=""
CRTSH_SUCCESS=false
for attempt in 1 2 3; do
    info "  crt.sh attempt $attempt / 3..."
    CRTSH_RAW=$(curl -s --max-time 30 "https://crt.sh/?q=.$DOMAIN&output=json" 2>/dev/null || true)
    if echo "$CRTSH_RAW" | jq -e '.[0]' &>/dev/null; then
        CRTSH_SUCCESS=true
        break
    fi
    warn "  crt.sh attempt $attempt returned empty/invalid — waiting 10s before retry..."
    sleep 10
done

if $CRTSH_SUCCESS; then
    echo "$CRTSH_RAW" | jq -r '.[].name_value' | sort -u > "$OUTPUT_DIR/subdomains_crtsh.txt"
    success "crt.sh complete → $OUTPUT_DIR/subdomains_crtsh.txt"
else
    warn "crt.sh failed after 3 attempts — skipping (subfinder results still saved)"
    touch "$OUTPUT_DIR/subdomains_crtsh.txt"
fi

# Merge & deduplicate all subdomains (exclude the output file itself, strip wildcards)
grep -h '' "$OUTPUT_DIR"/subdomains_subfinder.txt "$OUTPUT_DIR"/subdomains_crtsh.txt 2>/dev/null \
    | grep -v '^\*\.' \
    | sort -u > "$SUBDOMAINS_FILE"

SUBDOMAIN_COUNT=$(wc -l < "$SUBDOMAINS_FILE")
success "Total unique subdomains discovered: $SUBDOMAIN_COUNT → $SUBDOMAINS_FILE"

# ── Phase 1.5: Live Host Probing ─────────────────────────────
banner "Phase 1.5 — Live Host Probing (dnsx)"

LIVE_HOSTS_FILE="$OUTPUT_DIR/subdomains_live.txt"
info "Probing $SUBDOMAIN_COUNT subdomains for live DNS resolution..."
dnsx -l "$SUBDOMAINS_FILE" -silent -r 8.8.8.8,1.1.1.1 -t 25 -o "$LIVE_HOSTS_FILE" 2>/dev/null     || warn "dnsx encountered errors (partial results may exist)"

LIVE_COUNT=$(wc -l < "$LIVE_HOSTS_FILE")
success "$LIVE_COUNT live hosts confirmed → $LIVE_HOSTS_FILE"

# ── Phase 2: DNS Zone Transfer ────────────────────────────────
banner "Phase 2 — DNS Zone Transfer (dnsrecon)"

info "Running dnsrecon zone transfer against $DOMAIN..."
# Disable pipefail temporarily — zone transfers almost always fail (non-zero exit)
# which would kill the script. We capture output directly instead of piping.
set +e
dnsrecon -d "$DOMAIN" -t axfr \
    --xml "$OUTPUT_DIR/dnsrecon_zonetransfer.xml" \
    > "$OUTPUT_DIR/dnsrecon_zonetransfer.txt" 2>&1
DNSRECON_EXIT=$?
set -e

if [[ $DNSRECON_EXIT -eq 0 ]]; then
    success "dnsrecon complete → $OUTPUT_DIR/dnsrecon_zonetransfer.txt"
else
    warn "dnsrecon exited with code $DNSRECON_EXIT (zone transfer likely refused — normal for most targets)"
    warn "Partial output saved → $OUTPUT_DIR/dnsrecon_zonetransfer.txt"
fi

# ── Phase 3: SSL Analysis (concurrent) ───────────────────────
banner "Phase 3 — SSL/TLS Analysis (parallel: $PARALLEL_JOBS jobs)"

# Use live hosts only — cross-referenced and DNS-verified
SSL_TARGETS_FILE=$(mktemp)
{ echo "$DOMAIN"; cat "$LIVE_HOSTS_FILE" 2>/dev/null; } | sort -u > "$SSL_TARGETS_FILE"
SSL_TARGET_COUNT=$(wc -l < "$SSL_TARGETS_FILE")
info "Running SSL scans against $SSL_TARGET_COUNT live targets with $PARALLEL_JOBS parallel jobs..."

mkdir -p "$OUTPUT_DIR/ssl"

# Job pool — runs up to $PARALLEL_JOBS scans concurrently
scan_host() {
    local host="$1"
    local out_dir="$2"
    local safe_host="${host//\//_}"

    # script -q fakes a TTY so tools keep their native ANSI colours in the output file
    script -q -c "sslscan $host" /dev/null \
        > "$out_dir/sslscan_${safe_host}.txt" 2>&1 \
        || true

    sleep 1  # brief pause between tools to avoid resource spikes

    script -q -c "sslyze $host" /dev/null \
        > "$out_dir/sslyze_${safe_host}.txt" 2>&1 \
        || true

    echo "$host"   # signal completion
}

export -f scan_host

COMPLETED=0
PIDS=()

while IFS= read -r host; do
    [[ -z "$host" ]] && continue

    # Launch scan in background
    scan_host "$host" "$OUTPUT_DIR/ssl" </dev/null &
    PIDS+=($!)

    # Throttle: wait for a slot if at max jobs
    while (( ${#PIDS[@]} >= PARALLEL_JOBS )); do
        NEW_PIDS=()
        for pid in "${PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                NEW_PIDS+=("$pid")
            else
                (( COMPLETED++ )) || true
                info "  Progress: $COMPLETED / $SSL_TARGET_COUNT hosts scanned"
            fi
        done
        PIDS=("${NEW_PIDS[@]+"${NEW_PIDS[@]}"}")
        sleep 0.5
    done

done < "$SSL_TARGETS_FILE"

# Wait for remaining jobs
for pid in "${PIDS[@]+"${PIDS[@]}"}"; do
    wait "$pid" || true
    (( COMPLETED++ )) || true
done

rm -f "$SSL_TARGETS_FILE"
success "SSL scans complete ($COMPLETED hosts) → $OUTPUT_DIR/ssl/"

# ── Summary ───────────────────────────────────────────────────
banner "Scan Complete — Summary"

echo -e "${BOLD}Target:${RESET}       $DOMAIN"
echo -e "${BOLD}Output Dir:${RESET}   $OUTPUT_DIR"
echo -e "${BOLD}Subdomains:${RESET}   $SUBDOMAIN_COUNT unique (subfinder + crt.sh)"
echo -e "${BOLD}Live Hosts:${RESET}   $LIVE_COUNT DNS-verified → subdomains_live.txt"
echo -e "${BOLD}DNS:${RESET}          dnsrecon_zonetransfer.txt / .xml"
echo -e "${BOLD}SSL Reports:${RESET}  $OUTPUT_DIR/ssl/"
echo ""
echo -e "${GREEN}All done. Happy hunting.${RESET}"
