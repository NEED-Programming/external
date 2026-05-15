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
    echo -e "Usage: $0 [-d <domain>] [-f <target_file>] [-o <output_dir>] [-p <parallel_jobs>]"
    echo -e "  -d  Single target domain"
    echo -e "  -f  File containing one domain per line"
    echo -e "  -o  Output base directory (default: ./recon_<timestamp>)"
    echo -e "      Each domain gets its own subdirectory inside."
    echo -e "  -p  Parallel SSL scan jobs per domain (default: 3)"
    echo -e ""
    echo -e "  At least one of -d or -f is required."
    exit 1
}

# ── Argument Parsing ──────────────────────────────────────────
DOMAIN=""
TARGET_FILE=""
OUTPUT_BASE=""
PARALLEL_JOBS=3

while getopts "d:f:o:p:h" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        f) TARGET_FILE="$OPTARG" ;;
        o) OUTPUT_BASE="$OPTARG" ;;
        p) PARALLEL_JOBS="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$DOMAIN" && -z "$TARGET_FILE" ]] && { error "Specify -d <domain> or -f <file>."; usage; }

if [[ -n "$TARGET_FILE" ]]; then
    [[ -f "$TARGET_FILE" ]] || { error "Target file not found: $TARGET_FILE"; exit 1; }
    [[ -r "$TARGET_FILE" ]] || { error "Target file not readable: $TARGET_FILE"; exit 1; }
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_BASE="${OUTPUT_BASE:-./recon_${TIMESTAMP}}"
mkdir -p "$OUTPUT_BASE"

# ── Binary Downloader ─────────────────────────────────────────
download_github_binary() {
    local repo="$1"
    local binary="$2"
    local asset_pat="${3:-}"

    local os arch
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    case "$arch" in
        x86_64)        arch="amd64"  ;;
        aarch64|arm64) arch="arm64"  ;;
        armv7l)        arch="armv7"  ;;
        i386|i686)     arch="386"    ;;
    esac

    info "  Querying GitHub releases for ${repo} (${os}/${arch})..."
    local api_url="https://api.github.com/repos/${repo}/releases/latest"
    local release_json
    release_json=$(curl -fsSL --max-time 15 "$api_url") || {
        error "  GitHub API request failed for ${repo}."
        return 1
    }

    local download_url
    if [[ -n "$asset_pat" ]]; then
        download_url=$(echo "$release_json" | jq -r \
            --arg pat "$asset_pat" \
            '.assets[] | select(.name | test($pat;"i")) | .browser_download_url' \
            | head -1)
    else
        download_url=$(echo "$release_json" | jq -r \
            --arg os "$os" --arg arch "$arch" \
            '.assets[]
             | select(.name | test("\\.tar\\.gz$|\\.tgz$|\\.zip$";"i"))
             | select(.name | test($os;"i"))
             | select(.name | test($arch;"i"))
             | .browser_download_url' \
            | head -1)

        if [[ -z "$download_url" || "$download_url" == "null" ]]; then
            download_url=$(echo "$release_json" | jq -r \
                --arg arch "$arch" \
                '.assets[]
                 | select(.name | test("\\.tar\\.gz$|\\.tgz$|\\.zip$";"i"))
                 | select(.name | test($arch;"i"))
                 | .browser_download_url' \
                | head -1)
        fi
    fi

    if [[ -z "$download_url" || "$download_url" == "null" ]]; then
        error "  No suitable release asset found for ${os}/${arch} in ${repo}."
        error "  Visit https://github.com/${repo}/releases to download manually."
        return 1
    fi

    local tmp_dir filename
    tmp_dir=$(mktemp -d)
    filename="${download_url##*/}"
    info "  Downloading ${filename}..."
    curl -fL --max-time 120 -o "${tmp_dir}/${filename}" "$download_url" || {
        error "  Download failed: $download_url"
        rm -rf "$tmp_dir"
        return 1
    }

    local install_dir="/usr/local/bin"
    local extracted_bin

    if [[ "$filename" == *.tar.gz || "$filename" == *.tgz ]]; then
        tar -xzf "${tmp_dir}/${filename}" -C "$tmp_dir"
        extracted_bin=$(find "$tmp_dir" -type f -name "$binary" | head -1)
    elif [[ "$filename" == *.zip ]]; then
        unzip -q "${tmp_dir}/${filename}" -d "$tmp_dir"
        extracted_bin=$(find "$tmp_dir" -type f -name "$binary" | head -1)
    else
        extracted_bin="${tmp_dir}/${filename}"
    fi

    if [[ -z "$extracted_bin" ]]; then
        error "  Could not locate '${binary}' inside the downloaded archive."
        rm -rf "$tmp_dir"
        return 1
    fi

    if sudo mv "$extracted_bin" "${install_dir}/${binary}" 2>/dev/null && \
       sudo chmod +x "${install_dir}/${binary}"; then
        success "  ${binary} installed → ${install_dir}/${binary}"
    else
        mkdir -p "$HOME/bin"
        mv "$extracted_bin" "$HOME/bin/${binary}"
        chmod +x "$HOME/bin/${binary}"
        warn "  Could not write to ${install_dir} — installed to ~/bin/${binary}"
        warn "  Ensure ~/bin is on your PATH (export PATH=\"\$HOME/bin:\$PATH\")"
        export PATH="$HOME/bin:$PATH"
    fi

    rm -rf "$tmp_dir"
}

# ── Flight Controls: Tool Check & Install ─────────────────────
banner "Flight Controls — Verifying Tools"

if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt-get"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
elif command -v brew &>/dev/null; then
    PKG_MANAGER="brew"
else
    warn "No supported package manager found. Will fall back to direct binary downloads."
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
            error "Failed to install $tool automatically."
            error "Please install it manually and re-run the script."
            exit 1
        fi
    fi
}

check_and_install "subfinder" "
    if [[ '$PKG_MANAGER' == 'apt-get' ]]; then
        sudo apt-get install -y subfinder
    elif [[ '$PKG_MANAGER' == 'brew' ]]; then
        brew install subfinder
    elif command -v go &>/dev/null; then
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    else
        download_github_binary 'projectdiscovery/subfinder' 'subfinder'
    fi
"

check_and_install "dnsx" "
    if [[ '$PKG_MANAGER' == 'apt-get' ]]; then
        sudo apt-get install -y dnsx
    elif [[ '$PKG_MANAGER' == 'brew' ]]; then
        brew install dnsx
    elif command -v go &>/dev/null; then
        go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    else
        download_github_binary 'projectdiscovery/dnsx' 'dnsx'
    fi
"

check_and_install "dnsrecon" "
    if command -v pip3 &>/dev/null; then
        pip3 install dnsrecon --break-system-packages 2>/dev/null || pip3 install dnsrecon
    elif [[ '$PKG_MANAGER' == 'apt-get' ]]; then
        sudo apt-get install -y dnsrecon
    elif command -v git &>/dev/null && command -v python3 &>/dev/null; then
        warn 'pip3 not found — cloning dnsrecon from source...'
        local clone_dir='\$HOME/.local/dnsrecon'
        git clone --depth 1 https://github.com/darkoperator/dnsrecon.git \"\$clone_dir\" 2>/dev/null \
            || { warn 'Already cloned — pulling latest...'; git -C \"\$clone_dir\" pull; }
        python3 -m pip install -r \"\$clone_dir/requirements.txt\" --break-system-packages 2>/dev/null \
            || python3 -m pip install -r \"\$clone_dir/requirements.txt\"
        local wrapper='/usr/local/bin/dnsrecon'
        echo -e '#!/usr/bin/env bash\nexec python3 '\"\$clone_dir\"'/dnsrecon.py \"\$@\"' \
            | sudo tee \"\$wrapper\" > /dev/null && sudo chmod +x \"\$wrapper\" \
            || { mkdir -p \"\$HOME/bin\"; echo -e '#!/usr/bin/env bash\nexec python3 '\"\$clone_dir\"'/dnsrecon.py \"\$@\"' > \"\$HOME/bin/dnsrecon\" && chmod +x \"\$HOME/bin/dnsrecon\"; export PATH=\"\$HOME/bin:\$PATH\"; }
    else
        error 'Cannot install dnsrecon: no pip3, apt-get, or git+python3 found.'
        error 'Install pip3 (https://pip.pypa.io) then re-run.'
        exit 1
    fi
"

check_and_install "sslscan" "
    if [[ '$PKG_MANAGER' == 'apt-get' ]]; then
        sudo apt-get install -y sslscan
    elif [[ '$PKG_MANAGER' == 'brew' ]]; then
        brew install sslscan
    else
        download_github_binary 'rbsec/sslscan' 'sslscan'
    fi
"

check_and_install "sslyze" "
    if command -v pip3 &>/dev/null; then
        pip3 install sslyze --break-system-packages 2>/dev/null || pip3 install sslyze
    elif command -v pip &>/dev/null; then
        pip install sslyze --break-system-packages 2>/dev/null || pip install sslyze
    else
        error 'pip3/pip not found — cannot install sslyze.'
        error 'Install pip3 (https://pip.pypa.io) then re-run.'
        exit 1
    fi
"

if [[ -n "$PKG_MANAGER" ]]; then
    check_and_install "curl" "sudo $PKG_MANAGER install -y curl"
    check_and_install "jq"   "sudo $PKG_MANAGER install -y jq"
else
    check_and_install "curl" "echo 'Install curl manually: https://curl.se' && exit 1"
    check_and_install "jq" "
        local os arch jq_asset
        os=\$(uname -s | tr '[:upper:]' '[:lower:]')
        arch=\$(uname -m)
        case \"\$arch\" in
            x86_64)        jq_asset=\"jq-\${os}-amd64\" ;;
            aarch64|arm64) jq_asset=\"jq-\${os}-arm64\" ;;
            *)             jq_asset=\"jq-\${os}-amd64\" ;;
        esac
        download_github_binary 'jqlang/jq' 'jq' \"\$jq_asset\"
    "
fi

# ══════════════════════════════════════════════════════════════
# ── Per-domain recon pipeline ─────────────────────────────════
# ══════════════════════════════════════════════════════════════
run_recon() {
    local DOMAIN="$1"
    local OUTPUT_DIR="$2"

    mkdir -p "$OUTPUT_DIR"

    # ── Phase 1: Subdomain Enumeration ────────────────────────
    banner "[$DOMAIN] Phase 1 — Subdomain Enumeration"

    local SUBDOMAINS_FILE="$OUTPUT_DIR/subdomains_all.txt"
    touch "$SUBDOMAINS_FILE"

    info "Running subfinder passive enumeration on $DOMAIN..."
    subfinder -d "$DOMAIN" -silent -o "$OUTPUT_DIR/subdomains_subfinder.txt" 2>/dev/null \
        && success "subfinder complete → $OUTPUT_DIR/subdomains_subfinder.txt" \
        || warn "subfinder encountered errors (partial results may exist)"

    info "Querying crt.sh for $DOMAIN..."
    info "  Waiting 10s for crt.sh to generate results..."
    sleep 10
    local CRTSH_RAW="" CRTSH_SUCCESS=false
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
        warn "crt.sh failed after 3 attempts — skipping"
        touch "$OUTPUT_DIR/subdomains_crtsh.txt"
    fi

    grep -h '' "$OUTPUT_DIR"/subdomains_subfinder.txt "$OUTPUT_DIR"/subdomains_crtsh.txt 2>/dev/null \
        | grep -v '^\*\.' \
        | sort -u > "$SUBDOMAINS_FILE"

    local SUBDOMAIN_COUNT
    SUBDOMAIN_COUNT=$(wc -l < "$SUBDOMAINS_FILE")
    success "Total unique subdomains discovered: $SUBDOMAIN_COUNT → $SUBDOMAINS_FILE"

    # ── Phase 1.5: Live Host Probing ──────────────────────────
    banner "[$DOMAIN] Phase 1.5 — Live Host Probing (dnsx)"

    local LIVE_HOSTS_FILE="$OUTPUT_DIR/subdomains_live.txt"
    info "Probing $SUBDOMAIN_COUNT subdomains for live DNS resolution..."
    dnsx -l "$SUBDOMAINS_FILE" -silent -r 8.8.8.8,1.1.1.1 -t 25 -o "$LIVE_HOSTS_FILE" 2>/dev/null \
        || warn "dnsx encountered errors (partial results may exist)"

    local LIVE_COUNT
    LIVE_COUNT=$(wc -l < "$LIVE_HOSTS_FILE")
    success "$LIVE_COUNT live hosts confirmed → $LIVE_HOSTS_FILE"

    # ── Phase 2: DNS Zone Transfer ────────────────────────────
    banner "[$DOMAIN] Phase 2 — DNS Zone Transfer (dnsrecon)"

    info "Running dnsrecon zone transfer against $DOMAIN..."
    set +e
    dnsrecon -d "$DOMAIN" -t axfr \
        --xml "$OUTPUT_DIR/dnsrecon_zonetransfer.xml" \
        > "$OUTPUT_DIR/dnsrecon_zonetransfer.txt" 2>&1
    local DNSRECON_EXIT=$?
    set -e

    if [[ $DNSRECON_EXIT -eq 0 ]]; then
        success "dnsrecon complete → $OUTPUT_DIR/dnsrecon_zonetransfer.txt"
    else
        warn "dnsrecon exited with code $DNSRECON_EXIT (zone transfer likely refused — normal)"
        warn "Partial output saved → $OUTPUT_DIR/dnsrecon_zonetransfer.txt"
    fi

    # ── Phase 3: SSL Analysis (concurrent) ───────────────────
    banner "[$DOMAIN] Phase 3 — SSL/TLS Analysis (parallel: $PARALLEL_JOBS jobs)"

    local SSL_TARGETS_FILE
    SSL_TARGETS_FILE=$(mktemp)
    { echo "$DOMAIN"; cat "$LIVE_HOSTS_FILE" 2>/dev/null; } | sort -u > "$SSL_TARGETS_FILE"
    local SSL_TARGET_COUNT
    SSL_TARGET_COUNT=$(wc -l < "$SSL_TARGETS_FILE")
    info "Running SSL scans against $SSL_TARGET_COUNT live targets with $PARALLEL_JOBS parallel jobs..."

    mkdir -p "$OUTPUT_DIR/ssl"

    scan_host() {
        local host="$1"
        local out_dir="$2"
        local safe_host="${host//\//_}"

        script -q -c "sslscan $host" /dev/null \
            > "$out_dir/sslscan_${safe_host}.txt" 2>&1 || true

        sleep 1

        script -q -c "sslyze $host" /dev/null \
            > "$out_dir/sslyze_${safe_host}.txt" 2>&1 || true
    }
    export -f scan_host

    local COMPLETED=0
    local PIDS=()

    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        scan_host "$host" "$OUTPUT_DIR/ssl" </dev/null &
        PIDS+=($!)

        while (( ${#PIDS[@]} >= PARALLEL_JOBS )); do
            local NEW_PIDS=()
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

    for pid in "${PIDS[@]+"${PIDS[@]}"}"; do
        wait "$pid" || true
        (( COMPLETED++ )) || true
    done

    rm -f "$SSL_TARGETS_FILE"
    success "SSL scans complete ($COMPLETED hosts) → $OUTPUT_DIR/ssl/"

    # Return stats to the caller for the summary table
    echo "$SUBDOMAIN_COUNT $LIVE_COUNT $OUTPUT_DIR"
}

# ══════════════════════════════════════════════════════════════
# ── Build target list & run ────────────────────────────────────
# ══════════════════════════════════════════════════════════════

TARGETS_FILE=$(mktemp)

[[ -n "$DOMAIN" ]] && echo "$DOMAIN" >> "$TARGETS_FILE"
if [[ -n "$TARGET_FILE" ]]; then
    # Strip blank lines and comments
    grep -v '^\s*#' "$TARGET_FILE" | grep -v '^\s*$' >> "$TARGETS_FILE"
fi

sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"
TOTAL_TARGETS=$(wc -l < "$TARGETS_FILE")

[[ $TOTAL_TARGETS -eq 0 ]] && { error "No valid targets found."; exit 1; }

info "Targets to scan: $TOTAL_TARGETS"
[[ $TOTAL_TARGETS -gt 1 ]] && info "Output base: $OUTPUT_BASE"

# ── Per-domain summary accumulators ──────────────────────────
declare -A SUMMARY_SUBDOMAINS
declare -A SUMMARY_LIVE
declare -A SUMMARY_DIRS

CURRENT=0
while IFS= read -r target; do
    [[ -z "$target" ]] && continue
    (( CURRENT++ )) || true

    if [[ $TOTAL_TARGETS -eq 1 ]]; then
        # Single domain: flat output dir (original behaviour)
        domain_out="${OUTPUT_BASE}"
    else
        # Multiple domains: one subdir per target
        safe_target="${target//[^a-zA-Z0-9._-]/_}"
        domain_out="${OUTPUT_BASE}/${safe_target}"
        banner "Target $CURRENT / $TOTAL_TARGETS — $target"
    fi

    result=$(run_recon "$target" "$domain_out")
    read -r subs live outdir <<< "$result"

    SUMMARY_SUBDOMAINS["$target"]="$subs"
    SUMMARY_LIVE["$target"]="$live"
    SUMMARY_DIRS["$target"]="$outdir"

done < "$TARGETS_FILE"

rm -f "$TARGETS_FILE"

# ── Final Summary ─────────────────────────────────────────────
banner "All Scans Complete — Summary"

if [[ $TOTAL_TARGETS -eq 1 ]]; then
    target="${!SUMMARY_DIRS[*]}"
    echo -e "${BOLD}Target:${RESET}       $target"
    echo -e "${BOLD}Output Dir:${RESET}   ${SUMMARY_DIRS[$target]}"
    echo -e "${BOLD}Subdomains:${RESET}   ${SUMMARY_SUBDOMAINS[$target]} unique (subfinder + crt.sh)"
    echo -e "${BOLD}Live Hosts:${RESET}   ${SUMMARY_LIVE[$target]} DNS-verified"
    echo -e "${BOLD}DNS:${RESET}          dnsrecon_zonetransfer.txt / .xml"
    echo -e "${BOLD}SSL Reports:${RESET}  ${SUMMARY_DIRS[$target]}/ssl/"
else
    printf "\n${BOLD}%-40s %10s %10s   %s${RESET}\n" "Domain" "Subdomains" "Live" "Output Dir"
    printf '%s\n' "────────────────────────────────────────────────────────────────────────────────"
    for target in "${!SUMMARY_DIRS[@]}"; do
        printf "%-40s %10s %10s   %s\n" \
            "$target" \
            "${SUMMARY_SUBDOMAINS[$target]}" \
            "${SUMMARY_LIVE[$target]}" \
            "${SUMMARY_DIRS[$target]}"
    done
fi

echo ""
echo -e "${GREEN}All done. Happy hunting.${RESET}"
